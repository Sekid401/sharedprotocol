/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Sekid
 * Licensed under the MIT License; see the LICENSE file for the full text.
 */

/*
 * localenterprise.c — LocalEnterprise (LE) v1.0.0
 *
 * A spin-off of sharedprotocol.c with most features removed. What is left is the SPP v1.1
 * epoll engine, the SPP_RPC dispatcher and the capability bits, plus four enterprise parts:
 *
 *   SPPLogE     logs every single action to a tamper-evident, hash-chained, append-only file
 *   SPPServer   an HTTP/1.1 server (routes, middleware, tokens, rate limits, static files)
 *               next to the SPP port
 *   SPPPolicyE  enterprise policies: allow/deny rules by principal, role, address, action,
 *               resource and time window; deny overrides; lockdown; audit-only mode
 *   FSE         the enterprise filesystem: touch / read / edit / execute on the REAL disk,
 *               jailed to one root directory (no symlinks followed, no ".." ever)
 *
 * Removed compared with sharedprotocol.c: headless browser + bridge, SPCode runner, daemons,
 * drivers, cron, relay, trace, SPMemory regions and the whole JS forwarding layer.
 *
 * Build (Linux only):  gcc -O2 -Wall -Wextra -o localenterprise localenterprise.c -lpthread
 *
 * Usage:  localenterprise [--state-dir D] [--fse-root D] [--fse-exec] [--port N] [--http-port N] ...
 *         localenterprise --verify-log <file> [--expect-head <sha256>]
 *         localenterprise --help
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__)
#error "localenterprise.c needs Linux (epoll, openat, close_range, fexecve)"
#endif

#define SP_PLATFORM_LINUX
#define SP_PLATFORM_UNIX
#define LE_VERSION "1.0.0"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <strings.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <sys/sendfile.h>

typedef int sp_socket_t;
#define SP_INVALID_SOCKET (-1)
#define sp_close_socket(s) close(s)

/* ── SPP Constants ─────────────────────────────────────────────────────────── */
#define SPP_VERSION         0x0101
#define SPP_MAGIC           "\x53\x50\x50\x01"  /* "SPP\x01" */
#define SPP_MAGIC_LEN       4
#define SPP_DEFAULT_PORT    5221
#define SPP_MAX_PEERS       131072
#define SPP_MAX_PAYLOAD     65536
#define SPP_PING_INTERVAL   30000

#define SPP_CONNECT         0x0001
#define SPP_CONNECT_ACK     0x0002
#define SPP_DATA            0x0003
#define SPP_CLOSE           0x0004
#define SPP_PING            0x0005
#define SPP_PONG            0x0006
#define SPP_ERROR           0x0009
#define SPP_RPC             0x0010  /* {"id":N,"method":"..","params":{..}} */
#define SPP_RPC_RESULT      0x0011  /* {"id":N,"ok":true,"result":..} | {"id":N,"ok":false,"error":".."} */

#define SP_LD(x)        __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define SP_ST(x, v)     __atomic_store_n(&(x), (v), __ATOMIC_RELAXED)
#define SP_INC(x)       __atomic_fetch_add(&(x), 1, __ATOMIC_RELAXED)
#define SP_IS_RUNNING() SP_LD(g_sp.running)

#define SPP_MAX_PEERS_HARD  1048576
#define SPP_HS_MAX_PAYLOAD  1024
#define SPP_HS_TIMEOUT_MS   5000
#define SPP_TX_CAP          (1u << 20)
#define SPP_TX_TOTAL_CAP    ((size_t)256 << 20)
#define SPP_TX_FAIR         (16u << 10)
#define SPP_RX_BUDGET       (256u << 20)
#define SP_BASE_ID          5221

/* ── capability bits (one byte, per peer / per API token) ──────────────────── */
#define SPCAP_SRV           0x01   /* server admin: HTTP routes, server settings */
#define SPCAP_KICK          0x02   /* list and kick peers */
#define SPCAP_TOK           0x04   /* create / list / revoke API tokens */
#define SPCAP_EXEC          0x08   /* fse.exec (also needs fsr) */
#define SPCAP_LOGR          0x10   /* read and verify the audit log, metrics */
#define SPCAP_POLICY        0x20   /* policy rules, roles, grant / revoke caps */
#define SPCAP_FSW           0x40   /* FSE: write, touch, mkdir, rm, mv, cp, chmod */
#define SPCAP_FSR           0x80   /* FSE: stat, ls, read, hash */
#define SPCAP_ALL           0xFF

/* ── SPP Packet ────────────────────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];
    uint16_t msg_type;
    uint32_t payload_len;
    uint64_t seq;
    uint64_t timestamp_ms;
} spp_header_t;
#pragma pack(pop)

#define SPP_HEADER_SIZE     sizeof(spp_header_t)  /* 26 bytes */
#define SPP_CRC_SIZE        4

/* ── SPP Peer ──────────────────────────────────────────────────────────────── */
typedef struct {
    sp_socket_t  sock;
    char         spmention[64];
    char         session_id[37];
    uint64_t     seq_local;
    uint64_t     seq_remote;
    uint8_t      caps;
    int          active;
    uint64_t     conn_id;
    uint8_t      hs;
    uint8_t      sp_caps;          /* SPCAP_* granted to this peer */
    uint8_t      want_out;
    uint8_t      auth_fail;        /* failed auth.login attempts on this connection */
    uint32_t     addr;             /* IPv4, network order */
    uint32_t     tok_id;           /* API token this connection logged in with (0 = none) */
    char         principal[40];    /* token name after auth.login */
    char         role[24];         /* policy role */
    uint64_t     connected_ms, last_rx_ms, ping_sent_ms, next_ping_ms;
    uint32_t     rtt_ms;
    uint8_t     *rx;  size_t rx_len;
    uint8_t     *tx;  size_t tx_len, tx_off;
} spp_peer_t;

/* ── Global state ──────────────────────────────────────────────────────────── */
static struct {
    sp_socket_t   server_sock;
    spp_peer_t   *peers;
    size_t        max_peers, peer_hi, peer_count, ready_count;
    uint32_t     *free_slots;
    size_t        free_top;
    uint64_t      next_conn_id, bcast_seq, rx_buffered;
    uint8_t       default_caps;
    int           epfd;
    int           running;
    int           port;
    char          spmention[64];
    pthread_t     server_thread;
    pthread_t     io_thread;
    pthread_mutex_t peers_lock;
    int           verbose;
    uint64_t      start_ms;
} g_sp = {0};

/* ── CRC32 ─────────────────────────────────────────────────────────────────── */
static uint32_t sp_crc32_table[256];
static int      sp_crc32_init = 0;

static void spp_crc32_build_table(void) {
    uint32_t c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = (uint32_t)n;
        for (k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
        sp_crc32_table[n] = c;
    }
    sp_crc32_init = 1;
}

static uint32_t spp_crc32(const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
    size_t i;
    if (!sp_crc32_init) spp_crc32_build_table();
    for (i = 0; i < len; i++)
        c = sp_crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

/* ── console logging (diagnostics for the operator; the audit trail is SPPLogE) ── */
static void sp_log(const char *level, const char *fmt, ...) {
    va_list ap;
    time_t t = time(NULL);
    struct tm tmbuf;
    char timebuf[32];
    localtime_r(&t, &tmbuf);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tmbuf);
    fprintf(stderr, "[%s] [LE/%s] ", timebuf, level);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define SP_LOG(fmt, ...)  sp_log("INFO",  fmt, ##__VA_ARGS__)
#define SP_WARN(fmt, ...) sp_log("WARN",  fmt, ##__VA_ARGS__)
#define SP_ERR(fmt, ...)  sp_log("ERROR", fmt, ##__VA_ARGS__)
#define SP_DBG(fmt, ...)  do { if (g_sp.verbose) sp_log("DBG", fmt, ##__VA_ARGS__); } while(0)

static int le_random(void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom((char *)buf + off, n - off, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)r;
    }
    return 0;
}

static void sp_gen_uuid(char *out) {           /* v4 UUID from the kernel RNG */
    uint8_t b[16];
    if (le_random(b, sizeof(b)) < 0) memset(b, 0x5a, sizeof(b));
    b[6] = (uint8_t)((b[6] & 0x0F) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static uint64_t sp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}
static uint64_t sp_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void sp_gen_mention(char *out, size_t sz) {
    char hostname[128] = "localhost";
    gethostname(hostname, sizeof(hostname));
    snprintf(out, sz, "@%s:%d/localenterprise", hostname, g_sp.port);
}

/* ── peer table ────────────────────────────────────────────────────────────── */
typedef struct { uint32_t slot; uint64_t conn; } peer_ref_t;

enum { CALLER_TERMINAL = 0, CALLER_HTTP = 1, CALLER_PEER = 2 };

/* who is asking: filled in when the request arrives, so revokes take effect at once */
typedef struct {
    int        kind;
    peer_ref_t ref;          /* CALLER_PEER */
    uint8_t    caps;
    uint64_t   conn;         /* peer connection id (0 otherwise) */
    uint32_t   ip;           /* IPv4, network order */
    char       name[40];     /* API token name, "" when anonymous */
    char       role[24];
    char       mention[64];
} sp_caller_t;

typedef struct {
    sp_caller_t caller;
    uint64_t    id;
    int         has_id;
    uint64_t    t0_us;
    char        mname[40];
} rpc_req_t;

static inline uint8_t sp_caps_get(const spp_peer_t *p) {
    return __atomic_load_n(&p->sp_caps, __ATOMIC_RELAXED);
}

static void le_peer_closed(uint64_t conn, uint32_t addr, int was_active, uint64_t age_ms);

/* ── peer table (callers hold g_sp.peers_lock unless noted) ─────────────────── */
static spp_peer_t *peer_by_ref(peer_ref_t r) {
    spp_peer_t *p;
    if (r.slot >= g_sp.max_peers) return NULL;
    p = &g_sp.peers[r.slot];
    if (p->conn_id != r.conn || (!p->active && !p->hs)) return NULL;
    return p;
}

static int peer_find_conn_locked(uint64_t conn) {
    size_t i;
    for (i = 0; i < g_sp.peer_hi; i++) {
        spp_peer_t *p = &g_sp.peers[i];
        if ((p->active || p->hs) && p->conn_id == conn) return (int)i;
    }
    return -1;
}

/* Frees a slot. IO thread only (it owns rx buffers and the epoll set). */
static size_t g_tx_total;                      /* queued outbound bytes, all peers (peers_lock) */
static void peer_release_locked(uint32_t slot) {
    spp_peer_t *p = &g_sp.peers[slot];
    uint64_t conn, age;
    uint32_t addr;
    int was_active;
    if (!p->active && !p->hs) return;
    conn = p->conn_id; addr = p->addr; was_active = p->active; age = sp_now_ms() - p->connected_ms;
    epoll_ctl(g_sp.epfd, EPOLL_CTL_DEL, p->sock, NULL);
    sp_close_socket(p->sock);
    g_sp.rx_buffered -= p->rx_len;
    free(p->rx);
    g_tx_total -= p->tx_len;
    free(p->tx);
    if (p->active) g_sp.ready_count--;
    memset(p, 0, sizeof(*p));
    g_sp.free_slots[g_sp.free_top++] = slot;
    g_sp.peer_count--;
    le_peer_closed(conn, addr, was_active, age);   /* lock order: peers_lock -> log lock */
}

/* Any thread: the IO thread releases directly, other threads shut the socket
 * down and the IO thread reaps it when epoll reports the hangup. */
static void peer_drop_locked(uint32_t slot) {
    spp_peer_t *p = &g_sp.peers[slot];
    if (!p->active && !p->hs) return;
    if (pthread_equal(pthread_self(), g_sp.io_thread)) peer_release_locked(slot);
    else shutdown(p->sock, SHUT_RDWR);
}

static void peer_epoll_want_out(spp_peer_t *p, uint32_t slot, int want) {
    struct epoll_event ev;
    ev.events   = EPOLLIN | EPOLLRDHUP | (want ? EPOLLOUT : 0);
    ev.data.u64 = ((uint64_t)(uint32_t)p->sock << 32) | slot;
    epoll_ctl(g_sp.epfd, EPOLL_CTL_MOD, p->sock, &ev);
    p->want_out = (uint8_t)want;
}

static size_t spp_build_packet(uint8_t *buf, uint16_t type, uint64_t seq,
                               const uint8_t *payload, uint32_t len) {
    spp_header_t h;
    uint32_t crc;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, SPP_MAGIC, SPP_MAGIC_LEN);
    h.msg_type     = type;
    h.payload_len  = len;
    h.seq          = seq;
    h.timestamp_ms = sp_now_ms();
    memcpy(buf, &h, SPP_HEADER_SIZE);
    if (payload && len) memcpy(buf + SPP_HEADER_SIZE, payload, len);
    crc = spp_crc32(buf, SPP_HEADER_SIZE + len);
    memcpy(buf + SPP_HEADER_SIZE + len, &crc, SPP_CRC_SIZE);
    return SPP_HEADER_SIZE + len + SPP_CRC_SIZE;
}

/* Non-blocking send with a bounded per-peer queue. Drops the peer on failure. */
static int peer_send_raw_locked(uint32_t slot, const uint8_t *pkt, size_t total) {
    spp_peer_t *p = &g_sp.peers[slot];
    size_t off = 0, rest;
    uint8_t *nt;

    if (!p->active && !p->hs) return -1;

    if (p->tx_len == 0) {                       /* nothing queued: try the socket directly */
        while (off < total) {
            ssize_t n = send(p->sock, pkt + off, total - off, MSG_NOSIGNAL);
            if (n > 0) { off += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            peer_drop_locked(slot);
            return -1;
        }
        if (off == total) return 0;
    }

    rest = total - off;
    if (p->tx_off) {                            /* compact the queue */
        memmove(p->tx, p->tx + p->tx_off, p->tx_len - p->tx_off);
        p->tx_len -= p->tx_off;
        g_tx_total -= p->tx_off;
        p->tx_off = 0;
    }
    if (p->tx_len + rest > SPP_TX_CAP ||        /* slow consumer */
        (g_tx_total + rest > SPP_TX_TOTAL_CAP && p->tx_len + rest > SPP_TX_FAIR)) {
        SP_DBG("peer %u: send queue full, dropping", slot);
        peer_drop_locked(slot);
        return -1;
    }
    nt = (uint8_t *)realloc(p->tx, p->tx_len + rest);
    if (!nt) { peer_drop_locked(slot); return -1; }
    memcpy(nt + p->tx_len, pkt + off, rest);
    p->tx = nt;
    p->tx_len += rest;
    g_tx_total += rest;
    if (!p->want_out) peer_epoll_want_out(p, slot, 1);
    return 0;
}

static int peer_flush_locked(uint32_t slot) {   /* EPOLLOUT: push the queue */
    spp_peer_t *p = &g_sp.peers[slot];
    while (p->tx_off < p->tx_len) {
        ssize_t n = send(p->sock, p->tx + p->tx_off, p->tx_len - p->tx_off, MSG_NOSIGNAL);
        if (n > 0) { p->tx_off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    g_tx_total -= p->tx_len;
    free(p->tx);
    p->tx = NULL;
    p->tx_len = p->tx_off = 0;
    if (p->want_out) peer_epoll_want_out(p, slot, 0);
    return 0;
}

/* Send to one peer by reference (safe if the peer went away: returns -1). */
static int spp_peer_send(peer_ref_t r, uint16_t type, const uint8_t *payload, uint32_t len) {
    uint8_t buf[SPP_HEADER_SIZE + SPP_MAX_PAYLOAD + SPP_CRC_SIZE];
    spp_peer_t *p;
    int rc = -1;
    if (len > SPP_MAX_PAYLOAD) return -1;
    pthread_mutex_lock(&g_sp.peers_lock);
    p = peer_by_ref(r);
    if (p) {
        size_t total = spp_build_packet(buf, type, p->seq_local++, payload, len);
        rc = peer_send_raw_locked(r.slot, buf, total);
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
    return rc;
}


/* Broadcast to every ready peer. One shared sequence number so the packet (and its
 * CRC) is built once instead of once per peer. */
__attribute__((unused)) static void spp_broadcast_ready(uint16_t type, const uint8_t *payload, uint32_t len) {
    uint8_t buf[SPP_HEADER_SIZE + SPP_MAX_PAYLOAD + SPP_CRC_SIZE];
    size_t total, i;
    if (len > SPP_MAX_PAYLOAD) return;
    pthread_mutex_lock(&g_sp.peers_lock);
    total = spp_build_packet(buf, type, ++g_sp.bcast_seq, payload, len);
    for (i = 0; i < g_sp.peer_hi; i++)
        if (g_sp.peers[i].active) peer_send_raw_locked((uint32_t)i, buf, total);
    pthread_mutex_unlock(&g_sp.peers_lock);
}

/* ── growable string buffer + JSON helpers ──────────────────────────────────── */
typedef struct { char *p; size_t len, cap; int err; } sb_t;

static void sb_init(sb_t *s) {
    s->len = 0; s->cap = 256; s->err = 0;
    s->p = (char *)malloc(s->cap);
    if (!s->p) { s->err = 1; s->cap = 0; } else s->p[0] = '\0';
}
static void sb_free(sb_t *s) { free(s->p); s->p = NULL; s->len = s->cap = 0; }
static int sb_grow(sb_t *s, size_t need) {
    size_t nc; char *np;
    if (s->err) return -1;
    if (s->len + need + 1 <= s->cap) return 0;
    nc = s->cap ? s->cap : 256;
    while (nc < s->len + need + 1) nc *= 2;
    np = (char *)realloc(s->p, nc);
    if (!np) { s->err = 1; return -1; }
    s->p = np; s->cap = nc;
    return 0;
}
static void sb_putn(sb_t *s, const char *d, size_t n) {
    if (sb_grow(s, n) < 0) return;
    memcpy(s->p + s->len, d, n);
    s->len += n;
    s->p[s->len] = '\0';
}
static void sb_puts(sb_t *s, const char *d) { sb_putn(s, d, strlen(d)); }
static void sb_printf(sb_t *s, const char *fmt, ...) {
    va_list ap, ap2;
    int n;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0 && sb_grow(s, (size_t)n) == 0) {
        vsnprintf(s->p + s->len, (size_t)n + 1, fmt, ap2);
        s->len += (size_t)n;
    }
    va_end(ap2);
}
static void sb_json_str(sb_t *s, const char *str) {
    sb_putn(s, "\"", 1);
    for (; *str; str++) {
        unsigned char c = (unsigned char)*str;
        if (c == '"' || c == '\\') { char b[2]; b[0] = '\\'; b[1] = (char)c; sb_putn(s, b, 2); }
        else if (c == '\n') sb_puts(s, "\\n");
        else if (c == '\r') sb_puts(s, "\\r");
        else if (c == '\t') sb_puts(s, "\\t");
        else if (c < 0x20)  sb_printf(s, "\\u%04x", c);
        else                sb_putn(s, (const char *)&c, 1);
    }
    sb_putn(s, "\"", 1);
}

static const char *json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Returns the pointer just past the JSON value starting at p (NULL if malformed). */
static const char *json_skip_value(const char *p) {
    p = json_skip_ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
        return *p == '"' ? p + 1 : NULL;
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p) {
            if (*p == '"') { p = json_skip_value(p); if (!p) return NULL; continue; }
            if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') { if (--depth == 0) return p + 1; }
            p++;
        }
        return NULL;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']' && *p != ' ' &&
           *p != '\t' && *p != '\n' && *p != '\r') p++;
    return p;
}

/* Finds a top-level key of a JSON object; returns a pointer to its value or NULL. */
static const char *json_find(const char *json, const char *key) {
    const char *p = json_skip_ws(json);
    size_t klen = strlen(key);
    if (*p != '{') return NULL;
    p++;
    for (;;) {
        const char *ks, *ke;
        p = json_skip_ws(p);
        if (*p == '}' || !*p) return NULL;
        if (*p == ',') { p++; continue; }
        if (*p != '"') return NULL;
        ks = p + 1;
        ke = json_skip_value(p);
        if (!ke) return NULL;
        p = json_skip_ws(ke);
        if (*p != ':') return NULL;
        p = json_skip_ws(p + 1);
        if ((size_t)(ke - 1 - ks) == klen && memcmp(ks, key, klen) == 0) return p;
        p = json_skip_value(p);
        if (!p) return NULL;
    }
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decoded copy of a string value (caller frees) or NULL. */
static char *json_str_dup(const char *json, const char *key) {
    const char *p = json_find(json, key);
    char *out, *o;
    if (!p || *p != '"') return NULL;
    p++;
    out = (char *)malloc(strlen(p) + 1);      /* decoded text is never longer than the raw text */
    if (!out) return NULL;
    o = out;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': *o++ = '\n'; break;
            case 't': *o++ = '\t'; break;
            case 'r': *o++ = '\r'; break;
            case 'b': *o++ = '\b'; break;
            case 'f': *o++ = '\f'; break;
            case 'u': {
                unsigned cp = 0;
                int i, h;
                for (i = 1; i <= 4; i++) {
                    h = hexv((unsigned char)p[i]);
                    if (h < 0) { free(out); return NULL; }
                    cp = cp * 16 + (unsigned)h;
                }
                p += 4;
                if (cp >= 0xD800 && cp < 0xDC00 && p[1] == '\\' && p[2] == 'u') {
                    unsigned lo = 0;
                    for (i = 3; i <= 6; i++) {
                        h = hexv((unsigned char)p[i]);
                        if (h < 0) { free(out); return NULL; }
                        lo = lo * 16 + (unsigned)h;
                    }
                    if (lo >= 0xDC00 && lo < 0xE000) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); p += 6; }
                }
                if (cp < 0x80)         { *o++ = (char)cp; }
                else if (cp < 0x800)   { *o++ = (char)(0xC0 | (cp >> 6));  *o++ = (char)(0x80 | (cp & 0x3F)); }
                else if (cp < 0x10000) { *o++ = (char)(0xE0 | (cp >> 12)); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
                else                   { *o++ = (char)(0xF0 | (cp >> 18)); *o++ = (char)(0x80 | ((cp >> 12) & 0x3F)); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
                break;
            }
            default: *o++ = *p; break;     /* \" \\ \/ */
            }
            p++;
        } else {
            *o++ = *p++;
        }
    }
    *o = '\0';
    return out;
}

/* Raw copy of any value (object/array/number/...) or NULL. */
static char *json_raw_dup(const char *json, const char *key) {
    const char *p = json_find(json, key), *e;
    char *out;
    if (!p) return NULL;
    e = json_skip_value(p);
    if (!e) return NULL;
    out = (char *)malloc((size_t)(e - p) + 1);
    if (!out) return NULL;
    memcpy(out, p, (size_t)(e - p));
    out[e - p] = '\0';
    return out;
}

static int json_get_i64(const char *json, const char *key, int64_t *out) {
    const char *p = json_find(json, key);
    char *e;
    long long v;
    if (!p) return -1;
    v = strtoll(p, &e, 10);
    if (e == p) return -1;
    *out = (int64_t)v;
    return 0;
}

static int json_get_u64(const char *json, const char *key, uint64_t *out) {
    const char *p = json_find(json, key);
    char *e;
    unsigned long long v;
    if (!p || *p == '-') return -1;
    v = strtoull(p, &e, 10);
    if (e == p) return -1;
    *out = (uint64_t)v;
    return 0;
}


static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}


/* ── capabilities ──────────────────────────────────────────────────────────── */
static const struct { const char *name; uint8_t bit; } g_capnames[] = {
    { "srv", SPCAP_SRV }, { "kick", SPCAP_KICK }, { "tok", SPCAP_TOK }, { "exec", SPCAP_EXEC },
    { "logr", SPCAP_LOGR }, { "policy", SPCAP_POLICY }, { "fsw", SPCAP_FSW }, { "fsr", SPCAP_FSR },
};
#define N_CAPNAMES ((int)(sizeof(g_capnames) / sizeof(g_capnames[0])))

static const char *need_str(uint8_t need, char *buf, size_t n) {
    int i;
    size_t l = 0;
    buf[0] = '\0';
    for (i = 0; i < N_CAPNAMES && l + 1 < n; i++) {
        if (!(need & g_capnames[i].bit)) continue;
        l += (size_t)snprintf(buf + l, n - l, "%s%s", l ? "+" : "", g_capnames[i].name);
    }
    return buf;
}

static void sb_caps(sb_t *s, uint8_t caps) {
    int i, first = 1;
    sb_printf(s, "\"caps\":%u,\"cap_names\":[", caps);
    for (i = 0; i < N_CAPNAMES; i++) {
        if (!(caps & g_capnames[i].bit)) continue;
        sb_printf(s, "%s\"%s\"", first ? "" : ",", g_capnames[i].name);
        first = 0;
    }
    sb_puts(s, "]");
}

/* text form: "fsr,fsw" | "0x88" | "all" ; returns -1 on junk */
static int parse_caps_str(const char *str, uint8_t *out) {
    char *s = strdup(str), *tok, *save = NULL;
    unsigned v = 0;
    if (!s) return -1;
    for (tok = strtok_r(s, ", |", &save); tok; tok = strtok_r(NULL, ", |", &save)) {
        int i, hit = 0;
        if (isdigit((unsigned char)tok[0])) { v |= (unsigned)strtoul(tok, NULL, 0); continue; }
        if (strcmp(tok, "all") == 0) { v |= SPCAP_ALL; continue; }
        for (i = 0; i < N_CAPNAMES; i++)
            if (strcmp(tok, g_capnames[i].name) == 0) { v |= g_capnames[i].bit; hit = 1; }
        if (!hit) { free(s); return -1; }
    }
    free(s);
    *out = (uint8_t)(v & SPCAP_ALL);
    return 0;
}

/* "caps": 128 | "0x88" | "fsr,fsw" | "all" */
static int parse_caps(const char *params, uint8_t *out) {
    const char *p = json_find(params, "caps");
    if (!p) return -1;
    if (*p == '"') {
        char *s = json_str_dup(params, "caps");
        int rc;
        if (!s) return -1;
        rc = parse_caps_str(s, out);
        free(s);
        return rc;
    }
    if (isdigit((unsigned char)*p)) { *out = (uint8_t)(strtoul(p, NULL, 0) & SPCAP_ALL); return 0; }
    return -1;
}

static int json_true(const char *params, const char *key) {
    const char *p = json_find(params, key);
    return p && strncmp(p, "true", 4) == 0;
}

/* ── SHA-256 (streaming), base64, UTF-8 ────────────────────────────────────── */
typedef struct { uint32_t h[8]; uint8_t buf[64]; size_t blen; uint64_t total; } sha_ctx;

static void sha_init(sha_ctx *c) {
    static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(c->h, iv, sizeof(iv));
    c->blen = 0; c->total = 0;
}
static void sha_update(sha_ctx *c, const void *data, size_t n) {
    const uint8_t *d = (const uint8_t *)data;
    c->total += n;
    if (c->blen) {
        size_t t = 64 - c->blen;
        if (t > n) t = n;
        memcpy(c->buf + c->blen, d, t);
        c->blen += t; d += t; n -= t;
        if (c->blen == 64) { sha256_block(c->h, c->buf); c->blen = 0; }
    }
    while (n >= 64) { sha256_block(c->h, d); d += 64; n -= 64; }
    if (n) { memcpy(c->buf, d, n); c->blen = n; }
}
static void sha_final_hex(sha_ctx *c, char out[65]) {
    uint64_t bits = c->total * 8;
    uint8_t one = 0x80, z = 0, lenb[8];
    int i;
    sha_update(c, &one, 1);
    while (c->blen != 56) sha_update(c, &z, 1);
    for (i = 0; i < 8; i++) lenb[7 - i] = (uint8_t)(bits >> (8 * i));
    sha_update(c, lenb, 8);
    for (i = 0; i < 8; i++) sprintf(out + 8 * i, "%08x", c->h[i]);
    out[64] = '\0';
}
static void sha256_hex(const uint8_t *d, size_t n, char out[65]) {
    sha_ctx c;
    sha_init(&c);
    sha_update(&c, d, n);
    sha_final_hex(&c, out);
}

static int ct_streq(const char *a, const char *b, size_t n) {   /* constant time, equal lengths */
    unsigned char r = 0;
    size_t i;
    for (i = 0; i < n; i++) r |= (unsigned char)(a[i] ^ b[i]);
    return r == 0;
}

static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64_enc(const uint8_t *in, size_t n, sb_t *out) {
    size_t i;
    for (i = 0; i + 2 < n; i += 3) {
        char q[4];
        q[0] = B64T[in[i] >> 2]; q[1] = B64T[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        q[2] = B64T[((in[i+1] & 15) << 2) | (in[i+2] >> 6)]; q[3] = B64T[in[i+2] & 63];
        sb_putn(out, q, 4);
    }
    if (i < n) {
        char q[4];
        q[0] = B64T[in[i] >> 2];
        if (i + 1 < n) {
            q[1] = B64T[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            q[2] = B64T[(in[i+1] & 15) << 2];
        } else { q[1] = B64T[(in[i] & 3) << 4]; q[2] = '='; }
        q[3] = '=';
        sb_putn(out, q, 4);
    }
}
static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
/* out must hold n/4*3 bytes; returns decoded length or -1 */
static long b64_dec(const char *in, size_t n, uint8_t *out) {
    size_t i, o = 0;
    if (n % 4) return -1;
    for (i = 0; i < n; i += 4) {
        int a = b64_val(in[i]), b = b64_val(in[i+1]), c, d;
        int pad = 0;
        if (a < 0 || b < 0) return -1;
        if (in[i+2] == '=') { if (in[i+3] != '=' || i + 4 != n) return -1; c = 0; d = 0; pad = 2; }
        else {
            c = b64_val(in[i+2]);
            if (c < 0) return -1;
            if (in[i+3] == '=') { if (i + 4 != n) return -1; d = 0; pad = 1; }
            else { d = b64_val(in[i+3]); if (d < 0) return -1; }
        }
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (pad < 2) out[o++] = (uint8_t)(((b & 15) << 4) | (c >> 2));
        if (pad < 1) out[o++] = (uint8_t)(((c & 3) << 6) | d);
    }
    return (long)o;
}

static int utf8_valid(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c == 0) return 0;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xC2 && c <= 0xDF) { if (i + 1 >= n || (s[i+1] & 0xC0) != 0x80) return 0; i += 2; continue; }
        if (c >= 0xE0 && c <= 0xEF) {
            if (i + 2 >= n || (s[i+1] & 0xC0) != 0x80 || (s[i+2] & 0xC0) != 0x80) return 0;
            if (c == 0xE0 && s[i+1] < 0xA0) return 0;
            if (c == 0xED && s[i+1] > 0x9F) return 0;
            i += 3; continue;
        }
        if (c >= 0xF0 && c <= 0xF4) {
            if (i + 3 >= n || (s[i+1] & 0xC0) != 0x80 || (s[i+2] & 0xC0) != 0x80 || (s[i+3] & 0xC0) != 0x80) return 0;
            if (c == 0xF0 && s[i+1] < 0x90) return 0;
            if (c == 0xF4 && s[i+1] > 0x8F) return 0;
            i += 4; continue;
        }
        return 0;
    }
    return 1;
}

/* ════════════════════════════════════════════════════════════════════════════
 * SPPLogE — the audit trail
 *
 * One JSON object per line, append-only (O_APPEND, mode 0600):
 *   {"prev":"<64 hex>","seq":N,"ts":"...Z","ev":"...", ...fields...,"hash":"<64 hex>"}
 * hash = SHA-256 of the line up to (not including) ,"hash". prev is the previous line's hash,
 * so editing, deleting or re-ordering any line breaks the chain from that point on.
 * Truncating the tail is only caught by comparing against a head hash recorded elsewhere
 * (log.head / --expect-head). Rotation keeps the chain: the first line of the new file carries
 * the last hash of the old one in "prev".
 * ════════════════════════════════════════════════════════════════════════════ */
#define LE_ZERO_HASH "0000000000000000000000000000000000000000000000000000000000000000"

static struct {
    pthread_mutex_t lock;
    int      fd;
    char     path[320];
    uint64_t seq, size, max_size, entries, bytes_written, rotations;
    char     head[65];
    volatile int failed;
    int      fail_closed, sync_each, dirty;
    uint64_t last_sync_ms;
} g_log = { PTHREAD_MUTEX_INITIALIZER, -1, "", 0, 0, 64u << 20, 0, 0, 0, LE_ZERO_HASH, 0, 1, 0, 0, 0 };

typedef sb_t ev_t;
static void ev_begin(ev_t *e, const char *name) { sb_init(e); sb_puts(e, "\"ev\":"); sb_json_str(e, name); }
static void ev_s(ev_t *e, const char *k, const char *v) { sb_printf(e, ",\"%s\":", k); sb_json_str(e, v ? v : ""); }
static void ev_u(ev_t *e, const char *k, uint64_t v) { sb_printf(e, ",\"%s\":%" PRIu64, k, v); }
static void ev_i(ev_t *e, const char *k, int64_t v) { sb_printf(e, ",\"%s\":%" PRId64, k, v); }
static void ev_b(ev_t *e, const char *k, int v) { sb_printf(e, ",\"%s\":%s", k, v ? "true" : "false"); }

static void iso_now(char *buf, size_t n) {
    struct timespec ts;
    struct tm tm;
    char t[24];
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    strftime(t, sizeof(t), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buf, n, "%s.%03ldZ", t, ts.tv_nsec / 1000000);
}

static int log_open_locked(void) {
    struct stat st;
    g_log.fd = open(g_log.path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (g_log.fd < 0) return -1;
    if (fstat(g_log.fd, &st) == 0) g_log.size = (uint64_t)st.st_size;
    return 0;
}

static void log_rotate_locked(void) {
    char np[400];
    int n;
    close(g_log.fd);
    g_log.fd = -1;
    for (n = 0; n < 1000; n++) {
        struct stat st;
        snprintf(np, sizeof(np), "%s.%lld.%d", g_log.path, (long long)time(NULL), n);
        if (stat(np, &st) != 0) break;
    }
    if (rename(g_log.path, np) != 0) SP_WARN("audit log rotate: rename failed: %s", strerror(errno));
    else { g_log.rotations++; SP_LOG("audit log rotated to %s", np); }
    g_log.size = 0;
    log_open_locked();
}

static void le_emit(ev_t *e) {
    char ts[40], hx[65];
    sb_t line;
    size_t off = 0;
    if (e->err) { sb_free(e); return; }
    iso_now(ts, sizeof(ts));
    pthread_mutex_lock(&g_log.lock);
    if (g_log.fd < 0 && g_log.path[0]) log_open_locked();
    if (g_log.fd < 0) { g_log.failed = 1; pthread_mutex_unlock(&g_log.lock); sb_free(e); return; }
    sb_init(&line);
    sb_printf(&line, "{\"prev\":\"%s\",\"seq\":%" PRIu64 ",\"ts\":\"%s\",", g_log.head, g_log.seq + 1, ts);
    sb_putn(&line, e->p, e->len);
    sha256_hex((const uint8_t *)line.p, line.len, hx);
    sb_printf(&line, ",\"hash\":\"%s\"}\n", hx);
    if (!line.err) {
        if (g_log.max_size && g_log.size && g_log.size + line.len > g_log.max_size) log_rotate_locked();
        while (g_log.fd >= 0 && off < line.len) {
            ssize_t w = write(g_log.fd, line.p + off, line.len - off);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) break;
            off += (size_t)w;
        }
        if (g_log.fd >= 0 && off == line.len) {
            g_log.seq++;
            memcpy(g_log.head, hx, 65);
            g_log.size += line.len;
            g_log.entries++;
            g_log.bytes_written += line.len;
            g_log.dirty = 1;
            g_log.failed = 0;
            if (g_log.sync_each) { fdatasync(g_log.fd); g_log.dirty = 0; }
        } else {
            if (!g_log.failed) SP_ERR("audit log write failed: %s", strerror(errno));
            g_log.failed = 1;
        }
    } else g_log.failed = 1;
    pthread_mutex_unlock(&g_log.lock);
    sb_free(&line);
    sb_free(e);
}

static void le_log_tick(void) {                 /* once a second: flush to disk */
    pthread_mutex_lock(&g_log.lock);
    if (g_log.dirty && g_log.fd >= 0) { fdatasync(g_log.fd); g_log.dirty = 0; }
    pthread_mutex_unlock(&g_log.lock);
}

static int le_log_unavailable(void) { return g_log.fail_closed && g_log.failed; }

/* Parses one log line. Returns 0 and fills prev / seq / hash when the layout is right. */
static int log_parse_line(const char *line, size_t len, char prev[65], uint64_t *seq, char hash[65], size_t *body_len) {
    const char *p, *h;
    char *end;
    if (len < 9 + 64 + 8 + 12 + 10 + 64 + 3) return -1;
    if (memcmp(line, "{\"prev\":\"", 9) != 0) return -1;
    memcpy(prev, line + 9, 64); prev[64] = '\0';
    p = line + 9 + 64;
    if (memcmp(p, "\",\"seq\":", 8) != 0) return -1;
    *seq = strtoull(p + 8, &end, 10);
    if (end == p + 8) return -1;
    if (len < 4 || line[len - 1] != '}') return -1;
    h = line + len - 75;                    /* ,"hash":"<64>"}  = 9 + 64 + 2 chars */
    if (memcmp(h, ",\"hash\":\"", 9) != 0 || h[73] != '"') return -1;
    memcpy(hash, h + 9, 64); hash[64] = '\0';
    *body_len = (size_t)(h - line);
    return 0;
}

static int hex64_ok(const char *s) {
    int i;
    for (i = 0; i < 64; i++) if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i])) return 0;
    return s[64] == '\0';
}

/* Verifies the chain in a file (reads at most limit bytes when limit > 0). */
static int le_log_verify(const char *path, const char *expect_head, uint64_t limit, sb_t *out) {
    FILE *f = fopen(path, "r");
    char *line = NULL, prev[65], hash[65], chain[65] = "", first_prev[65] = "", why[160] = "";
    size_t cap = 0, bl;
    ssize_t n;
    uint64_t seq, last_seq = 0, first_seq = 0, entries = 0, lineno = 0, readb = 0;
    int ok = 1;
    if (!f) { sb_printf(out, "{\"ok\":false,\"error\":\"cannot open file: %s\"}", strerror(errno)); return -1; }
    while ((n = getline(&line, &cap, f)) > 0) {
        char hx[65];
        readb += (uint64_t)n;
        if (limit && readb > limit) break;
        lineno++;
        if (n > (1 << 20)) { snprintf(why, sizeof(why), "line %" PRIu64 " too long", lineno); ok = 0; break; }
        if (line[n - 1] != '\n') { snprintf(why, sizeof(why), "line %" PRIu64 ": incomplete (no newline)", lineno); ok = 0; break; }
        n--;
        if (log_parse_line(line, (size_t)n, prev, &seq, hash, &bl) < 0 || !hex64_ok(prev) || !hex64_ok(hash)) {
            snprintf(why, sizeof(why), "line %" PRIu64 ": malformed entry", lineno); ok = 0; break;
        }
        sha256_hex((const uint8_t *)line, bl, hx);
        if (memcmp(hx, hash, 64) != 0) { snprintf(why, sizeof(why), "line %" PRIu64 " (seq %" PRIu64 "): hash mismatch, entry was modified", lineno, seq); ok = 0; break; }
        if (entries == 0) { memcpy(first_prev, prev, 65); first_seq = seq; }
        else {
            if (memcmp(prev, chain, 64) != 0) { snprintf(why, sizeof(why), "line %" PRIu64 " (seq %" PRIu64 "): chain broken, entries removed or reordered", lineno, seq); ok = 0; break; }
            if (seq != last_seq + 1) { snprintf(why, sizeof(why), "line %" PRIu64 ": sequence gap (%" PRIu64 " after %" PRIu64 ")", lineno, seq, last_seq); ok = 0; break; }
        }
        memcpy(chain, hash, 65);
        last_seq = seq;
        entries++;
    }
    free(line);
    fclose(f);
    if (ok && entries && expect_head && *expect_head && strcmp(expect_head, chain) != 0) {
        snprintf(why, sizeof(why), "head mismatch: file ends at %.16s..., expected %.16s... (tail truncated or replaced)", chain, expect_head);
        ok = 0;
    }
    sb_printf(out, "{\"ok\":%s,\"entries\":%" PRIu64 ",\"first_seq\":%" PRIu64 ",\"last_seq\":%" PRIu64 ",\"starts_at_genesis\":%s,\"head\":\"%s\"",
              ok ? "true" : "false", entries, first_seq, last_seq,
              entries && strcmp(first_prev, LE_ZERO_HASH) == 0 ? "true" : "false", chain);
    if (!ok) { sb_puts(out, ",\"error\":"); sb_json_str(out, why); }
    sb_putn(out, "}", 1);
    return ok ? 0 : -1;
}

/* Recovers seq/head from the end of an existing log so the chain continues across restarts. */
static void log_recover_tail(void) {
    int fd = open(g_log.path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    char buf[32768], prev[65], hash[65];
    ssize_t n;
    off_t from;
    char *nl, *start;
    size_t len, bl;
    uint64_t seq;
    if (fd < 0) return;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return; }
    from = st.st_size > (off_t)sizeof(buf) ? st.st_size - (off_t)sizeof(buf) : 0;
    n = pread(fd, buf, sizeof(buf), from);
    close(fd);
    if (n <= 1) return;
    len = (size_t)n;
    if (buf[len - 1] != '\n') { SP_WARN("audit log: last line is incomplete; starting a new chain segment"); return; }
    len--;
    nl = (char *)memrchr(buf, '\n', len);
    start = nl ? nl + 1 : (from == 0 ? buf : NULL);
    if (!start) return;
    if (log_parse_line(start, len - (size_t)(start - buf), prev, &seq, hash, &bl) == 0 && hex64_ok(hash)) {
        g_log.seq = seq;
        memcpy(g_log.head, hash, 65);
    } else SP_WARN("audit log: cannot parse the last line; starting a new chain segment");
}

static int le_log_start(const char *path, uint64_t max_size) {
    snprintf(g_log.path, sizeof(g_log.path), "%s", path);
    g_log.max_size = max_size;
    log_recover_tail();
    pthread_mutex_lock(&g_log.lock);
    if (log_open_locked() < 0) { pthread_mutex_unlock(&g_log.lock); return -1; }
    pthread_mutex_unlock(&g_log.lock);
    return 0;
}

/* Parameter summaries: values of sensitive keys are replaced, the rest is cut at 240 bytes. */
static int key_sensitive(const char *k, size_t n) {
    static const char *bad[] = { "token", "secret", "pass", "key", "content", "data", "auth", "cookie", "cred" };
    char low[64];
    size_t i, j;
    if (n >= sizeof(low)) n = sizeof(low) - 1;
    for (i = 0; i < n; i++) low[i] = (char)tolower((unsigned char)k[i]);
    low[n] = '\0';
    for (j = 0; j < sizeof(bad) / sizeof(bad[0]); j++) if (strstr(low, bad[j])) return 1;
    return 0;
}
static void le_redact(const char *json, char *out, size_t outsz) {
    size_t o = 0;
    const char *p = json ? json : "";
#define PUTC(ch) do { if (o + 1 < outsz) out[o++] = (ch); } while (0)
    while (*p && o + 1 < outsz) {
        if (*p == '"') {
            const char *s = p++;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            if (*p == '"') p++;
            {
                const char *q = json_skip_ws(p);
                size_t kl = (size_t)(p - s);
                if (*q == ':' && key_sensitive(s + 1, kl > 2 ? kl - 2 : 0)) {
                    const char *v = json_skip_ws(q + 1);
                    const char *ve = json_skip_value(v);
                    size_t i;
                    for (i = 0; i < kl; i++) PUTC(s[i]);
                    PUTC(':'); PUTC('"'); PUTC('*'); PUTC('*'); PUTC('*'); PUTC('"');
                    p = ve ? ve : v + strlen(v);
                    continue;
                }
                { size_t i; for (i = 0; i < kl; i++) PUTC(s[i]); }
            }
            continue;
        }
        PUTC(*p++);
    }
    out[o] = '\0';
    if (*p && outsz > 4) { out[outsz - 4] = '.'; out[outsz - 3] = '.'; out[outsz - 2] = '.'; out[outsz - 1] = '\0'; }
#undef PUTC
}

static const char *caller_kind_name(int k) { return k == CALLER_TERMINAL ? "terminal" : (k == CALLER_HTTP ? "http" : "peer"); }

static void ev_caller(ev_t *e, const sp_caller_t *c) {
    char ip[INET_ADDRSTRLEN] = "";
    struct in_addr a;
    ev_s(e, "kind", caller_kind_name(c->kind));
    if (c->conn) ev_u(e, "conn", c->conn);
    if (c->ip) { a.s_addr = c->ip; inet_ntop(AF_INET, &a, ip, sizeof(ip)); ev_s(e, "ip", ip); }
    if (c->name[0]) ev_s(e, "principal", c->name);
    if (c->role[0]) ev_s(e, "role", c->role);
}

static void le_peer_closed(uint64_t conn, uint32_t addr, int was_active, uint64_t age_ms) {
    ev_t e;
    char ip[INET_ADDRSTRLEN];
    struct in_addr a;
    a.s_addr = addr;
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    ev_begin(&e, "conn.close");
    ev_u(&e, "conn", conn); ev_s(&e, "ip", ip); ev_b(&e, "handshaken", was_active); ev_u(&e, "age_ms", age_ms);
    le_emit(&e);
}


/* ════════════════════════════════════════════════════════════════════════════
 * SPPPolicyE — enterprise policies
 *
 * Capabilities (the 8 bits) say which KINDS of calls a principal may try. Policy rules say
 * which concrete calls are allowed:
 *     effect  who  action  resource  [hours] [days]
 *   who      * | kind:peer|http | name:<glob> | role:<glob> | mention:<glob> | ip:a.b.c.d[/n] | conn:N
 *            several conditions joined with & must all match, e.g. role:dev&ip:10.0.0.0/8
 *   action   glob over  rpc.<method>  fse.<op>  http.<METHOD>      (* = one segment, ** = anything)
 *   resource glob over the FSE path or HTTP path (default **)
 * Deny overrides allow. When nothing matches the default applies (deny unless --policy-default allow).
 * The terminal is the administrator and is never checked. Mode "audit" logs would-be denials
 * and lets the call through; "lockdown" denies every non-terminal call at once.
 * ════════════════════════════════════════════════════════════════════════════ */
#define POL_MAX_RULES 512

typedef struct {
    uint32_t id;
    int      allow;
    char     who[96], action[64], resource[160], note[64];
    int      hs, he;                 /* minutes since midnight, -1 = any time */
    uint8_t  days;                   /* bit per tm_wday (0 = Sunday), 0x7F = every day */
} pol_rule_t;

static struct {
    pthread_mutex_t lock;
    pol_rule_t rules[POL_MAX_RULES];
    int      n;
    uint32_t next_id;
    int      def_allow, audit_only, lockdown;
    char     file[320];
    uint64_t checks, denies, would_deny;
} g_pol = { PTHREAD_MUTEX_INITIALIZER, {{0}}, 0, 1, 0, 0, 0, "", 0, 0, 0 };

/* O(len(s) * len(g)) glob match: ? = one char (not /), * = any run without /, ** = any run */
static int glob_match(const char *g, const char *s) {
    enum { LIT, ANY1, STAR, DSTAR };
    struct { int t; char c; } tok[200];
    uint8_t a[2100], b[2100], *cur = a, *nxt = b, *tmp;
    size_t nt = 0, n = strlen(s), i, k;
    if (n > 2000 || strlen(g) > 190) return 0;
    {   /* a pattern ending in slash-star-star also covers the directory itself */
        size_t gl = strlen(g);
        if (gl > 3 && strcmp(g + gl - 3, "/**") == 0 && strlen(s) == gl - 3 && strncmp(g, s, gl - 3) == 0) return 1;
    }
    while (*g) {
        if (*g == '*') {
            int dbl = g[1] == '*';
            while (*g == '*') g++;
            tok[nt].t = dbl ? DSTAR : STAR; tok[nt].c = 0; nt++;
        } else if (*g == '?') { tok[nt].t = ANY1; tok[nt].c = 0; nt++; g++; }
        else { tok[nt].t = LIT; tok[nt].c = *g; nt++; g++; }
    }
    memset(cur, 0, n + 1);
    cur[0] = 1;
    for (k = 0; k < nt; k++) {
        memset(nxt, 0, n + 1);
        if (tok[k].t == LIT || tok[k].t == ANY1) {
            for (i = 0; i < n; i++)
                if (cur[i] && (tok[k].t == ANY1 ? s[i] != '/' : s[i] == tok[k].c)) nxt[i + 1] = 1;
        } else {
            for (i = 0; i <= n; i++) {
                if (cur[i]) nxt[i] = 1;
                if (i < n && nxt[i] && (tok[k].t == DSTAR || s[i] != '/')) nxt[i + 1] = 1;
            }
        }
        tmp = cur; cur = nxt; nxt = tmp;
    }
    return cur[n];
}

static int ip_in_cidr(uint32_t ip_net, const char *spec) {
    char buf[40], *slash;
    struct in_addr a;
    int bits = 32;
    uint32_t mask, ip = ntohl(ip_net);
    snprintf(buf, sizeof(buf), "%s", spec);
    slash = strchr(buf, '/');
    if (slash) { *slash++ = '\0'; bits = atoi(slash); }
    if (bits < 0 || bits > 32 || inet_pton(AF_INET, buf, &a) != 1) return 0;
    mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
    return (ip & mask) == (ntohl(a.s_addr) & mask);
}

static int who_cond_match(const char *cond, const sp_caller_t *c) {
    if (strcmp(cond, "*") == 0) return 1;
    if (strncmp(cond, "kind:", 5) == 0) return strcmp(cond + 5, caller_kind_name(c->kind)) == 0;
    if (strncmp(cond, "name:", 5) == 0) return c->name[0] && glob_match(cond + 5, c->name);
    if (strncmp(cond, "role:", 5) == 0) return c->role[0] && glob_match(cond + 5, c->role);
    if (strncmp(cond, "mention:", 8) == 0) return c->mention[0] && glob_match(cond + 8, c->mention);
    if (strncmp(cond, "conn:", 5) == 0) return c->conn && c->conn == strtoull(cond + 5, NULL, 10);
    if (strncmp(cond, "ip:", 3) == 0) return c->ip && ip_in_cidr(c->ip, cond + 3);
    return 0;                                   /* unknown condition never matches */
}

static int who_valid(const char *spec) {
    char buf[96], *tok, *save = NULL;
    snprintf(buf, sizeof(buf), "%s", spec);
    if (!*buf) return 0;
    for (tok = strtok_r(buf, "&", &save); tok; tok = strtok_r(NULL, "&", &save)) {
        if (strcmp(tok, "*") == 0) continue;
        if (strncmp(tok, "kind:", 5) == 0) { if (strcmp(tok + 5, "peer") && strcmp(tok + 5, "http")) return 0; continue; }
        if (!strncmp(tok, "name:", 5) || !strncmp(tok, "role:", 5) || !strncmp(tok, "mention:", 8)) { if (!tok[strcspn(tok, ":") + 1]) return 0; continue; }
        if (strncmp(tok, "conn:", 5) == 0) { if (!isdigit((unsigned char)tok[5])) return 0; continue; }
        if (strncmp(tok, "ip:", 3) == 0) {
            char t2[40], *sl;
            struct in_addr a;
            snprintf(t2, sizeof(t2), "%s", tok + 3);
            sl = strchr(t2, '/');
            if (sl) { *sl++ = '\0'; if (atoi(sl) < 0 || atoi(sl) > 32 || !isdigit((unsigned char)*sl)) return 0; }
            if (inet_pton(AF_INET, t2, &a) != 1) return 0;
            continue;
        }
        return 0;
    }
    return 1;
}

static int who_match(const char *spec, const sp_caller_t *c) {
    char buf[96], *tok, *save = NULL;
    snprintf(buf, sizeof(buf), "%s", spec);
    for (tok = strtok_r(buf, "&", &save); tok; tok = strtok_r(NULL, "&", &save))
        if (!who_cond_match(tok, c)) return 0;
    return 1;
}

static int rule_time_ok(const pol_rule_t *r) {
    time_t t = time(NULL);
    struct tm tm;
    int mins;
    localtime_r(&t, &tm);
    if (!(r->days & (1 << tm.tm_wday))) return 0;
    if (r->hs < 0) return 1;
    mins = tm.tm_hour * 60 + tm.tm_min;
    if (r->hs <= r->he) return mins >= r->hs && mins < r->he;
    return mins >= r->hs || mins < r->he;       /* window wraps past midnight */
}

static int parse_hours(const char *s, int *hs, int *he) {
    int h1, m1, h2, m2;
    if (!s || !*s || strcmp(s, "any") == 0) { *hs = *he = -1; return 0; }
    if (sscanf(s, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) != 4) return -1;
    if (h1 < 0 || h1 > 23 || h2 < 0 || h2 > 24 || m1 < 0 || m1 > 59 || m2 < 0 || m2 > 59) return -1;
    *hs = h1 * 60 + m1; *he = h2 * 60 + m2;
    return 0;
}

static int parse_days(const char *s, uint8_t *out) {
    static const char *nm[7] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
    char buf[64], *tok, *save = NULL;
    unsigned v = 0;
    int i;
    if (!s || !*s || strcmp(s, "all") == 0 || strcmp(s, "any") == 0) { *out = 0x7F; return 0; }
    snprintf(buf, sizeof(buf), "%s", s);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *dash = strchr(tok, '-');
        int a = -1, b = -1;
        if (dash) *dash++ = '\0';
        for (i = 0; i < 7; i++) { if (strcasecmp(tok, nm[i]) == 0) a = i; if (dash && strcasecmp(dash, nm[i]) == 0) b = i; }
        if (a < 0 || (dash && b < 0)) return -1;
        if (!dash) { v |= 1u << a; continue; }
        for (i = a;; i = (i + 1) % 7) { v |= 1u << i; if (i == b) break; }
    }
    *out = (uint8_t)v;
    return v ? 0 : -1;
}

static void days_str(uint8_t d, char *out, size_t n) {
    static const char *nm[7] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
    int i;
    size_t l = 0;
    out[0] = '\0';
    if (d == 0x7F) { snprintf(out, n, "all"); return; }
    for (i = 0; i < 7; i++) if (d & (1 << i)) l += (size_t)snprintf(out + l, n - l, "%s%s", l ? "," : "", nm[i]);
}

static int is_always_allowed(const char *action) {
    static const char *ok[] = { "rpc.identity", "rpc.rpc.methods", "rpc.auth.login", "rpc.auth.whoami", "rpc.auth.logout",
                                "rpc.policy.get", "rpc.policy.check", "rpc.peer.status" };
    size_t i;
    for (i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) if (strcmp(action, ok[i]) == 0) return 1;
    return 0;
}

/* 1 = allowed, 0 = denied (reason in why). Every decision except the always-allowed set is logged. */
static int policy_check(const sp_caller_t *c, const char *action, const char *resource, char *why, size_t wn) {
    int i, allow, rule = 0, would = 0;
    const char *res = (resource && *resource) ? resource : "*";
    const char *why_s = "";
    ev_t e;
    why[0] = '\0';
    if (c->kind == CALLER_TERMINAL) return 1;
    if (is_always_allowed(action)) return 1;
    SP_INC(g_pol.checks);
    if (le_log_unavailable()) {
        snprintf(why, wn, "audit log unavailable (fail-closed)");
        SP_INC(g_pol.denies);
        return 0;
    }
    pthread_mutex_lock(&g_pol.lock);
    if (g_pol.lockdown) { allow = 0; why_s = "lockdown"; }
    else {
        int hit_allow = 0, hit_deny = 0;
        uint32_t aid = 0, did = 0;
        for (i = 0; i < g_pol.n; i++) {
            const pol_rule_t *r = &g_pol.rules[i];
            if (!who_match(r->who, c) || !glob_match(r->action, action) || !glob_match(r->resource, res) || !rule_time_ok(r)) continue;
            if (r->allow) { if (!hit_allow) { hit_allow = 1; aid = r->id; } }
            else if (!hit_deny) { hit_deny = 1; did = r->id; }
        }
        if (hit_deny) { allow = 0; rule = (int)did; why_s = "deny rule"; }
        else if (hit_allow) { allow = 1; rule = (int)aid; why_s = "allow rule"; }
        else { allow = g_pol.def_allow; why_s = allow ? "default allow" : "no matching allow rule"; }
    }
    if (!allow && g_pol.audit_only) { would = 1; allow = 1; }
    pthread_mutex_unlock(&g_pol.lock);

    ev_begin(&e, "policy");
    ev_caller(&e, c);
    ev_s(&e, "action", action); ev_s(&e, "resource", res);
    ev_s(&e, "decision", would ? "would-deny" : (allow ? "allow" : "deny"));
    ev_u(&e, "rule", (uint64_t)rule); ev_s(&e, "reason", why_s);
    le_emit(&e);
    if (would) SP_INC(g_pol.would_deny);
    if (!allow) {
        SP_INC(g_pol.denies);
        if (rule) snprintf(why, wn, "rule %d", rule); else snprintf(why, wn, "%s", why_s);
        return 0;
    }
    return 1;
}

/* persistence: id|effect|who|action|resource|hours|days|note */
static void pol_save_locked(void) {
    char tmp[340], hrs[40], dys[32];
    FILE *f;
    int i;
    if (!g_pol.file[0]) return;
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_pol.file);
    f = fopen(tmp, "w");
    if (!f) { SP_WARN("policy: cannot save %s: %s", g_pol.file, strerror(errno)); return; }
    fchmod(fileno(f), 0600);
    for (i = 0; i < g_pol.n; i++) {
        const pol_rule_t *r = &g_pol.rules[i];
        if (r->hs < 0) snprintf(hrs, sizeof(hrs), "any");
        else snprintf(hrs, sizeof(hrs), "%02d:%02d-%02d:%02d", r->hs / 60, r->hs % 60, r->he / 60, r->he % 60);
        days_str(r->days, dys, sizeof(dys));
        fprintf(f, "%u|%s|%s|%s|%s|%s|%s|%s\n", r->id, r->allow ? "allow" : "deny", r->who, r->action, r->resource, hrs, dys, r->note);
    }
    if (fclose(f) == 0) { if (rename(tmp, g_pol.file) != 0) SP_WARN("policy: rename failed: %s", strerror(errno)); }
}

static int pol_field_ok(const char *s, size_t max) {
    size_t i, n = strlen(s);
    if (n >= max) return 0;
    for (i = 0; i < n; i++) if ((unsigned char)s[i] < 0x20 || s[i] == '|' || s[i] == 0x7f) return 0;
    return 1;
}

/* returns the new id or 0 (message in err) */
static uint32_t pol_add(int allow, const char *who, const char *action, const char *resource,
                        const char *hours, const char *days, const char *note, char *err, size_t errsz) {
    pol_rule_t r;
    uint32_t id = 0;
    memset(&r, 0, sizeof(r));
    if (!pol_field_ok(who, sizeof(r.who)) || !pol_field_ok(action, sizeof(r.action)) || !pol_field_ok(resource, sizeof(r.resource)) ||
        !pol_field_ok(note, sizeof(r.note))) { snprintf(err, errsz, "field too long or contains a forbidden character"); return 0; }
    if (!who_valid(who)) { snprintf(err, errsz, "bad who (use *, kind:, name:, role:, mention:, ip:, conn:, joined with &)"); return 0; }
    if (!*action) { snprintf(err, errsz, "action required"); return 0; }
    if (parse_hours(hours, &r.hs, &r.he) < 0) { snprintf(err, errsz, "hours must look like 09:00-18:00"); return 0; }
    if (parse_days(days, &r.days) < 0) { snprintf(err, errsz, "days must look like mon-fri or sat,sun"); return 0; }
    r.allow = allow;
    snprintf(r.who, sizeof(r.who), "%s", who);
    snprintf(r.action, sizeof(r.action), "%s", action);
    snprintf(r.resource, sizeof(r.resource), "%s", *resource ? resource : "**");
    snprintf(r.note, sizeof(r.note), "%s", note);
    pthread_mutex_lock(&g_pol.lock);
    if (g_pol.n >= POL_MAX_RULES) snprintf(err, errsz, "rule table full (%d)", POL_MAX_RULES);
    else {
        id = r.id = g_pol.next_id++;
        g_pol.rules[g_pol.n++] = r;
        pol_save_locked();
    }
    pthread_mutex_unlock(&g_pol.lock);
    return id;
}

static void pol_load(void) {
    FILE *f;
    char line[512];
    if (!g_pol.file[0] || !(f = fopen(g_pol.file, "r"))) return;
    while (fgets(line, sizeof(line), f)) {
        char *fld[8], *p = line;
        int k = 0;
        char err[100];
        uint32_t id;
        line[strcspn(line, "\r\n")] = '\0';
        fld[k++] = p;
        while (*p && k < 8) if (*p++ == '|') { p[-1] = '\0'; fld[k++] = p; }
        if (k != 8) { SP_WARN("policy: skipping malformed line in %s", g_pol.file); continue; }
        id = pol_add(strcmp(fld[1], "allow") == 0, fld[2], fld[3], fld[4], fld[5], fld[6], fld[7], err, sizeof(err));
        if (!id) SP_WARN("policy: skipping rule: %s", err);
        else if ((uint32_t)strtoul(fld[0], NULL, 10) >= g_pol.next_id) g_pol.next_id = (uint32_t)strtoul(fld[0], NULL, 10) + 1;
    }
    fclose(f);
    SP_LOG("policy: %d rule(s) loaded from %s", g_pol.n, g_pol.file);
}

/* ════════════════════════════════════════════════════════════════════════════
 * API tokens (SPPServer logins and SPP auth.login). Only SHA-256 hashes are kept.
 * ════════════════════════════════════════════════════════════════════════════ */
#define TOK_MAX 256
typedef struct {
    int      used;
    uint32_t id;
    char     name[40], sha[65], role[24];
    uint8_t  caps;
    uint64_t created_s, expires_s;      /* expires_s 0 = never */
    uint64_t uses;
} tok_t;

static tok_t g_tok[TOK_MAX];
static pthread_mutex_t g_tok_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_tok_next = 1;
static char g_tok_file[320];

static int name_ok(const char *s, size_t max) {
    size_t n = s ? strlen(s) : 0, i;
    if (n < 1 || n >= max) return 0;
    for (i = 0; i < n; i++) if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-' && s[i] != '.') return 0;
    return 1;
}

static void tok_save_locked(void) {
    char tmp[340];
    FILE *f;
    int i;
    if (!g_tok_file[0]) return;
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_tok_file);
    f = fopen(tmp, "w");
    if (!f) { SP_WARN("tokens: cannot save: %s", strerror(errno)); return; }
    fchmod(fileno(f), 0600);
    for (i = 0; i < TOK_MAX; i++) {
        const tok_t *t = &g_tok[i];
        if (t->used) fprintf(f, "%s|%s|%u|%s|%" PRIu64 "|%" PRIu64 "\n", t->name, t->sha, t->caps, t->role, t->expires_s, t->created_s);
    }
    if (fclose(f) == 0) rename(tmp, g_tok_file);
}

static void tok_load(void) {
    FILE *f;
    char line[300];
    if (!g_tok_file[0] || !(f = fopen(g_tok_file, "r"))) return;
    while (fgets(line, sizeof(line), f)) {
        char *fld[6], *p = line;
        int k = 0, i;
        line[strcspn(line, "\r\n")] = '\0';
        fld[k++] = p;
        while (*p && k < 6) if (*p++ == '|') { p[-1] = '\0'; fld[k++] = p; }
        if (k != 6 || !name_ok(fld[0], 40) || !hex64_ok(fld[1])) continue;
        for (i = 0; i < TOK_MAX; i++) if (!g_tok[i].used) {
            tok_t *t = &g_tok[i];
            memset(t, 0, sizeof(*t));
            t->used = 1; t->id = g_tok_next++;
            snprintf(t->name, sizeof(t->name), "%s", fld[0]);
            snprintf(t->sha, sizeof(t->sha), "%s", fld[1]);
            t->caps = (uint8_t)atoi(fld[2]);
            snprintf(t->role, sizeof(t->role), "%s", fld[3]);
            t->expires_s = strtoull(fld[4], NULL, 10);
            t->created_s = strtoull(fld[5], NULL, 10);
            break;
        }
    }
    fclose(f);
}

/* Finds a token by its secret; fills the principal. Returns the token id or 0. */
static uint32_t tok_lookup(const char *secret, uint8_t *caps, char *name, size_t nn, char *role, size_t rn) {
    char hx[65];
    uint32_t id = 0;
    int i;
    uint64_t now = (uint64_t)time(NULL);
    if (!secret || strlen(secret) < 8 || strlen(secret) > 128) return 0;
    sha256_hex((const uint8_t *)secret, strlen(secret), hx);
    pthread_mutex_lock(&g_tok_lock);
    for (i = 0; i < TOK_MAX; i++) {
        tok_t *t = &g_tok[i];
        if (!t->used) continue;
        if (ct_streq(t->sha, hx, 64) && id == 0 && (t->expires_s == 0 || t->expires_s > now)) {
            id = t->id; *caps = t->caps; t->uses++;
            snprintf(name, nn, "%s", t->name);
            snprintf(role, rn, "%s", t->role);
        }
    }
    pthread_mutex_unlock(&g_tok_lock);
    return id;
}

/* live sessions of a token lose their caps when it is revoked or expires */
static void tok_drop_sessions(uint32_t id) {
    size_t i;
    pthread_mutex_lock(&g_sp.peers_lock);
    for (i = 0; i < g_sp.peer_hi; i++) {
        spp_peer_t *p = &g_sp.peers[i];
        if ((p->active || p->hs) && p->tok_id == id) {
            __atomic_store_n(&p->sp_caps, g_sp.default_caps, __ATOMIC_RELAXED);
            p->tok_id = 0; p->principal[0] = '\0'; p->role[0] = '\0';
        }
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
}

static void tok_tick(void) {
    uint64_t now = (uint64_t)time(NULL);
    uint32_t dead[8];
    int nd = 0, i;
    pthread_mutex_lock(&g_tok_lock);
    for (i = 0; i < TOK_MAX && nd < 8; i++) {
        tok_t *t = &g_tok[i];
        if (t->used && t->expires_s && t->expires_s <= now) { dead[nd++] = t->id; t->used = 0; }
    }
    if (nd) tok_save_locked();
    pthread_mutex_unlock(&g_tok_lock);
    for (i = 0; i < nd; i++) {
        ev_t e;
        tok_drop_sessions(dead[i]);
        ev_begin(&e, "token.expire"); ev_u(&e, "id", dead[i]); le_emit(&e);
    }
}


/* ════════════════════════════════════════════════════════════════════════════
 * FSE — the enterprise filesystem
 *
 * Touch, read, edit, move, copy, delete and execute REAL files, but only inside one root
 * directory (--fse-root). Every path is walked one component at a time with openat(O_NOFOLLOW):
 * symlinks are never followed, ".." is rejected, and a path can therefore never leave the
 * root, even if somebody plants a symlink there. Every operation passes the capability check
 * (fsr / fsw / exec) and then SPPPolicyE with action fse.<op> and the canonical path.
 * ════════════════════════════════════════════════════════════════════════════ */
#define RPC_ERR(...) do { snprintf(err, errsz, __VA_ARGS__); return -1; } while (0)

#define FSE_MAXPATH  1024
#define FSE_MAXDEPTH 32
#define FSE_IO_MAX   32768            /* raw bytes per read call */
#define FSE_WRITE_MAX 49152           /* raw bytes per write call (an SPP frame is 64 KB) */

static struct {
    int      ready, root_fd, exec_enabled;
    char     root[PATH_MAX];
    uint64_t max_file;
    int      execs;
    uint64_t ops, bytes_read, bytes_written, exec_total;
} g_fse = { 0, -1, 0, "", 256ull << 20, 0, 0, 0, 0, 0 };

typedef struct { int dirfd; char leaf[256]; char canon[FSE_MAXPATH + 2]; int is_root; } fse_ref_t;

static void fse_close(fse_ref_t *r) {
    if (r->dirfd >= 0 && r->dirfd != g_fse.root_fd) close(r->dirfd);
    r->dirfd = -1;
}

static void fse_errno(const char *what, char *err, size_t errsz) {
    int e = errno;
    if (e == ELOOP) snprintf(err, errsz, "%s: symlink refused", what);
    else if (e == ENOENT) snprintf(err, errsz, "%s: no such file or directory", what);
    else snprintf(err, errsz, "%s: %s", what, strerror(e));
}

/* Walks to the parent directory of path. mkparents creates missing directories on the way. */
static int fse_gate(const rpc_req_t *rq, uint8_t need, const char *action, const char *canon, char *err, size_t errsz);

static int fse_resolve(const char *path, fse_ref_t *r, int mkparents, const rpc_req_t *rq, uint8_t need, const char *action, char *err, size_t errsz) {
    const char *p = path ? path : "", *comps[FSE_MAXDEPTH];
    size_t lens[FSE_MAXDEPTH], n = strlen(p), i, cl = 0;
    int nc = 0, cur;
    memset(r, 0, sizeof(*r));
    r->dirfd = -1;
    if (!g_fse.ready) RPC_ERR("fse is not configured");
    if (n == 0 || n > FSE_MAXPATH) RPC_ERR("bad path length");
    if (p[0] != '/') RPC_ERR("path must be absolute (start with /)");
    while (*p) {
        const char *s;
        size_t l, j;
        while (*p == '/') p++;
        if (!*p) break;
        s = p;
        while (*p && *p != '/') p++;
        l = (size_t)(p - s);
        if (l == 1 && s[0] == '.') continue;
        if (l == 2 && s[0] == '.' && s[1] == '.') RPC_ERR("'..' is not allowed");
        if (l > 255) RPC_ERR("name too long");
        for (j = 0; j < l; j++) if ((unsigned char)s[j] < 0x20 || s[j] == 0x7f) RPC_ERR("control character in path");
        if (nc >= FSE_MAXDEPTH) RPC_ERR("path too deep");
        comps[nc] = s; lens[nc] = l; nc++;
    }
    r->canon[cl++] = '/';
    for (i = 0; i < (size_t)nc; i++) {
        memcpy(r->canon + cl, comps[i], lens[i]); cl += lens[i];
        if (i + 1 < (size_t)nc) r->canon[cl++] = '/';
    }
    r->canon[cl] = '\0';
    if (rq && fse_gate(rq, need, action, r->canon, err, errsz) < 0) return -1;   /* before any disk access: no existence leaks */
    if (nc == 0) { r->is_root = 1; r->dirfd = g_fse.root_fd; return 0; }
    cur = g_fse.root_fd;
    for (i = 0; i + 1 < (size_t)nc; i++) {
        char comp[256];
        int nfd, e;
        memcpy(comp, comps[i], lens[i]); comp[lens[i]] = '\0';
        nfd = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nfd < 0 && errno == ENOENT && mkparents && mkdirat(cur, comp, 0750) == 0)
            nfd = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        e = errno;
        if (cur != g_fse.root_fd) close(cur);
        if (nfd < 0) { errno = e; fse_errno("path", err, errsz); return -1; }
        cur = nfd;
    }
    r->dirfd = cur;
    memcpy(r->leaf, comps[nc - 1], lens[nc - 1]);
    r->leaf[lens[nc - 1]] = '\0';
    return 0;
}

/* capability + policy for one FSE action */
static int fse_gate(const rpc_req_t *rq, uint8_t need, const char *action, const char *canon, char *err, size_t errsz) {
    char why[100], nb[48];
    if ((rq->caller.caps & need) != need) RPC_ERR("denied: needs cap %s", need_str(need, nb, sizeof(nb)));
    if (!policy_check(&rq->caller, action, canon, why, sizeof(why))) RPC_ERR("denied by policy (%s)", why);
    SP_INC(g_fse.ops);
    return 0;
}

static const char *mode_type(mode_t m) {
    if (S_ISREG(m)) return "file";
    if (S_ISDIR(m)) return "dir";
    if (S_ISLNK(m)) return "link";
    return "other";
}

static void fse_stat_json(sb_t *out, const struct stat *st) {
    sb_printf(out, "\"type\":\"%s\",\"size\":%lld,\"mode\":\"%04o\",\"mtime\":%lld,\"uid\":%u,\"gid\":%u",
              mode_type(st->st_mode), (long long)st->st_size, (unsigned)(st->st_mode & 0777), (long long)st->st_mtime,
              (unsigned)st->st_uid, (unsigned)st->st_gid);
}

static int fse_lstat(const fse_ref_t *r, struct stat *st) {
    if (r->is_root) return fstat(g_fse.root_fd, st);
    return fstatat(r->dirfd, r->leaf, st, AT_SYMLINK_NOFOLLOW);
}

/* opens a regular file for reading; used by fse.read, fse.hash and HTTP downloads */
static int fse_open_read(const char *path, struct stat *st, char *canon, size_t cn, const rpc_req_t *rq, char *err, size_t errsz) {
    fse_ref_t r;
    int fd;
    if (fse_resolve(path, &r, 0, rq, SPCAP_FSR, "fse.read", err, errsz) < 0) return -1;
    if (canon) snprintf(canon, cn, "%s", r.canon);
    if (r.is_root) { fse_close(&r); RPC_ERR("is a directory"); }
    fd = openat(r.dirfd, r.leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { fse_errno("open", err, errsz); fse_close(&r); return -1; }
    fse_close(&r);
    if (fstat(fd, st) < 0 || !S_ISREG(st->st_mode)) { close(fd); RPC_ERR("not a regular file"); }
    return fd;
}

/* write bytes to a file inside the jail. mode: write | append | create | patch */
static int fse_write_core(const char *path, const uint8_t *data, size_t n, const char *mode, uint64_t offset,
                          mode_t perm, int parents, const rpc_req_t *rq, uint64_t *newsize, char *canon_out, size_t cn,
                          char *err, size_t errsz) {
    fse_ref_t r;
    int fd, flags = O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    struct stat st;
    size_t off = 0;
    if (strcmp(mode, "write") == 0) flags |= O_CREAT | O_TRUNC;
    else if (strcmp(mode, "append") == 0) flags |= O_CREAT | O_APPEND;
    else if (strcmp(mode, "create") == 0) flags |= O_CREAT | O_EXCL;
    else if (strcmp(mode, "patch") == 0) { /* must exist */ }
    else RPC_ERR("mode must be write, append, create or patch");
    if (fse_resolve(path, &r, parents, rq, SPCAP_FSW, "fse.write", err, errsz) < 0) return -1;
    if (canon_out) snprintf(canon_out, cn, "%s", r.canon);
    if (r.is_root) { fse_close(&r); RPC_ERR("is a directory"); }
    fd = openat(r.dirfd, r.leaf, flags, perm);
    if (fd < 0) { fse_errno("open", err, errsz); fse_close(&r); return -1; }
    fse_close(&r);
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) { close(fd); RPC_ERR("not a regular file"); }
    {
        uint64_t base = strcmp(mode, "patch") == 0 ? offset : (strcmp(mode, "append") == 0 ? (uint64_t)st.st_size : 0);
        if (base + n > g_fse.max_file) { close(fd); RPC_ERR("file would exceed the %" PRIu64 " byte limit", g_fse.max_file); }
    }
    while (off < n) {
        ssize_t w = strcmp(mode, "patch") == 0 ? pwrite(fd, data + off, n - off, (off_t)(offset + off)) : write(fd, data + off, n - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { fse_errno("write", err, errsz); close(fd); return -1; }
        off += (size_t)w;
    }
    if (fstat(fd, &st) == 0 && newsize) *newsize = (uint64_t)st.st_size;
    close(fd);
    g_fse.bytes_written += n;
    return 0;
}

static int fse_rmrf(int dirfd, const char *name, int depth, long *count) {
    int fd;
    DIR *d;
    struct dirent *de;
    if (depth > 64) { errno = ELOOP; return -1; }
    fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOTDIR || errno == ELOOP) return unlinkat(dirfd, name, 0);
        return -1;
    }
    d = fdopendir(fd);
    if (!d) { close(fd); return -1; }
    while ((de = readdir(d)) != NULL) {
        struct stat st;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (++*count > 200000) { closedir(d); errno = EFBIG; return -1; }
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) continue;
        if (S_ISDIR(st.st_mode)) { if (fse_rmrf(fd, de->d_name, depth + 1, count) < 0) { int e = errno; closedir(d); errno = e; return -1; } }
        else if (unlinkat(fd, de->d_name, 0) < 0) { int e = errno; closedir(d); errno = e; return -1; }
    }
    closedir(d);
    return unlinkat(dirfd, name, AT_REMOVEDIR);
}

static int fse_rm_core(const char *path, int recursive, const rpc_req_t *rq, char *canon_out, size_t cn, char *err, size_t errsz) {
    fse_ref_t r;
    struct stat st;
    long count = 0;
    int rc;
    if (fse_resolve(path, &r, 0, rq, SPCAP_FSW, "fse.rm", err, errsz) < 0) return -1;
    if (canon_out) snprintf(canon_out, cn, "%s", r.canon);
    if (r.is_root) { fse_close(&r); RPC_ERR("the root cannot be removed"); }
    if (fstatat(r.dirfd, r.leaf, &st, AT_SYMLINK_NOFOLLOW) < 0) { fse_errno("stat", err, errsz); fse_close(&r); return -1; }
    if (S_ISDIR(st.st_mode)) rc = recursive ? fse_rmrf(r.dirfd, r.leaf, 0, &count) : unlinkat(r.dirfd, r.leaf, AT_REMOVEDIR);
    else rc = unlinkat(r.dirfd, r.leaf, 0);
    if (rc < 0) fse_errno("remove", err, errsz);
    fse_close(&r);
    return rc;
}

/* ── RPC methods ───────────────────────────────────────────────────────────── */
static int rpc_fse_info(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_printf(out, "{\"ready\":%s,\"exec_enabled\":%s,\"max_file\":%" PRIu64 ",\"max_read\":%d,\"max_write\":%d}",
              g_fse.ready ? "true" : "false", g_fse.exec_enabled ? "true" : "false", g_fse.max_file, FSE_IO_MAX, FSE_WRITE_MAX);
    return 0;
}

static int rpc_fse_stat(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path");
    fse_ref_t r;
    struct stat st;
    int rc = -1;
    if (!path) RPC_ERR("path required");
    if (fse_resolve(path, &r, 0, rq, SPCAP_FSR, "fse.stat", err, errsz) < 0) { free(path); return -1; }
    free(path);
    {
        if (fse_lstat(&r, &st) < 0) fse_errno("stat", err, errsz);
        else { sb_puts(out, "{\"path\":"); sb_json_str(out, r.canon); sb_putn(out, ",", 1); fse_stat_json(out, &st); sb_putn(out, "}", 1); rc = 0; }
    }
    fse_close(&r);
    return rc;
}

static int name_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int rpc_fse_ls(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), **names = NULL;
    fse_ref_t r;
    int dfd, rc = -1, truncated = 0;
    size_t nn = 0, cap = 0, i;
    int64_t cursor = 0, limit = 200;
    DIR *d;
    struct dirent *de;
    json_get_i64(params, "cursor", &cursor);
    json_get_i64(params, "limit", &limit);
    if (cursor < 0) cursor = 0;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    if (!path) RPC_ERR("path required");
    if (fse_resolve(path, &r, 0, rq, SPCAP_FSR, "fse.ls", err, errsz) < 0) { free(path); return -1; }
    free(path);
    dfd = r.is_root ? openat(g_fse.root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                    : openat(r.dirfd, r.leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) { fse_errno("open", err, errsz); fse_close(&r); return -1; }
    d = fdopendir(dfd);
    if (!d) { close(dfd); fse_close(&r); RPC_ERR("fdopendir failed"); }
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (nn >= 20000) { truncated = 1; break; }
        if (nn == cap) {
            char **nb = (char **)realloc(names, (cap ? cap * 2 : 256) * sizeof(char *));
            if (!nb) break;
            names = nb; cap = cap ? cap * 2 : 256;
        }
        names[nn] = strdup(de->d_name);
        if (names[nn]) nn++;
    }
    qsort(names, nn, sizeof(char *), name_cmp);
    sb_puts(out, "{\"path\":"); sb_json_str(out, r.canon);
    sb_puts(out, ",\"entries\":[");
    {
        int64_t next = -1;
        int first = 1;
        for (i = (size_t)cursor; i < nn; i++) {
            struct stat st;
            if (limit-- == 0 || out->len > SPP_MAX_PAYLOAD - 2048) { next = (int64_t)i; break; }
            if (fstatat(dirfd(d), names[i], &st, AT_SYMLINK_NOFOLLOW) < 0) continue;
            sb_printf(out, "%s{\"name\":", first ? "" : ",");
            sb_json_str(out, names[i]);
            sb_putn(out, ",", 1);
            fse_stat_json(out, &st);
            sb_putn(out, "}", 1);
            first = 0;
        }
        sb_printf(out, "],\"total\":%zu,\"truncated\":%s,\"next\":%" PRId64 "}", nn, truncated ? "true" : "false", next);
    }
    rc = 0;
    for (i = 0; i < nn; i++) free(names[i]);
    free(names);
    closedir(d);
    fse_close(&r);
    return rc;
}

static int rpc_fse_read(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), *enc = json_str_dup(params, "enc"), canon[FSE_MAXPATH + 2];
    int64_t offset = 0, length = 16384;
    struct stat st;
    int fd, b64, rc = -1;
    uint8_t *buf;
    ssize_t n;
    json_get_i64(params, "offset", &offset);
    json_get_i64(params, "length", &length);
    b64 = enc && strcmp(enc, "base64") == 0;
    if (enc && !b64 && strcmp(enc, "utf8") != 0) { free(path); free(enc); RPC_ERR("enc must be utf8 or base64"); }
    free(enc);
    if (!path) RPC_ERR("path required");
    if (offset < 0 || length < 1) { free(path); RPC_ERR("bad offset or length"); }
    if (length > FSE_IO_MAX) length = FSE_IO_MAX;
    fd = fse_open_read(path, &st, canon, sizeof(canon), rq, err, errsz);
    free(path);
    if (fd < 0) return -1;
    buf = (uint8_t *)malloc((size_t)length + 1);
    if (!buf) { close(fd); RPC_ERR("out of memory"); }
    n = pread(fd, buf, (size_t)length, (off_t)offset);
    close(fd);
    if (n < 0) { fse_errno("read", err, errsz); free(buf); return -1; }
    g_fse.bytes_read += (uint64_t)n;
    if (!b64 && !utf8_valid(buf, (size_t)n)) { free(buf); RPC_ERR("not valid UTF-8 text here: use enc=base64 (or a different range)"); }
    sb_puts(out, "{\"path\":"); sb_json_str(out, canon);
    sb_printf(out, ",\"size\":%lld,\"offset\":%" PRId64 ",\"length\":%zd,\"eof\":%s,\"enc\":\"%s\",\"data\":", (long long)st.st_size, offset, n,
              offset + n >= st.st_size ? "true" : "false", b64 ? "base64" : "utf8");
    if (b64) { sb_putn(out, "\"", 1); b64_enc(buf, (size_t)n, out); sb_putn(out, "\"", 1); }
    else { buf[n] = '\0'; sb_json_str(out, (const char *)buf); }
    sb_putn(out, "}", 1);
    free(buf);
    if (out->len > SPP_MAX_PAYLOAD - 256) { out->len = 0; if (out->p) out->p[0] = '\0'; RPC_ERR("response too large for one frame: use a smaller length or enc=base64"); }
    rc = 0;
    return rc;
}

static mode_t parse_perm(const char *s, mode_t dflt) {
    char *end;
    unsigned long v;
    if (!s || !*s) return dflt;
    v = strtoul(s, &end, 8);
    if (*end || v > 0777) return (mode_t)-1;
    return (mode_t)v;
}

static int rpc_fse_write(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), *content = json_str_dup(params, "content"), *enc = json_str_dup(params, "enc");
    char *mode = json_str_dup(params, "mode"), *permv = json_str_dup(params, "perm"), canon[FSE_MAXPATH + 2];
    uint8_t *data = NULL;
    size_t n = 0;
    int64_t offset = 0;
    uint64_t newsize = 0;
    mode_t perm;
    int rc = -1;
    json_get_i64(params, "offset", &offset);
    perm = parse_perm(permv, 0640);
    if (!path) { snprintf(err, errsz, "path required"); goto done; }
    if (!content) { snprintf(err, errsz, "content required (string)"); goto done; }
    if (perm == (mode_t)-1) { snprintf(err, errsz, "perm must be octal like 0640"); goto done; }
    if (offset < 0) { snprintf(err, errsz, "bad offset"); goto done; }
    if (enc && strcmp(enc, "base64") == 0) {
        data = (uint8_t *)malloc(strlen(content) / 4 * 3 + 4);
        if (!data) { snprintf(err, errsz, "out of memory"); goto done; }
        {
            long dn = b64_dec(content, strlen(content), data);
            if (dn < 0) { snprintf(err, errsz, "invalid base64"); goto done; }
            n = (size_t)dn;
        }
    } else if (!enc || strcmp(enc, "utf8") == 0) { data = (uint8_t *)content; content = NULL; n = strlen((char *)data); }
    else { snprintf(err, errsz, "enc must be utf8 or base64"); goto done; }
    if (n > FSE_WRITE_MAX) { snprintf(err, errsz, "too much data for one call (max %d bytes): send chunks with mode append or patch", FSE_WRITE_MAX); goto done; }
    if (fse_write_core(path, data, n, mode ? mode : "write", (uint64_t)offset, perm, json_true(params, "parents"), rq, &newsize,
                       canon, sizeof(canon), err, errsz) < 0) goto done;
    sb_puts(out, "{\"path\":"); sb_json_str(out, canon);
    sb_printf(out, ",\"written\":%zu,\"size\":%" PRIu64 "}", n, newsize);
    rc = 0;
done:
    free(path); free(enc); free(mode); free(permv);
    if (content) free(content);
    if (data && (void *)data != (void *)content) free(data);
    return rc;
}

static int rpc_fse_touch(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path");
    fse_ref_t r;
    int fd, rc = -1;
    struct stat st;
    if (!path) RPC_ERR("path required");
    if (fse_resolve(path, &r, json_true(params, "parents"), rq, SPCAP_FSW, "fse.touch", err, errsz) < 0) { free(path); return -1; }
    free(path);
    {
        if (r.is_root) snprintf(err, errsz, "is a directory");
        else if ((fd = openat(r.dirfd, r.leaf, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0640)) < 0) fse_errno("open", err, errsz);
        else {
            if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) snprintf(err, errsz, "not a regular file");
            else if (futimens(fd, NULL) < 0) fse_errno("utimens", err, errsz);
            else { sb_puts(out, "{\"path\":"); sb_json_str(out, r.canon); sb_printf(out, ",\"size\":%lld}", (long long)st.st_size); rc = 0; }
            close(fd);
        }
    }
    fse_close(&r);
    return rc;
}

static int rpc_fse_mkdir(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), *permv = json_str_dup(params, "perm");
    fse_ref_t r;
    mode_t perm = parse_perm(permv, 0750);
    int rc = -1;
    free(permv);
    if (!path) RPC_ERR("path required");
    if (perm == (mode_t)-1) { free(path); RPC_ERR("perm must be octal like 0750"); }
    if (fse_resolve(path, &r, json_true(params, "parents"), rq, SPCAP_FSW, "fse.mkdir", err, errsz) < 0) { free(path); return -1; }
    free(path);
    {
        if (r.is_root) snprintf(err, errsz, "already exists");
        else if (mkdirat(r.dirfd, r.leaf, perm) < 0 && !(errno == EEXIST && json_true(params, "parents"))) fse_errno("mkdir", err, errsz);
        else { sb_puts(out, "{\"path\":"); sb_json_str(out, r.canon); sb_putn(out, "}", 1); rc = 0; }
    }
    fse_close(&r);
    return rc;
}

static int rpc_fse_rm(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), canon[FSE_MAXPATH + 2];
    int rc;
    if (!path) RPC_ERR("path required");
    rc = fse_rm_core(path, json_true(params, "recursive"), rq, canon, sizeof(canon), err, errsz);
    free(path);
    if (rc == 0) { sb_puts(out, "{\"removed\":"); sb_json_str(out, canon); sb_putn(out, "}", 1); }
    return rc;
}

static int fse_rename_noreplace(int ofd, const char *o, int nfd, const char *n, int overwrite) {
    if (overwrite) return renameat(ofd, o, nfd, n);
#ifdef SYS_renameat2
    {
        long rc = syscall(SYS_renameat2, ofd, o, nfd, n, 1u /* RENAME_NOREPLACE */);
        if (rc == 0 || (errno != ENOSYS && errno != EINVAL)) return (int)rc;
    }
#endif
    {
        struct stat st;
        if (fstatat(nfd, n, &st, AT_SYMLINK_NOFOLLOW) == 0) { errno = EEXIST; return -1; }
        return renameat(ofd, o, nfd, n);
    }
}

static int rpc_fse_mv(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *from = json_str_dup(params, "from"), *to = json_str_dup(params, "to");
    fse_ref_t a, b;
    int rc = -1;
    a.dirfd = b.dirfd = -1;
    if (!from || !to) { free(from); free(to); RPC_ERR("from and to required"); }
    if (fse_resolve(from, &a, 0, rq, SPCAP_FSW, "fse.mv", err, errsz) < 0) goto done;
    if (fse_resolve(to, &b, json_true(params, "parents"), rq, SPCAP_FSW, "fse.mv", err, errsz) < 0) { fse_close(&a); goto done; }
    if (a.is_root || b.is_root) { snprintf(err, errsz, "the root cannot be moved or replaced"); goto fin; }
    if (strncmp(b.canon, a.canon, strlen(a.canon)) == 0 && (b.canon[strlen(a.canon)] == '/')) { snprintf(err, errsz, "cannot move a directory into itself"); goto fin; }
    if (fse_rename_noreplace(a.dirfd, a.leaf, b.dirfd, b.leaf, json_true(params, "overwrite")) < 0) { fse_errno("rename", err, errsz); goto fin; }
    sb_puts(out, "{\"from\":"); sb_json_str(out, a.canon); sb_puts(out, ",\"to\":"); sb_json_str(out, b.canon); sb_putn(out, "}", 1);
    rc = 0;
fin:
    fse_close(&a); fse_close(&b);
done:
    free(from); free(to);
    return rc;
}

static int rpc_fse_cp(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *from = json_str_dup(params, "from"), *to = json_str_dup(params, "to"), buf[65536];
    fse_ref_t a, b;
    int sfd = -1, dfd = -1, rc = -1;
    struct stat st;
    uint64_t total = 0;
    a.dirfd = b.dirfd = -1;
    if (!from || !to) { free(from); free(to); RPC_ERR("from and to required"); }
    if (fse_resolve(from, &a, 0, rq, SPCAP_FSR, "fse.read", err, errsz) < 0) goto done;
    if (fse_resolve(to, &b, json_true(params, "parents"), rq, SPCAP_FSW, "fse.cp", err, errsz) < 0) { fse_close(&a); goto done; }
    if (a.is_root || b.is_root) { snprintf(err, errsz, "is a directory"); goto fin; }
    sfd = openat(a.dirfd, a.leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (sfd < 0) { fse_errno("open source", err, errsz); goto fin; }
    if (fstat(sfd, &st) < 0 || !S_ISREG(st.st_mode)) { snprintf(err, errsz, "source is not a regular file"); goto fin; }
    if ((uint64_t)st.st_size > g_fse.max_file) { snprintf(err, errsz, "source exceeds the file size limit"); goto fin; }
    dfd = openat(b.dirfd, b.leaf, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (json_true(params, "overwrite") ? O_TRUNC : O_EXCL), st.st_mode & 0777);
    if (dfd < 0) { fse_errno("open destination", err, errsz); goto fin; }
    for (;;) {
        ssize_t n = read(sfd, buf, sizeof(buf)), off = 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { fse_errno("read", err, errsz); goto fin; }
        if (n == 0) break;
        while (off < n) {
            ssize_t w = write(dfd, buf + off, (size_t)(n - off));
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { fse_errno("write", err, errsz); goto fin; }
            off += w;
        }
        total += (uint64_t)n;
        if (total > g_fse.max_file) { snprintf(err, errsz, "copy exceeds the file size limit"); goto fin; }
    }
    sb_puts(out, "{\"from\":"); sb_json_str(out, a.canon); sb_puts(out, ",\"to\":"); sb_json_str(out, b.canon);
    sb_printf(out, ",\"bytes\":%" PRIu64 "}", total);
    g_fse.bytes_written += total;
    rc = 0;
fin:
    if (sfd >= 0) close(sfd);
    if (dfd >= 0) close(dfd);
    fse_close(&a); fse_close(&b);
done:
    free(from); free(to);
    return rc;
}

static int rpc_fse_chmod(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), *mv = json_str_dup(params, "mode");
    fse_ref_t r;
    mode_t m = parse_perm(mv, (mode_t)-1);
    int rc = -1, fd;
    free(mv);
    if (!path) RPC_ERR("path required");
    if (m == (mode_t)-1) { free(path); RPC_ERR("mode must be octal 0000-0777 (no setuid/setgid/sticky)"); }
    if (fse_resolve(path, &r, 0, rq, SPCAP_FSW, "fse.chmod", err, errsz) < 0) { free(path); return -1; }
    free(path);
    {
        if (r.is_root) fd = openat(g_fse.root_fd, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
        else fd = openat(r.dirfd, r.leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) fse_errno("open", err, errsz);
        else {
            struct stat st;
            char proc[40];
            snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
            if (fstat(fd, &st) == 0 && S_ISLNK(st.st_mode)) snprintf(err, errsz, "symlink refused");
            else if (chmod(proc, m) < 0) fse_errno("chmod", err, errsz);
            else { sb_puts(out, "{\"path\":"); sb_json_str(out, r.canon); sb_printf(out, ",\"mode\":\"%04o\"}", (unsigned)m); rc = 0; }
            close(fd);
        }
    }
    fse_close(&r);
    return rc;
}

static int rpc_fse_hash(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), canon[FSE_MAXPATH + 2], hx[65];
    struct stat st;
    int fd;
    sha_ctx c;
    uint8_t buf[65536];
    uint64_t total = 0;
    if (!path) RPC_ERR("path required");
    fd = fse_open_read(path, &st, canon, sizeof(canon), rq, err, errsz);
    free(path);
    if (fd < 0) return -1;
    sha_init(&c);
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { fse_errno("read", err, errsz); close(fd); return -1; }
        if (n == 0) break;
        sha_update(&c, buf, (size_t)n);
        total += (uint64_t)n;
        if (total > g_fse.max_file) { close(fd); RPC_ERR("file exceeds the size limit"); }
    }
    close(fd);
    sha_final_hex(&c, hx);
    sb_puts(out, "{\"path\":"); sb_json_str(out, canon);
    sb_printf(out, ",\"sha256\":\"%s\",\"size\":%" PRIu64 "}", hx, total);
    return 0;
}

/* ── fse.exec ──────────────────────────────────────────────────────────────── */
#define EXEC_MAX_ARGS 32
#define EXEC_OUT_MAX  32000

/* parses ["a","b"] into malloc'd strings; returns count or -1 */
static int json_str_array(const char *params, const char *key, char **vec, int max) {
    const char *p = json_find(params, key);
    int n = 0;
    if (!p) return 0;
    if (*p != '[') return -1;
    p = json_skip_ws(p + 1);
    while (*p && *p != ']') {
        char tmp[1100];
        size_t l = 0;
        if (*p != '"' || n >= max) return -1;
        p++;
        while (*p && *p != '"') {
            char ch = *p++;
            if (ch == '\\') {
                char e = *p++;
                if (e == 'n') ch = '\n'; else if (e == 't') ch = '\t'; else if (e == 'r') ch = '\r';
                else if (e == '"' || e == '\\' || e == '/') ch = e;
                else if (e == 'u') { p += 4; ch = '?'; }
                else return -1;
            }
            if (l + 1 >= sizeof(tmp)) return -1;
            tmp[l++] = ch;
        }
        if (*p != '"') return -1;
        p++;
        tmp[l] = '\0';
        vec[n] = strdup(tmp);
        if (!vec[n]) return -1;
        n++;
        p = json_skip_ws(p);
        if (*p == ',') p = json_skip_ws(p + 1);
    }
    return *p == ']' ? n : -1;
}

typedef struct {
    sp_caller_t caller;
    uint64_t    id;
    int         has_id;
    int         exec_fd, timeout_ms, argc;
    char        canon[FSE_MAXPATH + 2];
    char       *argv[EXEC_MAX_ARGS + 2];
    uint64_t    t0_us;
} exec_job_t;

static void exec_job_free(exec_job_t *j) {
    int i;
    for (i = 0; i < j->argc; i++) free(j->argv[i]);
    if (j->exec_fd >= 0) close(j->exec_fd);
    free(j);
}

static int exec_run(exec_job_t *j, sb_t *out, char *err, size_t errsz) {
    int pfd[2], status = 0, timed_out = 0, truncated = 0;
    pid_t pid;
    char obuf[EXEC_OUT_MAX + 1], *envp[] = { (char *)"PATH=/usr/bin:/bin", (char *)"HOME=/", (char *)"LANG=C", NULL };
    size_t olen = 0, i;
    uint64_t deadline = sp_now_ms() + (uint64_t)j->timeout_ms;
    if (pipe2(pfd, O_CLOEXEC) < 0) RPC_ERR("pipe: %s", strerror(errno));
    fflush(NULL);
    pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); RPC_ERR("fork: %s", strerror(errno)); }
    if (pid == 0) {                                   /* child: async-signal-safe calls only */
        struct rlimit rl;
        int xfd = j->exec_fd, nul;
        setsid();
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        if (fchdir(g_fse.root_fd) < 0) _exit(126);
        if (xfd < 10) { int nx = fcntl(xfd, F_DUPFD, 10); if (nx >= 0) xfd = nx; }
        if (xfd > 3) syscall(SYS_close_range, 3, xfd - 1, 0);
        syscall(SYS_close_range, xfd + 1, ~0U, 0);
        { int fl = fcntl(xfd, F_GETFD); if (fl >= 0) fcntl(xfd, F_SETFD, fl & ~FD_CLOEXEC); }
        rl.rlim_cur = rl.rlim_max = (rlim_t)((j->timeout_ms / 1000) + 2); setrlimit(RLIMIT_CPU, &rl);
        rl.rlim_cur = rl.rlim_max = (rlim_t)1 << 30; setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = (rlim_t)64 << 20; setrlimit(RLIMIT_FSIZE, &rl);
        rl.rlim_cur = rl.rlim_max = 64; setrlimit(RLIMIT_NOFILE, &rl);
        rl.rlim_cur = rl.rlim_max = 0; setrlimit(RLIMIT_CORE, &rl);
        fexecve(xfd, j->argv, envp);
        _exit(127);
    }
    close(pfd[1]);
    for (;;) {
        struct pollfd pf;
        uint64_t now = sp_now_ms();
        int pr;
        if (now >= deadline) { timed_out = 1; kill(-pid, SIGKILL); break; }
        pf.fd = pfd[0]; pf.events = POLLIN;
        pr = poll(&pf, 1, (int)(deadline - now > 200 ? 200 : deadline - now));
        if (pr < 0 && errno == EINTR) continue;
        if (pr > 0) {
            char tmp[4096];
            ssize_t n = read(pfd[0], tmp, sizeof(tmp));
            if (n <= 0) break;
            if (olen < EXEC_OUT_MAX) {
                size_t take = (size_t)n;
                if (olen + take > EXEC_OUT_MAX) { take = EXEC_OUT_MAX - olen; truncated = 1; }
                memcpy(obuf + olen, tmp, take);
                olen += take;
            } else truncated = 1;
        }
    }
    close(pfd[0]);
    kill(-pid, SIGKILL);                              /* nothing may outlive the call */
    waitpid(pid, &status, 0);
    for (i = 0; i < olen; i++) {                      /* printable ASCII, \n and \t only */
        unsigned char c = (unsigned char)obuf[i];
        if (!(c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f))) obuf[i] = '?';
    }
    obuf[olen] = '\0';
    sb_puts(out, "{\"path\":"); sb_json_str(out, j->canon);
    if (WIFEXITED(status)) sb_printf(out, ",\"exit\":%d,\"signal\":0", WEXITSTATUS(status));
    else sb_printf(out, ",\"exit\":-1,\"signal\":%d", WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    sb_printf(out, ",\"timed_out\":%s,\"truncated\":%s,\"output\":", timed_out ? "true" : "false", truncated ? "true" : "false");
    sb_json_str(out, obuf);
    sb_putn(out, "}", 1);
    return 0;
}

static void rpc_run_logged_done(const rpc_req_t *rq, const char *method, const char *params, int rc, const char *err);
static void rpc_reply(const sp_caller_t *c, int has_id, uint64_t id, int ok, const char *body);

static void *exec_thread(void *arg) {
    exec_job_t *j = (exec_job_t *)arg;
    sb_t out;
    char err[200] = "";
    rpc_req_t rq;
    int rc;
    sb_init(&out);
    rc = exec_run(j, &out, err, sizeof(err));
    if (rc == 0 && out.err) { rc = -1; snprintf(err, sizeof(err), "out of memory"); }
    if (j->has_id) rpc_reply(&j->caller, 1, j->id, rc == 0, rc == 0 ? out.p : err);
    memset(&rq, 0, sizeof(rq));
    rq.caller = j->caller; rq.t0_us = j->t0_us;
    snprintf(rq.mname, sizeof(rq.mname), "fse.exec");
    rpc_run_logged_done(&rq, "fse.exec", j->canon, rc, rc == 0 ? NULL : err);
    __atomic_fetch_sub(&g_fse.execs, 1, __ATOMIC_RELAXED);
    sb_free(&out);
    exec_job_free(j);
    return NULL;
}

static int rpc_fse_exec(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path"), *args[EXEC_MAX_ARGS];
    fse_ref_t r;
    struct stat st;
    exec_job_t *j;
    int64_t tmo = 10000;
    int na, i, fd;
    if (!g_fse.exec_enabled) { free(path); RPC_ERR("exec is disabled (start with --fse-exec)"); }
    if (!path) RPC_ERR("path required");
    json_get_i64(params, "timeout_ms", &tmo);
    if (tmo < 100) tmo = 100;
    if (tmo > 60000) tmo = 60000;
    memset(args, 0, sizeof(args));
    na = json_str_array(params, "args", args, EXEC_MAX_ARGS);
    if (na < 0) { free(path); for (i = 0; i < EXEC_MAX_ARGS; i++) free(args[i]); RPC_ERR("args must be an array of at most %d short strings", EXEC_MAX_ARGS); }
    if (fse_resolve(path, &r, 0, rq, SPCAP_EXEC | SPCAP_FSR, "fse.exec", err, errsz) < 0) goto fail;
    if (r.is_root) { fse_close(&r); snprintf(err, errsz, "is a directory"); goto fail; }
    fd = openat(r.dirfd, r.leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { fse_errno("open", err, errsz); fse_close(&r); goto fail; }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) { close(fd); snprintf(err, errsz, "not an executable regular file"); fse_close(&r); goto fail; }
    j = (exec_job_t *)calloc(1, sizeof(*j));
    if (!j) { close(fd); fse_close(&r); snprintf(err, errsz, "out of memory"); goto fail; }
    j->exec_fd = fd; j->timeout_ms = (int)tmo; j->caller = rq->caller; j->id = rq->id; j->has_id = rq->has_id; j->t0_us = rq->t0_us;
    snprintf(j->canon, sizeof(j->canon), "%s", r.canon);
    fse_close(&r);
    j->argv[0] = strdup(j->canon);
    for (i = 0; i < na; i++) j->argv[i + 1] = args[i];
    j->argv[na + 1] = NULL;
    j->argc = na + 1;
    free(path);
    if (__atomic_fetch_add(&g_fse.execs, 1, __ATOMIC_RELAXED) >= 8) {
        __atomic_fetch_sub(&g_fse.execs, 1, __ATOMIC_RELAXED);
        exec_job_free(j);
        RPC_ERR("too many concurrent executions (max 8)");
    }
    SP_INC(g_fse.exec_total);
    if (rq->caller.kind == CALLER_PEER) {              /* never block the IO thread */
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 256 * 1024);
        if (pthread_create(&t, &at, exec_thread, j) != 0) {
            pthread_attr_destroy(&at);
            __atomic_fetch_sub(&g_fse.execs, 1, __ATOMIC_RELAXED);
            exec_job_free(j);
            RPC_ERR("cannot start the execution thread");
        }
        pthread_attr_destroy(&at);
        return 1;                                      /* the thread sends the reply and writes the log entry */
    }
    {
        int rc = exec_run(j, out, err, errsz);
        __atomic_fetch_sub(&g_fse.execs, 1, __ATOMIC_RELAXED);
        exec_job_free(j);
        return rc;
    }
fail:
    free(path);
    for (i = 0; i < EXEC_MAX_ARGS; i++) free(args[i]);
    return -1;
}


/* ════════════════════════════════════════════════════════════════════════════
 * SPPServer — shared state (routes, limits, counters). The HTTP engine is further down.
 * ════════════════════════════════════════════════════════════════════════════ */
enum { RT_TEXT = 0, RT_JSON = 1, RT_FILE = 2, RT_RPC = 3 };
#define HTTP_MAX_ROUTES 64

typedef struct {
    int      used;
    uint32_t id;
    char     method[8], pattern[128], target[512], ctype[64];
    int      type, status, is_public;
} route_t;

static struct {
    int      enabled, port, rate, max_conns, per_ip;
    char     bind[64];
    uint64_t max_body;
    char     cors[8][200];
    int      ncors;
    volatile int conns;
    int      listen_fd;
    pthread_t thread;
    pthread_mutex_t lock;
    route_t  routes[HTTP_MAX_ROUTES];
    uint32_t next_route;
    uint64_t req_total, rate_limited, unauthorized, st2xx, st3xx, st4xx, st5xx, bytes_out;
} g_http = { 1, 5223, 50, 256, 32, "127.0.0.1", 8u << 20, {{0}}, 0, 0, -1, 0, PTHREAD_MUTEX_INITIALIZER, {{0}}, 1, 0, 0, 0, 0, 0, 0, 0, 0 };

static struct { uint64_t rpc_total, rpc_denied, rpc_errors, auth_fail; } g_stat;

static int route_pattern_ok(const char *p) {
    size_t i, n = strlen(p);
    if (n < 1 || n >= 128 || p[0] != '/') return 0;
    for (i = 0; i < n; i++) if ((unsigned char)p[i] <= 0x20 || p[i] == '?' || p[i] == '#' || p[i] == '%' || p[i] == 0x7f) return 0;
    if (strstr(p, "..")) return 0;
    return 1;
}

static int route_reserved(const char *p) {
    static const char *rs[] = { "/rpc", "/files", "/health", "/metrics" };
    size_t i;
    for (i = 0; i < sizeof(rs) / sizeof(rs[0]); i++) {
        size_t l = strlen(rs[i]);
        if (strncmp(p, rs[i], l) == 0 && (p[l] == '\0' || p[l] == '/')) return 1;
    }
    return 0;
}

/* pattern /a/:id/b matches /a/7/b ; a trailing /star matches any rest of the path */
static int route_path_match(const char *pat, const char *path) {
    while (*pat && *path) {
        if (pat[0] == '*' && pat[1] == '\0') return 1;
        if (pat[0] == ':') {
            while (*pat && *pat != '/') pat++;
            if (!*path || *path == '/') return 0;
            while (*path && *path != '/') path++;
            continue;
        }
        if (*pat != *path) return 0;
        pat++; path++;
    }
    if (pat[0] == '*' && pat[1] == '\0') return 1;
    if (pat[0] == '/' && pat[1] == '*' && pat[2] == '\0' && !*path) return 1;
    return *pat == '\0' && *path == '\0';
}

static const route_t *route_find(const char *method, const char *path, route_t *copy) {
    int i;
    pthread_mutex_lock(&g_http.lock);
    for (i = 0; i < HTTP_MAX_ROUTES; i++) {
        const route_t *r = &g_http.routes[i];
        if (!r->used) continue;
        if (strcmp(r->method, "ANY") && strcmp(r->method, method)) continue;
        if (route_path_match(r->pattern, path)) { *copy = *r; pthread_mutex_unlock(&g_http.lock); return copy; }
    }
    pthread_mutex_unlock(&g_http.lock);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════════
 * RPC: replies, method table, dispatcher
 * ════════════════════════════════════════════════════════════════════════════ */
typedef int (*rpc_fn)(const rpc_req_t *, const char *, sb_t *, char *, size_t);
typedef struct { const char *name; rpc_fn fn; uint8_t need; uint8_t terminal_only; uint8_t self_gated; } rpc_method_t;

static void rpc_reply(const sp_caller_t *c, int has_id, uint64_t id, int ok, const char *body) {
    sb_t r;
    sb_init(&r);
    sb_putn(&r, "{", 1);
    if (has_id) sb_printf(&r, "\"id\":%" PRIu64 ",", id); else sb_puts(&r, "\"id\":null,");
    if (ok) { sb_puts(&r, "\"ok\":true,\"result\":"); sb_puts(&r, body ? body : "null"); }
    else    { sb_puts(&r, "\"ok\":false,\"error\":");  sb_json_str(&r, body ? body : "error"); }
    sb_putn(&r, "}", 1);
    if (r.err) { sb_free(&r); return; }
    if (r.len > SPP_MAX_PAYLOAD) {
        sb_free(&r);
        rpc_reply(c, has_id, id, 0, "response too large for one SPP frame");
        return;
    }
    if (c->kind == CALLER_PEER) {
        peer_ref_t ref = c->ref;
        spp_peer_send(ref, SPP_RPC_RESULT, (const uint8_t *)r.p, (uint32_t)r.len);
    }
    sb_free(&r);
}

static void spp_peer_error(peer_ref_t r, const char *msg) {
    sb_t b;
    sb_init(&b);
    sb_puts(&b, "{\"error\":");
    sb_json_str(&b, msg);
    sb_putn(&b, "}", 1);
    if (!b.err) spp_peer_send(r, SPP_ERROR, (const uint8_t *)b.p, (uint32_t)b.len);
    sb_free(&b);
}

static void caller_from_peer(peer_ref_t ref, sp_caller_t *c) {
    spp_peer_t *p;
    memset(c, 0, sizeof(*c));
    c->kind = CALLER_PEER;
    c->ref = ref;
    pthread_mutex_lock(&g_sp.peers_lock);
    p = peer_by_ref(ref);
    if (p) {
        c->caps = sp_caps_get(p);
        c->conn = p->conn_id;
        c->ip = p->addr;
        snprintf(c->name, sizeof(c->name), "%s", p->principal);
        snprintf(c->role, sizeof(c->role), "%s", p->role);
        snprintf(c->mention, sizeof(c->mention), "%s", p->spmention);
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
}

/* ── identity ──────────────────────────────────────────────────────────────── */
static int rpc_identity(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    size_t ready;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_sp.peers_lock);
    ready = g_sp.ready_count;
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_puts(out, "{\"product\":\"LocalEnterprise\",\"version\":\"" LE_VERSION "\",\"spmention\":");
    sb_json_str(out, g_sp.spmention);
    sb_printf(out, ",\"spp\":\"%d.%d\",\"port\":%d,\"http_port\":%d,\"max_peers\":%zu,\"peers\":%zu,\"fse\":%s,\"exec\":%s}",
              SPP_VERSION >> 8, SPP_VERSION & 0xFF, g_sp.port, g_http.enabled ? g_http.port : 0, g_sp.max_peers, ready,
              g_fse.ready ? "true" : "false", g_fse.exec_enabled ? "true" : "false");
    return 0;
}

/* ── auth ──────────────────────────────────────────────────────────────────── */
static int rpc_auth_login(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *tok = json_str_dup(params, "token"), name[40], role[24];
    uint8_t caps = 0;
    uint32_t id;
    spp_peer_t *p;
    ev_t e;
    if (rq->caller.kind != CALLER_PEER) { free(tok); RPC_ERR("auth.login is for SPP connections (HTTP uses a Bearer header)"); }
    if (!tok) RPC_ERR("token required");
    id = tok_lookup(tok, &caps, name, sizeof(name), role, sizeof(role));
    free(tok);
    pthread_mutex_lock(&g_sp.peers_lock);
    p = peer_by_ref(rq->caller.ref);
    if (!p) { pthread_mutex_unlock(&g_sp.peers_lock); RPC_ERR("peer gone"); }
    if (!id) {
        int drop = ++p->auth_fail >= 5;
        if (drop) peer_drop_locked(rq->caller.ref.slot);
        pthread_mutex_unlock(&g_sp.peers_lock);
        SP_INC(g_stat.auth_fail);
        ev_begin(&e, "auth.fail"); ev_caller(&e, &rq->caller); ev_b(&e, "dropped", drop); le_emit(&e);
        RPC_ERR("invalid or expired token");
    }
    __atomic_store_n(&p->sp_caps, (uint8_t)(g_sp.default_caps | caps), __ATOMIC_RELAXED);
    p->tok_id = id;
    snprintf(p->principal, sizeof(p->principal), "%s", name);
    snprintf(p->role, sizeof(p->role), "%s", role);
    p->auth_fail = 0;
    caps = sp_caps_get(p);
    pthread_mutex_unlock(&g_sp.peers_lock);
    ev_begin(&e, "auth.ok"); ev_caller(&e, &rq->caller); ev_s(&e, "token", name); ev_u(&e, "caps", caps); le_emit(&e);
    sb_puts(out, "{\"name\":"); sb_json_str(out, name);
    sb_puts(out, ",\"role\":"); sb_json_str(out, role);
    sb_putn(out, ",", 1); sb_caps(out, caps); sb_putn(out, "}", 1);
    return 0;
}

static int rpc_auth_logout(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    spp_peer_t *p;
    ev_t e;
    (void)params;
    if (rq->caller.kind != CALLER_PEER) RPC_ERR("auth.logout is for SPP connections");
    pthread_mutex_lock(&g_sp.peers_lock);
    p = peer_by_ref(rq->caller.ref);
    if (p) {
        __atomic_store_n(&p->sp_caps, g_sp.default_caps, __ATOMIC_RELAXED);
        p->tok_id = 0; p->principal[0] = '\0'; p->role[0] = '\0';
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
    ev_begin(&e, "auth.logout"); ev_caller(&e, &rq->caller); le_emit(&e);
    sb_puts(out, "{\"ok\":true}");
    return 0;
}

static int rpc_auth_whoami(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)params; (void)err; (void)errsz;
    sb_printf(out, "{\"kind\":\"%s\",\"conn\":%" PRIu64 ",\"name\":", caller_kind_name(rq->caller.kind), rq->caller.conn);
    sb_json_str(out, rq->caller.name);
    sb_puts(out, ",\"role\":"); sb_json_str(out, rq->caller.role);
    sb_putn(out, ",", 1); sb_caps(out, rq->caller.caps); sb_putn(out, "}", 1);
    return 0;
}

/* ── peers ─────────────────────────────────────────────────────────────────── */
static int rpc_peer_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t cursor = 0, limit = 100, next = -1;
    size_t i;
    int first = 1;
    (void)rq; (void)err; (void)errsz;
    json_get_i64(params, "cursor", &cursor);
    json_get_i64(params, "limit", &limit);
    if (cursor < 0) cursor = 0;
    if (limit < 1) limit = 1;
    if (limit > 200) limit = 200;
    sb_puts(out, "{\"peers\":[");
    pthread_mutex_lock(&g_sp.peers_lock);
    for (i = (size_t)cursor; i < g_sp.peer_hi; i++) {
        spp_peer_t *p = &g_sp.peers[i];
        char ip[INET_ADDRSTRLEN];
        struct in_addr a;
        if (!p->active && !p->hs) continue;
        if (limit-- == 0 || out->len > SPP_MAX_PAYLOAD - 1024) { next = (int64_t)i; break; }
        a.s_addr = p->addr;
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        sb_printf(out, "%s{\"conn\":%" PRIu64 ",\"slot\":%zu,\"state\":\"%s\",\"ip\":\"%s\",\"spmention\":",
                  first ? "" : ",", p->conn_id, i, p->active ? "ready" : "handshake", ip);
        sb_json_str(out, p->spmention);
        sb_puts(out, ",\"principal\":"); sb_json_str(out, p->principal);
        sb_puts(out, ",\"role\":"); sb_json_str(out, p->role);
        sb_putn(out, ",", 1);
        sb_caps(out, sp_caps_get(p));
        sb_printf(out, ",\"rtt_ms\":%u,\"age_ms\":%" PRIu64 "}", p->rtt_ms, sp_now_ms() - p->connected_ms);
        first = 0;
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_printf(out, "],\"next\":%" PRId64 "}", next);
    return 0;
}

static int rpc_peer_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    size_t ready, total, hi;
    uint64_t rxb;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_sp.peers_lock);
    ready = g_sp.ready_count; total = g_sp.peer_count; hi = g_sp.peer_hi; rxb = g_sp.rx_buffered;
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_printf(out, "{\"ready\":%zu,\"handshaking\":%zu,\"max\":%zu,\"highest_slot\":%zu,\"rx_buffered\":%" PRIu64 "}",
              ready, total - ready, g_sp.max_peers, hi, rxb);
    return 0;
}

static int rpc_peer_kick(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t conn;
    int slot;
    (void)rq;
    if (json_get_i64(params, "conn", &conn) < 0 || conn <= 0) RPC_ERR("conn required");
    pthread_mutex_lock(&g_sp.peers_lock);
    slot = peer_find_conn_locked((uint64_t)conn);
    if (slot >= 0) peer_drop_locked((uint32_t)slot);
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (slot < 0) RPC_ERR("no such peer");
    sb_puts(out, "{\"kicked\":true}");
    return 0;
}

/* ── capabilities (policy.get / check / grant / revoke) ────────────────────── */
/* {"conn":N} (needs the policy cap unless it is the caller itself) or the caller's own connection.
 * Caller holds g_sp.peers_lock. */
static int caps_ptr_locked(const rpc_req_t *rq, const char *params, uint8_t **pp, char *err, size_t errsz) {
    int64_t conn;
    if (json_get_i64(params, "conn", &conn) == 0) {
        int slot = peer_find_conn_locked((uint64_t)conn);
        if (slot < 0) RPC_ERR("no such peer");
        if ((uint64_t)conn != rq->caller.conn && rq->caller.kind != CALLER_TERMINAL && !(rq->caller.caps & SPCAP_POLICY))
            RPC_ERR("denied: needs cap policy to look at other connections");
        *pp = &g_sp.peers[slot].sp_caps;
        return 0;
    }
    if (rq->caller.kind == CALLER_PEER) {
        spp_peer_t *p = peer_by_ref(rq->caller.ref);
        if (!p) RPC_ERR("peer gone");
        *pp = &p->sp_caps;
        return 0;
    }
    RPC_ERR("conn required");
}

static int rpc_policy_get(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    uint8_t *cp, caps;
    int rc;
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    caps = rc == 0 ? __atomic_load_n(cp, __ATOMIC_RELAXED) : 0;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0) {
        if (rq->caller.kind == CALLER_HTTP) { sb_putn(out, "{", 1); sb_caps(out, rq->caller.caps); sb_putn(out, "}", 1); return 0; }
        return -1;
    }
    sb_putn(out, "{", 1); sb_caps(out, caps); sb_putn(out, "}", 1);
    return 0;
}

static int rpc_policy_check(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    uint8_t *cp, caps, mask;
    int rc;
    if (parse_caps(params, &mask) < 0) RPC_ERR("caps required (number, \"fsr,fsw\" ...)");
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    caps = rc == 0 ? __atomic_load_n(cp, __ATOMIC_RELAXED) : rq->caller.caps;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0 && rq->caller.kind != CALLER_HTTP) return -1;
    sb_printf(out, "{\"has\":%s}", (caps & mask) == mask ? "true" : "false");
    return 0;
}

static int rpc_policy_change(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz, int grant) {
    uint8_t *cp, mask, now;
    int rc;
    ev_t e;
    if (parse_caps(params, &mask) < 0) RPC_ERR("caps required (number, \"fsr,fsw\" ...)");
    if (mask & ~rq->caller.caps) RPC_ERR("cannot %s capabilities you do not hold", grant ? "grant" : "revoke");
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    if (rc == 0) {
        if (grant) __atomic_fetch_or(cp, mask, __ATOMIC_RELAXED);
        else       __atomic_fetch_and(cp, (uint8_t)~mask, __ATOMIC_RELAXED);
        now = __atomic_load_n(cp, __ATOMIC_RELAXED);
    } else now = 0;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0) return -1;
    ev_begin(&e, grant ? "caps.grant" : "caps.revoke"); ev_caller(&e, &rq->caller); ev_u(&e, "mask", mask); ev_u(&e, "now", now); le_emit(&e);
    sb_putn(out, "{", 1); sb_caps(out, now); sb_putn(out, "}", 1);
    return 0;
}
static int rpc_policy_grant(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) { return rpc_policy_change(rq, params, out, err, errsz, 1); }
static int rpc_policy_revoke(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) { return rpc_policy_change(rq, params, out, err, errsz, 0); }

/* ── SPPPolicyE rules ──────────────────────────────────────────────────────── */
static void pol_rule_json(sb_t *out, const pol_rule_t *r) {
    char dys[32];
    days_str(r->days, dys, sizeof(dys));
    sb_printf(out, "{\"id\":%u,\"effect\":\"%s\",\"who\":", r->id, r->allow ? "allow" : "deny");
    sb_json_str(out, r->who);
    sb_puts(out, ",\"action\":"); sb_json_str(out, r->action);
    sb_puts(out, ",\"resource\":"); sb_json_str(out, r->resource);
    if (r->hs < 0) sb_puts(out, ",\"hours\":\"any\"");
    else sb_printf(out, ",\"hours\":\"%02d:%02d-%02d:%02d\"", r->hs / 60, r->hs % 60, r->he / 60, r->he % 60);
    sb_printf(out, ",\"days\":\"%s\",\"note\":", dys);
    sb_json_str(out, r->note);
    sb_putn(out, "}", 1);
}

static int rpc_rule_add(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *eff = json_str_dup(params, "effect"), *who = json_str_dup(params, "who"), *act = json_str_dup(params, "action");
    char *res = json_str_dup(params, "resource"), *hrs = json_str_dup(params, "hours"), *dys = json_str_dup(params, "days"), *note = json_str_dup(params, "note");
    uint32_t id = 0;
    int rc = -1;
    ev_t e;
    if (!eff || (strcmp(eff, "allow") && strcmp(eff, "deny"))) { snprintf(err, errsz, "effect must be allow or deny"); goto done; }
    if (!act) { snprintf(err, errsz, "action required"); goto done; }
    id = pol_add(strcmp(eff, "allow") == 0, who ? who : "*", act, res ? res : "**", hrs ? hrs : "", dys ? dys : "", note ? note : "", err, errsz);
    if (!id) goto done;
    ev_begin(&e, "policy.change"); ev_caller(&e, &rq->caller); ev_s(&e, "op", "rule.add"); ev_u(&e, "rule", id);
    ev_s(&e, "effect", eff); ev_s(&e, "who", who ? who : "*"); ev_s(&e, "action", act); ev_s(&e, "resource", res ? res : "**");
    le_emit(&e);
    sb_printf(out, "{\"id\":%u}", id);
    rc = 0;
done:
    free(eff); free(who); free(act); free(res); free(hrs); free(dys); free(note);
    return rc;
}

static int rpc_rule_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_pol.lock);
    sb_printf(out, "{\"default\":\"%s\",\"mode\":\"%s\",\"lockdown\":%s,\"rules\":[", g_pol.def_allow ? "allow" : "deny",
              g_pol.audit_only ? "audit" : "enforce", g_pol.lockdown ? "true" : "false");
    for (i = 0; i < g_pol.n; i++) { if (i) sb_putn(out, ",", 1); pol_rule_json(out, &g_pol.rules[i]); if (out->len > SPP_MAX_PAYLOAD - 1024) break; }
    pthread_mutex_unlock(&g_pol.lock);
    sb_puts(out, "]}");
    return 0;
}

static int rpc_rule_remove(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t id;
    int i, hit = -1;
    ev_t e;
    if (json_get_i64(params, "id", &id) < 0) RPC_ERR("id required");
    pthread_mutex_lock(&g_pol.lock);
    for (i = 0; i < g_pol.n; i++) if (g_pol.rules[i].id == (uint32_t)id) hit = i;
    if (hit >= 0) {
        memmove(&g_pol.rules[hit], &g_pol.rules[hit + 1], (size_t)(g_pol.n - hit - 1) * sizeof(pol_rule_t));
        g_pol.n--;
        pol_save_locked();
    }
    pthread_mutex_unlock(&g_pol.lock);
    if (hit < 0) RPC_ERR("no such rule");
    ev_begin(&e, "policy.change"); ev_caller(&e, &rq->caller); ev_s(&e, "op", "rule.remove"); ev_u(&e, "rule", (uint64_t)id); le_emit(&e);
    sb_puts(out, "{\"removed\":true}");
    return 0;
}

static int rpc_rule_clear(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int n;
    ev_t e;
    (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_pol.lock);
    n = g_pol.n; g_pol.n = 0;
    pol_save_locked();
    pthread_mutex_unlock(&g_pol.lock);
    ev_begin(&e, "policy.change"); ev_caller(&e, &rq->caller); ev_s(&e, "op", "rule.clear"); ev_u(&e, "removed", (uint64_t)n); le_emit(&e);
    sb_printf(out, "{\"removed\":%d}", n);
    return 0;
}

/* what would happen? {"action":..,"resource":..,"kind":..,"name":..,"role":..,"ip":..,"conn":N} (nothing is logged as a decision) */
static int rpc_rule_eval(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    sp_caller_t c;
    char *act = json_str_dup(params, "action"), *res = json_str_dup(params, "resource"), *s;
    int64_t conn;
    int i, allow, rule = 0, hit_a = 0, hit_d = 0;
    const char *why = "";
    (void)rq;
    if (!act) RPC_ERR("action required");
    memset(&c, 0, sizeof(c));
    c.kind = CALLER_PEER;
    if (json_get_i64(params, "conn", &conn) == 0) {
        int slot;
        pthread_mutex_lock(&g_sp.peers_lock);
        slot = peer_find_conn_locked((uint64_t)conn);
        if (slot >= 0) {
            spp_peer_t *p = &g_sp.peers[slot];
            c.conn = p->conn_id; c.ip = p->addr;
            snprintf(c.name, sizeof(c.name), "%s", p->principal); snprintf(c.role, sizeof(c.role), "%s", p->role);
            snprintf(c.mention, sizeof(c.mention), "%s", p->spmention);
        }
        pthread_mutex_unlock(&g_sp.peers_lock);
        if (slot < 0) { free(act); free(res); RPC_ERR("no such peer"); }
    }
    if ((s = json_str_dup(params, "kind"))) { c.kind = strcmp(s, "http") == 0 ? CALLER_HTTP : CALLER_PEER; free(s); }
    if ((s = json_str_dup(params, "name"))) { snprintf(c.name, sizeof(c.name), "%s", s); free(s); }
    if ((s = json_str_dup(params, "role"))) { snprintf(c.role, sizeof(c.role), "%s", s); free(s); }
    if ((s = json_str_dup(params, "mention"))) { snprintf(c.mention, sizeof(c.mention), "%s", s); free(s); }
    if ((s = json_str_dup(params, "ip"))) { struct in_addr a; if (inet_pton(AF_INET, s, &a) == 1) c.ip = a.s_addr; free(s); }
    pthread_mutex_lock(&g_pol.lock);
    if (g_pol.lockdown) { allow = 0; why = "lockdown"; }
    else {
        for (i = 0; i < g_pol.n; i++) {
            const pol_rule_t *r = &g_pol.rules[i];
            if (!who_match(r->who, &c) || !glob_match(r->action, act) || !glob_match(r->resource, res ? res : "*") || !rule_time_ok(r)) continue;
            if (r->allow) { if (!hit_a) { hit_a = 1; if (!hit_d) rule = (int)r->id; } }
            else if (!hit_d) { hit_d = 1; rule = (int)r->id; }
        }
        if (hit_d) { allow = 0; why = "deny rule"; }
        else if (hit_a) { allow = 1; why = "allow rule"; }
        else { allow = g_pol.def_allow; why = allow ? "default allow" : "no matching allow rule"; }
    }
    pthread_mutex_unlock(&g_pol.lock);
    sb_printf(out, "{\"decision\":\"%s\",\"rule\":%d,\"reason\":\"%s\",\"always_allowed\":%s}", allow ? "allow" : "deny", rule, why,
              is_always_allowed(act) ? "true" : "false");
    free(act); free(res);
    return 0;
}

static int rpc_policy_set(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *d = json_str_dup(params, "default"), *m = json_str_dup(params, "mode");
    ev_t e;
    int rc = 0;
    if ((d && strcmp(d, "allow") && strcmp(d, "deny")) || (m && strcmp(m, "enforce") && strcmp(m, "audit"))) {
        free(d); free(m); RPC_ERR("default is allow|deny, mode is enforce|audit");
    }
    pthread_mutex_lock(&g_pol.lock);
    if (d) g_pol.def_allow = strcmp(d, "allow") == 0;
    if (m) g_pol.audit_only = strcmp(m, "audit") == 0;
    if (json_find(params, "lockdown")) g_pol.lockdown = json_true(params, "lockdown");
    sb_printf(out, "{\"default\":\"%s\",\"mode\":\"%s\",\"lockdown\":%s}", g_pol.def_allow ? "allow" : "deny",
              g_pol.audit_only ? "audit" : "enforce", g_pol.lockdown ? "true" : "false");
    ev_begin(&e, "policy.change"); ev_caller(&e, &rq->caller); ev_s(&e, "op", "set");
    ev_s(&e, "default", g_pol.def_allow ? "allow" : "deny"); ev_s(&e, "mode", g_pol.audit_only ? "audit" : "enforce"); ev_b(&e, "lockdown", g_pol.lockdown);
    pthread_mutex_unlock(&g_pol.lock);
    le_emit(&e);
    free(d); free(m);
    return rc;
}

static int rpc_policy_role(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t conn;
    char *role = json_str_dup(params, "role");
    int slot;
    ev_t e;
    if (json_get_i64(params, "conn", &conn) < 0) { free(role); RPC_ERR("conn required"); }
    if (role && *role && !name_ok(role, 24)) { free(role); RPC_ERR("role: 1-23 letters, digits, _ - ."); }
    pthread_mutex_lock(&g_sp.peers_lock);
    slot = peer_find_conn_locked((uint64_t)conn);
    if (slot >= 0) snprintf(g_sp.peers[slot].role, sizeof(g_sp.peers[slot].role), "%s", role ? role : "");
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (slot < 0) { free(role); RPC_ERR("no such peer"); }
    ev_begin(&e, "policy.change"); ev_caller(&e, &rq->caller); ev_s(&e, "op", "role.set"); ev_u(&e, "target_conn", (uint64_t)conn); ev_s(&e, "role", role ? role : "");
    le_emit(&e);
    free(role);
    sb_puts(out, "{\"ok\":true}");
    return 0;
}

static int rpc_policy_stats(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_printf(out, "{\"checks\":%" PRIu64 ",\"denies\":%" PRIu64 ",\"would_deny\":%" PRIu64 ",\"rules\":%d}", SP_LD(g_pol.checks), SP_LD(g_pol.denies), SP_LD(g_pol.would_deny), g_pol.n);
    return 0;
}

/* ── SPPLogE ───────────────────────────────────────────────────────────────── */
static int rpc_log_head(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_log.lock);
    sb_printf(out, "{\"seq\":%" PRIu64 ",\"hash\":\"%s\"}", g_log.seq, g_log.head);
    pthread_mutex_unlock(&g_log.lock);
    return 0;
}

static int rpc_log_stats(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_log.lock);
    sb_printf(out, "{\"entries\":%" PRIu64 ",\"seq\":%" PRIu64 ",\"file_size\":%" PRIu64 ",\"max_size\":%" PRIu64 ",\"rotations\":%" PRIu64 ",\"failed\":%s,\"fail_closed\":%s}",
              g_log.entries, g_log.seq, g_log.size, g_log.max_size, g_log.rotations, g_log.failed ? "true" : "false", g_log.fail_closed ? "true" : "false");
    pthread_mutex_unlock(&g_log.lock);
    return 0;
}

static int rpc_log_tail(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t n = 20;
    int fd, count = 0, i;
    char buf[49152];
    struct stat st;
    ssize_t r;
    off_t from;
    char *lines[200], *p, *end;
    (void)rq;
    json_get_i64(params, "n", &n);
    if (n < 1) n = 1;
    if (n > 200) n = 200;
    fd = open(g_log.path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0) { if (fd >= 0) close(fd); RPC_ERR("cannot read the log"); }
    from = st.st_size > (off_t)sizeof(buf) - 1 ? st.st_size - ((off_t)sizeof(buf) - 1) : 0;
    r = pread(fd, buf, sizeof(buf) - 1, from);
    close(fd);
    if (r <= 0) { sb_puts(out, "{\"lines\":[]}"); return 0; }
    buf[r] = '\0';
    p = buf;
    if (from > 0) { p = strchr(buf, '\n'); p = p ? p + 1 : buf + r; }   /* drop the cut-off first line */
    while (*p) {
        end = strchr(p, '\n');
        if (!end) break;
        *end = '\0';
        if (count < 200) lines[count++] = p; else { memmove(lines, lines + 1, 199 * sizeof(char *)); lines[199] = p; }
        p = end + 1;
    }
    sb_puts(out, "{\"lines\":[");
    {
        int start = count > n ? count - (int)n : 0, first = 1;
        size_t used = 0;
        for (i = count - 1; i >= start; i--) used += strlen(lines[i]) + 1;
        while (used > SPP_MAX_PAYLOAD - 512 && start < count) { used -= strlen(lines[start]) + 1; start++; }
        for (i = start; i < count; i++) { if (!first) sb_putn(out, ",", 1); sb_puts(out, lines[i]); first = 0; }
    }
    sb_puts(out, "]}");
    return 0;
}

static int rpc_log_verify(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *file = json_str_dup(params, "file"), *exp = json_str_dup(params, "expect_head"), path[400], dir[320];
    uint64_t limit = 0;
    char *slash;
    (void)rq;
    snprintf(dir, sizeof(dir), "%s", g_log.path);
    slash = strrchr(dir, '/');
    if (slash) *slash = '\0'; else snprintf(dir, sizeof(dir), ".");
    if (file) {
        if (!name_ok(file, 100)) { free(file); free(exp); RPC_ERR("file must be a plain file name inside the log directory"); }
        snprintf(path, sizeof(path), "%s/%s", dir, file);
    } else {
        snprintf(path, sizeof(path), "%s", g_log.path);
        pthread_mutex_lock(&g_log.lock);
        limit = g_log.size;                             /* only what was complete when we started */
        pthread_mutex_unlock(&g_log.lock);
    }
    if (exp && *exp && !hex64_ok(exp)) { free(file); free(exp); RPC_ERR("expect_head must be 64 hex characters"); }
    le_log_verify(path, exp, limit, out);
    free(file); free(exp);
    return 0;
}

/* ── FSE table lives below; server.* ───────────────────────────────────────── */
static int rpc_server_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    size_t ready;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_sp.peers_lock);
    ready = g_sp.ready_count;
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_printf(out, "{\"uptime_s\":%" PRIu64 ",\"peers\":%zu,\"http\":{\"enabled\":%s,\"port\":%d,\"bind\":\"%s\",\"conns\":%d,\"requests\":%" PRIu64
              ",\"rate_limited\":%" PRIu64 ",\"unauthorized\":%" PRIu64 ",\"rate\":%d,\"max_body\":%" PRIu64 "},\"rpc\":{\"total\":%" PRIu64 ",\"denied\":%" PRIu64
              ",\"errors\":%" PRIu64 "}}",
              (sp_now_ms() - g_sp.start_ms) / 1000, ready, g_http.enabled ? "true" : "false", g_http.port, g_http.bind, g_http.conns, SP_LD(g_http.req_total),
              SP_LD(g_http.rate_limited), SP_LD(g_http.unauthorized), g_http.rate, g_http.max_body, SP_LD(g_stat.rpc_total), SP_LD(g_stat.rpc_denied), SP_LD(g_stat.rpc_errors));
    return 0;
}

static void route_json(sb_t *out, const route_t *r) {
    static const char *tn[] = { "text", "json", "file", "rpc" };
    sb_printf(out, "{\"id\":%u,\"method\":\"%s\",\"pattern\":", r->id, r->method);
    sb_json_str(out, r->pattern);
    sb_printf(out, ",\"type\":\"%s\",\"target\":", tn[r->type]);
    sb_json_str(out, r->target);
    sb_printf(out, ",\"status\":%d,\"public\":%s}", r->status, r->is_public ? "true" : "false");
}

static int rpc_route_add(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *method = json_str_dup(params, "method"), *pattern = json_str_dup(params, "pattern"), *type = json_str_dup(params, "type");
    char *target = json_str_dup(params, "target"), *ctype = json_str_dup(params, "content_type");
    int64_t status = 200;
    int ty = -1, i, slot = -1, rc = -1, pub = json_true(params, "public");
    route_t *r;
    ev_t e;
    static const char *ms[] = { "GET", "POST", "PUT", "DELETE", "ANY" };
    json_get_i64(params, "status", &status);
    if (!method) method = strdup("GET");
    if (!pattern || !type || !target) { snprintf(err, errsz, "pattern, type and target required"); goto done; }
    for (i = 0; i < 5; i++) if (strcmp(method, ms[i]) == 0) break;
    if (i == 5) { snprintf(err, errsz, "method must be GET, POST, PUT, DELETE or ANY"); goto done; }
    if (!route_pattern_ok(pattern) || route_reserved(pattern)) { snprintf(err, errsz, "bad or reserved pattern (/rpc, /files, /health, /metrics are built in)"); goto done; }
    if (!strcmp(type, "text")) ty = RT_TEXT; else if (!strcmp(type, "json")) ty = RT_JSON;
    else if (!strcmp(type, "file")) ty = RT_FILE; else if (!strcmp(type, "rpc")) ty = RT_RPC;
    if (ty < 0) { snprintf(err, errsz, "type must be text, json, file or rpc"); goto done; }
    if (strlen(target) > 500 || (ty == RT_JSON && !json_skip_value(target))) { snprintf(err, errsz, "bad target"); goto done; }
    if (status < 100 || status > 599) { snprintf(err, errsz, "bad status"); goto done; }
    if (ctype && (strlen(ctype) > 60 || strpbrk(ctype, "\r\n"))) { snprintf(err, errsz, "bad content_type"); goto done; }
    if (pub && ty != RT_TEXT && ty != RT_JSON) { snprintf(err, errsz, "only text and json routes can be public"); goto done; }
    pthread_mutex_lock(&g_http.lock);
    for (i = 0; i < HTTP_MAX_ROUTES; i++) if (!g_http.routes[i].used) { slot = i; break; }
    if (slot < 0) snprintf(err, errsz, "route table full");
    else {
        r = &g_http.routes[slot];
        memset(r, 0, sizeof(*r));
        r->used = 1; r->id = g_http.next_route++; r->type = ty; r->status = (int)status; r->is_public = pub;
        snprintf(r->method, sizeof(r->method), "%s", method);
        snprintf(r->pattern, sizeof(r->pattern), "%s", pattern);
        snprintf(r->target, sizeof(r->target), "%s", target);
        snprintf(r->ctype, sizeof(r->ctype), "%s", ctype ? ctype : (ty == RT_JSON ? "application/json" : "text/plain; charset=utf-8"));
        sb_printf(out, "{\"id\":%u}", r->id);
        rc = 0;
    }
    pthread_mutex_unlock(&g_http.lock);
    if (rc == 0) { ev_begin(&e, "server.route.add"); ev_caller(&e, &rq->caller); ev_s(&e, "method", method); ev_s(&e, "pattern", pattern); ev_s(&e, "type", type); ev_b(&e, "public", pub); le_emit(&e); }
done:
    free(method); free(pattern); free(type); free(target); free(ctype);
    return rc;
}

static int rpc_route_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, first = 1;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"routes\":[");
    pthread_mutex_lock(&g_http.lock);
    for (i = 0; i < HTTP_MAX_ROUTES; i++) if (g_http.routes[i].used) { if (!first) sb_putn(out, ",", 1); route_json(out, &g_http.routes[i]); first = 0; }
    pthread_mutex_unlock(&g_http.lock);
    sb_puts(out, "]}");
    return 0;
}

static int rpc_route_remove(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t id;
    int i, hit = 0;
    ev_t e;
    if (json_get_i64(params, "id", &id) < 0) RPC_ERR("id required");
    pthread_mutex_lock(&g_http.lock);
    for (i = 0; i < HTTP_MAX_ROUTES; i++) if (g_http.routes[i].used && g_http.routes[i].id == (uint32_t)id) { g_http.routes[i].used = 0; hit = 1; }
    pthread_mutex_unlock(&g_http.lock);
    if (!hit) RPC_ERR("no such route");
    ev_begin(&e, "server.route.remove"); ev_caller(&e, &rq->caller); ev_u(&e, "id", (uint64_t)id); le_emit(&e);
    sb_puts(out, "{\"removed\":true}");
    return 0;
}

static int rpc_server_config(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t v;
    int i, changed = 0;
    ev_t e;
    char *cors = json_str_dup(params, "cors");
    if (json_get_i64(params, "rate", &v) == 0) { if (v < 0 || v > 100000) { free(cors); RPC_ERR("rate is 0..100000 requests/s per IP (0 = off)"); } g_http.rate = (int)v; changed = 1; }
    if (json_get_i64(params, "max_body", &v) == 0) { if (v < 1024 || v > (1 << 30)) { free(cors); RPC_ERR("max_body is 1024..1073741824"); } g_http.max_body = (uint64_t)v; changed = 1; }
    if (cors) {
        char *tok, *save = NULL;
        pthread_mutex_lock(&g_http.lock);
        g_http.ncors = 0;
        for (tok = strtok_r(cors, ", ", &save); tok && g_http.ncors < 8; tok = strtok_r(NULL, ", ", &save))
            if (strlen(tok) < 190 && (!strcmp(tok, "*") || !strncmp(tok, "http", 4))) snprintf(g_http.cors[g_http.ncors++], 200, "%s", tok);
        pthread_mutex_unlock(&g_http.lock);
        free(cors);
        changed = 1;
    }
    if (changed) { ev_begin(&e, "server.config"); ev_caller(&e, &rq->caller); ev_i(&e, "rate", g_http.rate); ev_u(&e, "max_body", g_http.max_body); ev_u(&e, "cors_origins", (uint64_t)g_http.ncors); le_emit(&e); }
    sb_printf(out, "{\"rate\":%d,\"max_body\":%" PRIu64 ",\"max_conns\":%d,\"per_ip\":%d,\"cors\":[", g_http.rate, g_http.max_body, g_http.max_conns, g_http.per_ip);
    for (i = 0; i < g_http.ncors; i++) { if (i) sb_putn(out, ",", 1); sb_json_str(out, g_http.cors[i]); }
    sb_puts(out, "]}");
    return 0;
}

/* ── tokens ────────────────────────────────────────────────────────────────── */
static int rpc_token_add(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name"), *role = json_str_dup(params, "role");
    uint8_t caps = 0;
    int64_t ttl = 0;
    int i, slot = -1, rc = -1;
    char secret[40], rnd[16], hx[65];
    ev_t e;
    json_get_i64(params, "ttl_s", &ttl);
    if (!name_ok(name, 40)) { snprintf(err, errsz, "name: 1-39 letters, digits, _ - ."); goto done; }
    if (role && *role && !name_ok(role, 24)) { snprintf(err, errsz, "role: 1-23 letters, digits, _ - ."); goto done; }
    if (json_find(params, "caps") && parse_caps(params, &caps) < 0) { snprintf(err, errsz, "bad caps"); goto done; }
    if (caps & ~rq->caller.caps) { snprintf(err, errsz, "cannot give a token capabilities you do not hold"); goto done; }
    if (ttl < 0 || ttl > 3153600000LL) { snprintf(err, errsz, "bad ttl_s"); goto done; }
    if (le_random(rnd, sizeof(rnd)) < 0) { snprintf(err, errsz, "no random source"); goto done; }
    memcpy(secret, "le_", 3);
    for (i = 0; i < 16; i++) sprintf(secret + 3 + 2 * i, "%02x", (unsigned char)rnd[i]);
    sha256_hex((const uint8_t *)secret, strlen(secret), hx);
    pthread_mutex_lock(&g_tok_lock);
    for (i = 0; i < TOK_MAX; i++) {
        if (g_tok[i].used && strcmp(g_tok[i].name, name) == 0) { snprintf(err, errsz, "a token with this name exists (revoke it first)"); slot = -2; break; }
        if (!g_tok[i].used && slot < 0) slot = i;
    }
    if (slot == -1) snprintf(err, errsz, "token table full (%d)", TOK_MAX);
    if (slot >= 0) {
        tok_t *t = &g_tok[slot];
        memset(t, 0, sizeof(*t));
        t->used = 1; t->id = g_tok_next++; t->caps = caps;
        snprintf(t->name, sizeof(t->name), "%s", name);
        snprintf(t->sha, sizeof(t->sha), "%s", hx);
        snprintf(t->role, sizeof(t->role), "%s", role ? role : "");
        t->created_s = (uint64_t)time(NULL);
        t->expires_s = ttl ? t->created_s + (uint64_t)ttl : 0;
        tok_save_locked();
        rc = 0;
    }
    pthread_mutex_unlock(&g_tok_lock);
    if (rc < 0) goto done;
    ev_begin(&e, "token.create"); ev_caller(&e, &rq->caller); ev_s(&e, "token", name); ev_u(&e, "caps", caps); ev_s(&e, "role", role ? role : ""); ev_i(&e, "ttl_s", ttl); le_emit(&e);
    sb_puts(out, "{\"name\":"); sb_json_str(out, name);
    sb_printf(out, ",\"token\":\"%s\",\"note\":\"shown once; only its hash is stored\"}", secret);
done:
    free(name); free(role);
    return rc;
}

static int rpc_token_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, first = 1;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"tokens\":[");
    pthread_mutex_lock(&g_tok_lock);
    for (i = 0; i < TOK_MAX; i++) {
        const tok_t *t = &g_tok[i];
        if (!t->used) continue;
        sb_printf(out, "%s{\"name\":", first ? "" : ",");
        sb_json_str(out, t->name);
        sb_puts(out, ",\"role\":"); sb_json_str(out, t->role);
        sb_putn(out, ",", 1); sb_caps(out, t->caps);
        sb_printf(out, ",\"created\":%" PRIu64 ",\"expires\":%" PRIu64 ",\"uses\":%" PRIu64 "}", t->created_s, t->expires_s, t->uses);
        first = 0;
    }
    pthread_mutex_unlock(&g_tok_lock);
    sb_puts(out, "]}");
    return 0;
}

static int rpc_token_revoke(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    uint32_t id = 0;
    int i;
    ev_t e;
    if (!name) RPC_ERR("name required");
    pthread_mutex_lock(&g_tok_lock);
    for (i = 0; i < TOK_MAX; i++) if (g_tok[i].used && strcmp(g_tok[i].name, name) == 0) { id = g_tok[i].id; g_tok[i].used = 0; }
    if (id) tok_save_locked();
    pthread_mutex_unlock(&g_tok_lock);
    if (!id) { free(name); RPC_ERR("no such token"); }
    tok_drop_sessions(id);
    ev_begin(&e, "token.revoke"); ev_caller(&e, &rq->caller); ev_s(&e, "token", name); le_emit(&e);
    free(name);
    sb_puts(out, "{\"revoked\":true}");
    return 0;
}

/* ── method table ──────────────────────────────────────────────────────────── */
static int rpc_methods_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz);

static const rpc_method_t g_rpc_methods[] = {
    { "identity",         rpc_identity,       0,           0, 0 },
    { "rpc.methods",      rpc_methods_list,   0,           0, 0 },
    { "auth.login",       rpc_auth_login,     0,           0, 0 },
    { "auth.logout",      rpc_auth_logout,    0,           0, 0 },
    { "auth.whoami",      rpc_auth_whoami,    0,           0, 0 },
    { "peer.list",        rpc_peer_list,      SPCAP_KICK,  0, 0 },
    { "peer.status",      rpc_peer_status,    0,           0, 0 },
    { "peer.kick",        rpc_peer_kick,      SPCAP_KICK,  0, 0 },
    { "policy.get",       rpc_policy_get,     0,           0, 0 },
    { "policy.check",     rpc_policy_check,   0,           0, 0 },
    { "policy.grant",     rpc_policy_grant,   SPCAP_POLICY, 0, 0 },
    { "policy.revoke",    rpc_policy_revoke,  SPCAP_POLICY, 0, 0 },
    { "policy.rule.add",  rpc_rule_add,       SPCAP_POLICY, 0, 0 },
    { "policy.rule.list", rpc_rule_list,      SPCAP_POLICY, 0, 0 },
    { "policy.rule.remove", rpc_rule_remove,  SPCAP_POLICY, 0, 0 },
    { "policy.rule.clear", rpc_rule_clear,    SPCAP_POLICY, 0, 0 },
    { "policy.eval",      rpc_rule_eval,      SPCAP_POLICY, 0, 0 },
    { "policy.set",       rpc_policy_set,     SPCAP_POLICY, 0, 0 },
    { "policy.role.set",  rpc_policy_role,    SPCAP_POLICY, 0, 0 },
    { "policy.stats",     rpc_policy_stats,   SPCAP_POLICY, 0, 0 },
    { "log.head",         rpc_log_head,       SPCAP_LOGR,  0, 0 },
    { "log.stats",        rpc_log_stats,      SPCAP_LOGR,  0, 0 },
    { "log.tail",         rpc_log_tail,       SPCAP_LOGR,  0, 0 },
    { "log.verify",       rpc_log_verify,     SPCAP_LOGR,  0, 0 },
    { "fse.info",         rpc_fse_info,       SPCAP_FSR,   0, 0 },
    { "fse.stat",         rpc_fse_stat,       SPCAP_FSR,   0, 1 },
    { "fse.ls",           rpc_fse_ls,         SPCAP_FSR,   0, 1 },
    { "fse.read",         rpc_fse_read,       SPCAP_FSR,   0, 1 },
    { "fse.hash",         rpc_fse_hash,       SPCAP_FSR,   0, 1 },
    { "fse.write",        rpc_fse_write,      SPCAP_FSW,   0, 1 },
    { "fse.touch",        rpc_fse_touch,      SPCAP_FSW,   0, 1 },
    { "fse.mkdir",        rpc_fse_mkdir,      SPCAP_FSW,   0, 1 },
    { "fse.rm",           rpc_fse_rm,         SPCAP_FSW,   0, 1 },
    { "fse.mv",           rpc_fse_mv,         SPCAP_FSW,   0, 1 },
    { "fse.cp",           rpc_fse_cp,         SPCAP_FSW | SPCAP_FSR, 0, 1 },
    { "fse.chmod",        rpc_fse_chmod,      SPCAP_FSW,   0, 1 },
    { "fse.exec",         rpc_fse_exec,       SPCAP_EXEC | SPCAP_FSR, 0, 1 },
    { "server.status",    rpc_server_status,  0,           0, 0 },
    { "server.route.add", rpc_route_add,      SPCAP_SRV,   0, 0 },
    { "server.route.list", rpc_route_list,    SPCAP_SRV,   0, 0 },
    { "server.route.remove", rpc_route_remove, SPCAP_SRV,  0, 0 },
    { "server.config",    rpc_server_config,  SPCAP_SRV,   0, 0 },
    { "server.token.add", rpc_token_add,      SPCAP_TOK,   0, 0 },
    { "server.token.list", rpc_token_list,    SPCAP_TOK,   0, 0 },
    { "server.token.revoke", rpc_token_revoke, SPCAP_TOK,  0, 0 },
};
#define N_RPC_METHODS ((int)(sizeof(g_rpc_methods) / sizeof(g_rpc_methods[0])))

static int rpc_methods_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"methods\":[");
    for (i = 0; i < N_RPC_METHODS; i++) {
        const rpc_method_t *m = &g_rpc_methods[i];
        char nb[48];
        sb_printf(out, "%s{\"name\":\"%s\",\"needs\":\"%s\"}", i ? "," : "", m->name, need_str(m->need, nb, sizeof(nb)));
    }
    sb_puts(out, "]}");
    return 0;
}

/* One line in the audit log for every finished call (denied and failed ones included). */
static void rpc_run_logged_done(const rpc_req_t *rq, const char *method, const char *params, int rc, const char *err) {
    ev_t e;
    char red[260];
    uint64_t dur = sp_now_us() - rq->t0_us;
    SP_INC(g_stat.rpc_total);
    if (rc != 0 && err && strncmp(err, "denied", 6) == 0) SP_INC(g_stat.rpc_denied);
    else if (rc != 0) SP_INC(g_stat.rpc_errors);
    le_redact(params ? params : "", red, sizeof(red));
    ev_begin(&e, "rpc");
    ev_caller(&e, &rq->caller);
    ev_s(&e, "method", method); ev_s(&e, "params", red);
    if (rq->has_id) ev_u(&e, "id", rq->id);
    ev_b(&e, "ok", rc == 0);
    if (rc != 0) ev_s(&e, "error", err ? err : "error");
    ev_u(&e, "dur_us", dur);
    le_emit(&e);
}

/* 0 = ok (result in out), -1 = error (message in err), 1 = async (the reply comes later) */
static int rpc_execute(const rpc_req_t *rq, const char *method, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    if (*json_skip_ws(params) != '{') RPC_ERR("params must be an object");
    for (i = 0; i < N_RPC_METHODS; i++) {
        const rpc_method_t *m = &g_rpc_methods[i];
        char nb[48];
        if (strcmp(m->name, method) != 0) continue;
        if (m->terminal_only && rq->caller.kind != CALLER_TERMINAL) RPC_ERR("denied: terminal only");
        if ((rq->caller.caps & m->need) != m->need) RPC_ERR("denied: needs cap %s", need_str(m->need, nb, sizeof(nb)));
        if (!m->self_gated) {
            char act[80], why[100];
            snprintf(act, sizeof(act), "rpc.%s", m->name);
            if (!policy_check(&rq->caller, act, "*", why, sizeof(why))) RPC_ERR("denied by policy (%s)", why);
        }
        return m->fn(rq, params, out, err, errsz);
    }
    RPC_ERR("unknown method: %.64s", method);
}

static int rpc_execute_logged(rpc_req_t *rq, const char *method, const char *params, sb_t *out, char *err, size_t errsz) {
    int rc;
    snprintf(rq->mname, sizeof(rq->mname), "%s", method);
    err[0] = '\0';
    rc = rpc_execute(rq, method, params, out, err, errsz);
    if (rc == 0 && out->err) { rc = -1; snprintf(err, errsz, "out of memory"); }
    if (rc <= 0) rpc_run_logged_done(rq, method, params, rc, err);
    return rc;
}

/* SPP_RPC entry point (IO thread). text is NUL-terminated JSON. */
static void rpc_handle_text(peer_ref_t ref, const char *text) {
    rpc_req_t rq;
    char *method, *params, err[200] = "";
    sb_t out;
    int rc;
    uint64_t id = 0;

    memset(&rq, 0, sizeof(rq));
    caller_from_peer(ref, &rq.caller);
    rq.has_id = json_get_u64(text, "id", &id) == 0;
    rq.id = id;
    rq.t0_us = sp_now_us();
    method = json_str_dup(text, "method");
    params = json_raw_dup(text, "params");
    sb_init(&out);
    if (!method) {
        snprintf(err, sizeof(err), "method required");
        rpc_run_logged_done(&rq, "(none)", text, -1, err);
        rc = -1;
    } else rc = rpc_execute_logged(&rq, method, params ? params : "{}", &out, err, sizeof(err));
    if (rc <= 0 && rq.has_id) rpc_reply(&rq.caller, 1, rq.id, rc == 0, rc == 0 ? out.p : err);
    sb_free(&out);
    free(method);
    free(params);
}

/* Terminal and HTTP: run a method and wait for the answer. */
static int rpc_call_as(const sp_caller_t *caller, const char *method, const char *params, sb_t *out, char *err, size_t errsz) {
    rpc_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.caller = *caller;
    rq.t0_us = sp_now_us();
    return rpc_execute_logged(&rq, method, params, out, err, errsz);
}

static int rpc_call_terminal(const char *method, const char *params, sb_t *out, char *err, size_t errsz) {
    sp_caller_t c;
    memset(&c, 0, sizeof(c));
    c.kind = CALLER_TERMINAL;
    c.caps = SPCAP_ALL;
    snprintf(c.name, sizeof(c.name), "terminal");
    return rpc_call_as(&c, method, params, out, err, errsz);
}


/* ── SPP message handler (IO thread, no locks held) ────────────────────────── */
/* Returns -1 to have the peer dropped. Never touch `peer` after a send: the send may drop it. */
static int spp_handle_message(spp_peer_t *peer, uint16_t msg_type, uint8_t *payload, uint32_t payload_len) {
    peer_ref_t ref;
    ev_t e;
    ref.slot = (uint32_t)(peer - g_sp.peers);
    ref.conn = peer->conn_id;

    switch (msg_type) {
    case SPP_PING:
        spp_peer_send(ref, SPP_PONG, NULL, 0);
        break;
    case SPP_PONG:
        pthread_mutex_lock(&g_sp.peers_lock);
        if (peer->ping_sent_ms) {
            peer->rtt_ms = (uint32_t)(sp_now_ms() - peer->ping_sent_ms);
            peer->ping_sent_ms = 0;
        }
        pthread_mutex_unlock(&g_sp.peers_lock);
        break;
    case SPP_RPC:
        rpc_handle_text(ref, (const char *)payload);
        break;
    case SPP_CLOSE:
        ev_begin(&e, "spp.close"); ev_u(&e, "conn", ref.conn); le_emit(&e);
        return -1;
    default:
        ev_begin(&e, "spp.frame");
        ev_u(&e, "conn", ref.conn); ev_u(&e, "type", msg_type); ev_u(&e, "len", payload_len); ev_b(&e, "handled", 0);
        le_emit(&e);
        spp_peer_error(ref, "unsupported message type (LocalEnterprise speaks SPP_RPC only)");
        break;
    }
    return 0;
}

/* ── SPP IO engine ─────────────────────────────────────────────────────────────
 * One epoll thread serves every peer (a thread per peer cannot reach ~128k).
 * Sockets are non-blocking; partial packets are buffered per peer only while
 * incomplete; writes go through a bounded per-peer queue.
 */
static uint8_t g_io_scratch[SPP_HEADER_SIZE + SPP_MAX_PAYLOAD + SPP_CRC_SIZE];
static uint8_t g_io_payload[SPP_MAX_PAYLOAD + 1];

static void io_drop(uint32_t slot, int fd) {
    pthread_mutex_lock(&g_sp.peers_lock);
    if (g_sp.peers[slot].sock == fd) peer_release_locked(slot);
    pthread_mutex_unlock(&g_sp.peers_lock);
}

static void io_accept_all(void) {
    for (;;) {
        struct sockaddr_in ca;
        socklen_t al = sizeof(ca);
        struct epoll_event ev;
        spp_peer_t *p;
        uint32_t slot;
        int fd = accept4(g_sp.server_sock, (struct sockaddr *)&ca, &al, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EMFILE || errno == ENFILE) {   /* out of fds: back off instead of spinning */
                static uint64_t last_warn;
                uint64_t now = sp_now_ms();
                if (now - last_warn > 5000) { SP_WARN("accept: out of file descriptors (raise ulimit -n)"); last_warn = now; }
                usleep(20000);
            }
            return;                                     /* EAGAIN: drained */
        }

        pthread_mutex_lock(&g_sp.peers_lock);
        if (g_sp.free_top == 0) {
            pthread_mutex_unlock(&g_sp.peers_lock);
            SP_DBG("peer slots full (%zu), rejecting connection", g_sp.max_peers);
            close(fd);
            continue;
        }
        slot = g_sp.free_slots[--g_sp.free_top];
        p = &g_sp.peers[slot];
        memset(p, 0, sizeof(*p));
        p->sock         = fd;
        p->hs           = 1;
        p->conn_id      = ++g_sp.next_conn_id;
        p->addr         = ca.sin_addr.s_addr;
        p->sp_caps      = g_sp.default_caps;
        p->connected_ms = p->last_rx_ms = sp_now_ms();
        g_sp.peer_count++;
        if ((size_t)slot + 1 > g_sp.peer_hi) g_sp.peer_hi = (size_t)slot + 1;

        ev.events   = EPOLLIN | EPOLLRDHUP;
        ev.data.u64 = ((uint64_t)(uint32_t)fd << 32) | slot;
        if (epoll_ctl(g_sp.epfd, EPOLL_CTL_ADD, fd, &ev) < 0) peer_release_locked(slot);
        pthread_mutex_unlock(&g_sp.peers_lock);
        SP_DBG("new connection from %s (slot %u)", inet_ntoa(ca.sin_addr), slot);
        { ev_t e; ev_begin(&e, "conn.open"); ev_s(&e, "ip", inet_ntoa(ca.sin_addr)); ev_u(&e, "slot", slot); le_emit(&e); }
    }
}

static int io_handshake(uint32_t slot, spp_peer_t *p, const char *payload) {
    char session[37], mention[64] = {0};
    char *m;
    size_t i;
    peer_ref_t ref;
    sb_t ack;

    SP_DBG("handshake: CONNECT from: %.200s", payload);
    m = json_str_dup(payload, "spmention");
    if (m) {
        strncpy(mention, m, sizeof(mention) - 1);
        for (i = 0; mention[i]; i++)                    /* printable ASCII only: it ends up in logs and JSON */
            if ((unsigned char)mention[i] < 0x20 || (unsigned char)mention[i] > 0x7E) mention[i] = '_';
        free(m);
    }
    sp_gen_uuid(session);

    pthread_mutex_lock(&g_sp.peers_lock);
    p->seq_local = 1;
    memcpy(p->session_id, session, sizeof(p->session_id));
    memcpy(p->spmention, mention, sizeof(p->spmention));
    p->caps   = 0x04;                                   /* host */
    p->hs     = 0;
    p->active = 1;
    p->next_ping_ms = sp_now_ms() + SPP_PING_INTERVAL;
    g_sp.ready_count++;
    ref.slot = slot;
    ref.conn = p->conn_id;
    pthread_mutex_unlock(&g_sp.peers_lock);

    sb_init(&ack);
    sb_puts(&ack, "{\"spmention\":");
    sb_json_str(&ack, g_sp.spmention);
    sb_printf(&ack, ",\"session_id\":\"%s\",\"uid\":%" PRIu64 ",\"spp\":\"%d.%d\",",
              session, (uint64_t)SP_BASE_ID + ref.conn, SPP_VERSION >> 8, SPP_VERSION & 0xFF);
    sb_caps(&ack, sp_caps_get(p));
    sb_puts(&ack, ",\"accepted_caps\":[\"rpc\"],\"product\":\"LocalEnterprise\"}");
    if (!ack.err) spp_peer_send(ref, SPP_CONNECT_ACK, (const uint8_t *)ack.p, (uint32_t)ack.len);
    sb_free(&ack);
    SP_DBG("handshake: accepted peer %s session=%s", mention, session);
    { ev_t e; ev_begin(&e, "conn.handshake"); ev_u(&e, "conn", ref.conn); ev_s(&e, "spmention", mention); ev_s(&e, "session", session); le_emit(&e); }
    return 0;
}

static int io_consume(uint32_t slot, int fd, const uint8_t *data, size_t n) {
    spp_peer_t *p = &g_sp.peers[slot];
    uint64_t conn = p->conn_id;
    const uint8_t *buf;
    size_t len, off = 0, rem;

    if (p->rx_len) {                                    /* continue a partial message */
        uint8_t *nb;
        if (g_sp.rx_buffered + n > SPP_RX_BUDGET) return -1;
        nb = (uint8_t *)realloc(p->rx, p->rx_len + n);
        if (!nb) return -1;
        memcpy(nb + p->rx_len, data, n);
        p->rx = nb;
        p->rx_len += n;
        g_sp.rx_buffered += n;
        buf = p->rx; len = p->rx_len;
    } else {
        buf = data; len = n;
    }
    p->last_rx_ms = sp_now_ms();

    while (len - off >= SPP_HEADER_SIZE) {
        spp_header_t h;
        size_t need;
        uint32_t crc_recv, crc_calc;

        memcpy(&h, buf + off, SPP_HEADER_SIZE);
        if (memcmp(h.magic, SPP_MAGIC, SPP_MAGIC_LEN) != 0) { SP_DBG("slot %u: bad magic", slot); return -1; }
        if (h.payload_len > (p->hs ? SPP_HS_MAX_PAYLOAD : SPP_MAX_PAYLOAD)) { SP_DBG("slot %u: payload too large", slot); return -1; }
        need = SPP_HEADER_SIZE + h.payload_len + SPP_CRC_SIZE;
        if (len - off < need) break;                    /* wait for the rest */

        memcpy(&crc_recv, buf + off + SPP_HEADER_SIZE + h.payload_len, SPP_CRC_SIZE);
        crc_calc = spp_crc32(buf + off, SPP_HEADER_SIZE + h.payload_len);
        if (crc_recv != crc_calc) { SP_WARN("slot %u: CRC mismatch (got %08x, expected %08x)", slot, crc_recv, crc_calc); return -1; }

        memcpy(g_io_payload, buf + off + SPP_HEADER_SIZE, h.payload_len);
        g_io_payload[h.payload_len] = '\0';
        off += need;
        p->seq_remote = h.seq;

        if (p->hs) {
            if (h.msg_type != SPP_CONNECT) { SP_WARN("handshake: expected CONNECT, got 0x%04x", h.msg_type); return -1; }
            if (io_handshake(slot, p, (const char *)g_io_payload) < 0) return -1;
        } else if (spp_handle_message(p, h.msg_type, g_io_payload, h.payload_len) < 0) {
            return -1;
        }
        /* The handler may have dropped this peer (kick, failed send). buf may be gone. */
        if (p->conn_id != conn || p->sock != fd || (!p->active && !p->hs)) return 0;
    }

    rem = len - off;                                    /* keep only an incomplete tail */
    if (buf == data) {
        if (rem) {
            uint8_t *nb = (uint8_t *)malloc(rem);
            if (!nb) return -1;
            memcpy(nb, data + off, rem);
            p->rx = nb; p->rx_len = rem; g_sp.rx_buffered += rem;
        }
    } else if (rem == 0) {
        g_sp.rx_buffered -= p->rx_len;
        free(p->rx); p->rx = NULL; p->rx_len = 0;
    } else if (off) {
        memmove(p->rx, p->rx + off, rem);
        g_sp.rx_buffered -= off;
        p->rx_len = rem;
    }
    return 0;
}

static void io_on_readable(uint32_t slot, int fd) {
    int rounds;
    for (rounds = 0; rounds < 4; rounds++) {            /* bounded per event so one peer cannot starve the rest */
        ssize_t n = recv(fd, g_io_scratch, sizeof(g_io_scratch), 0);
        if (n == 0) { io_drop(slot, fd); return; }
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            io_drop(slot, fd);
            return;
        }
        if (io_consume(slot, fd, g_io_scratch, (size_t)n) < 0) { io_drop(slot, fd); return; }
        if (g_sp.peers[slot].sock != fd) return;        /* released while handling */
        if ((size_t)n < sizeof(g_io_scratch)) return;   /* drained */
    }
}

/* Once a second: handshake timeouts, keepalive pings, dead-peer reaping, RPC deadlines. */
static void io_housekeeping(void) {
    uint64_t now = sp_now_ms();
    size_t i;

    pthread_mutex_lock(&g_sp.peers_lock);
    for (i = 0; i < g_sp.peer_hi; i++) {
        spp_peer_t *p = &g_sp.peers[i];
        if (p->hs) {
            if (now - p->connected_ms > SPP_HS_TIMEOUT_MS) peer_release_locked((uint32_t)i);
        } else if (p->active) {
            if (now - p->last_rx_ms > 3 * (uint64_t)SPP_PING_INTERVAL) {
                peer_release_locked((uint32_t)i);       /* silent for three ping intervals */
            } else if (now >= p->next_ping_ms) {        /* keepalive + RTT sample */
                uint8_t pkt[SPP_HEADER_SIZE + SPP_CRC_SIZE];
                size_t total = spp_build_packet(pkt, SPP_PING, p->seq_local++, NULL, 0);
                p->ping_sent_ms = now;
                p->next_ping_ms = now + SPP_PING_INTERVAL;
                peer_send_raw_locked((uint32_t)i, pkt, total);
            }
        }
    }
    pthread_mutex_unlock(&g_sp.peers_lock);

    le_log_tick();
    tok_tick();
}

static void *spp_server_thread(void *arg) {
    struct epoll_event evs[256];
    uint64_t last_hk = sp_now_ms();
    (void)arg;

    g_sp.io_thread = pthread_self();
    SP_LOG("SPP server listening on port %d (epoll, up to %zu peers)", g_sp.port, g_sp.max_peers);

    while (SP_IS_RUNNING()) {
        int n = epoll_wait(g_sp.epfd, evs, 256, 250), i;
        if (n < 0) {
            if (errno == EINTR) continue;
            if (SP_IS_RUNNING()) SP_ERR("epoll_wait: %s", strerror(errno));
            break;
        }
        for (i = 0; i < n; i++) {
            uint64_t d = evs[i].data.u64;
            uint32_t ev = evs[i].events, slot;
            int fd;
            spp_peer_t *p;

            if (d == UINT64_MAX) { io_accept_all(); continue; }
            slot = (uint32_t)d;
            fd   = (int)(d >> 32);
            p    = &g_sp.peers[slot];
            if (p->sock != fd || (!p->active && !p->hs)) continue;   /* stale event */

            if (ev & EPOLLOUT) {
                int rc;
                pthread_mutex_lock(&g_sp.peers_lock);
                rc = peer_flush_locked(slot);
                if (rc < 0) peer_release_locked(slot);
                pthread_mutex_unlock(&g_sp.peers_lock);
                if (rc < 0) continue;
            }
            if (ev & EPOLLIN)                              io_on_readable(slot, fd);
            else if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) io_drop(slot, fd);
        }
        if (sp_now_ms() - last_hk >= 1000) { last_hk = sp_now_ms(); io_housekeeping(); }
    }
    return NULL;
}


/* ════════════════════════════════════════════════════════════════════════════
 * SPPServer — HTTP/1.1 next to the SPP port
 *
 * Pipeline for every request:
 *   request id -> connection / per-IP limits -> rate limit (token bucket per IP) -> CORS ->
 *   Bearer-token auth -> route (built-in or user route) -> SPPPolicyE -> handler -> SPPLogE
 * Built-in routes:  GET /health (public)  GET /metrics  POST /rpc  GET|HEAD|PUT|DELETE /files/<path>
 * /rpc and /files delegate to the same RPC methods as SPP, so capabilities and policy rules
 * (fse.*, rpc.*) apply identically; user routes (server.route.add) are checked as http.<METHOD>.
 * No TLS here: bind to localhost or put a TLS terminator in front, because tokens travel in clear.
 * ════════════════════════════════════════════════════════════════════════════ */
#define HDR_MAX 16384

typedef struct {
    char    method[8], path[1100], query[1000], authz[300], origin[200], ctype[100], range[80];
    size_t  clen;
    int     minor, keepalive, expect100;
    uint8_t *body;
    size_t  nbody;
} hreq_t;

typedef struct {
    int      fd;
    uint32_t ip;
    char     ipstr[INET_ADDRSTRLEN], reqid[17], cors_origin[200];
    hreq_t   rq;
    int      status, head_only, more;
    uint64_t bytes;
    sp_caller_t caller;
} hctx_t;

/* ── limits ────────────────────────────────────────────────────────────────── */
static pthread_mutex_t g_ipc_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { uint32_t ip; int n; } g_ipc[512];
static struct { uint32_t ip; double tokens; uint64_t last; } g_bucket[1024];

static int ip_acquire(uint32_t ip) {
    int i, free_i = -1, ok = 0;
    pthread_mutex_lock(&g_ipc_lock);
    for (i = 0; i < 512; i++) {
        if (g_ipc[i].n && g_ipc[i].ip == ip) { if (g_ipc[i].n < g_http.per_ip) { g_ipc[i].n++; ok = 1; } goto out; }
        if (!g_ipc[i].n && free_i < 0) free_i = i;
    }
    if (free_i >= 0) { g_ipc[free_i].ip = ip; g_ipc[free_i].n = 1; ok = 1; }
out:
    pthread_mutex_unlock(&g_ipc_lock);
    return ok;
}
static void ip_release(uint32_t ip) {
    int i;
    pthread_mutex_lock(&g_ipc_lock);
    for (i = 0; i < 512; i++) if (g_ipc[i].n && g_ipc[i].ip == ip) { g_ipc[i].n--; break; }
    pthread_mutex_unlock(&g_ipc_lock);
}

static int rate_ok(uint32_t ip) {
    uint64_t now = sp_now_ms();
    size_t k = (ip * 2654435761u) % 1024;
    double burst = g_http.rate * 2.0, el;
    int ok;
    if (g_http.rate <= 0) return 1;
    pthread_mutex_lock(&g_ipc_lock);
    if (g_bucket[k].ip != ip) { g_bucket[k].ip = ip; g_bucket[k].tokens = burst; g_bucket[k].last = now; }
    el = (double)(now - g_bucket[k].last) / 1000.0;
    g_bucket[k].tokens += el * g_http.rate;
    if (g_bucket[k].tokens > burst) g_bucket[k].tokens = burst;
    g_bucket[k].last = now;
    ok = g_bucket[k].tokens >= 1.0;
    if (ok) g_bucket[k].tokens -= 1.0;
    pthread_mutex_unlock(&g_ipc_lock);
    return ok;
}

/* ── responses ─────────────────────────────────────────────────────────────── */
static const char *http_reason(int s) {
    switch (s) {
    case 100: return "Continue"; case 200: return "OK"; case 201: return "Created"; case 204: return "No Content";
    case 206: return "Partial Content"; case 301: return "Moved Permanently"; case 302: return "Found"; case 304: return "Not Modified";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden"; case 404: return "Not Found";
    case 405: return "Method Not Allowed"; case 408: return "Request Timeout"; case 409: return "Conflict"; case 413: return "Payload Too Large";
    case 416: return "Range Not Satisfiable"; case 429: return "Too Many Requests"; case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error"; case 501: return "Not Implemented"; case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported"; default: return "Status";
    }
}

static int send_all_f(int fd, const void *buf, size_t n, int flags) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, (const char *)buf + off, n - off, MSG_NOSIGNAL | flags);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}
static int send_all(int fd, const void *buf, size_t n) { return send_all_f(fd, buf, n, 0); }

static void stat_status(int s) {
    if (s >= 500) SP_INC(g_http.st5xx); else if (s >= 400) SP_INC(g_http.st4xx);
    else if (s >= 300) SP_INC(g_http.st3xx); else SP_INC(g_http.st2xx);
}

/* clen is the Content-Length to announce; body may be NULL when streaming or HEAD */
static int http_head(hctx_t *h, int status, const char *ctype, uint64_t clen, const char *extra) {
    char buf[2048], date[40];
    time_t t = time(NULL);
    struct tm tm;
    int n;
    gmtime_r(&t, &tm);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    n = snprintf(buf, sizeof(buf),
                 "HTTP/1.1 %d %s\r\nServer: LocalEnterprise/" LE_VERSION "\r\nDate: %s\r\nX-Request-Id: %s\r\n"
                 "X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n"
                 "Content-Type: %s\r\nContent-Length: %" PRIu64 "\r\nConnection: %s\r\n%s",
                 status, http_reason(status), date, h->reqid, ctype ? ctype : "text/plain", clen,
                 h->rq.keepalive ? "keep-alive" : "close", extra ? extra : "");
    if (h->cors_origin[0])
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\n"
                      "Access-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS\r\n",
                      h->cors_origin);
    if (n < 0 || (size_t)n + 3 > sizeof(buf)) return -1;
    memcpy(buf + n, "\r\n", 2);
    h->status = status;
    return send_all_f(h->fd, buf, (size_t)n + 2, h->more ? MSG_MORE : 0);   /* headers and body leave in one segment */
}

static int http_reply(hctx_t *h, int status, const char *ctype, const void *body, size_t n, const char *extra) {
    h->more = n && body && !h->head_only;
    if (http_head(h, status, ctype, n, extra) < 0) return -1;
    h->bytes += n;
    if (n && body && !h->head_only) return send_all(h->fd, body, n);
    return 0;
}

static int http_error(hctx_t *h, int status, const char *msg) {
    sb_t b;
    int rc;
    sb_init(&b);
    sb_puts(&b, "{\"error\":");
    sb_json_str(&b, msg);
    sb_putn(&b, "}", 1);
    rc = http_reply(h, status, "application/json", b.p, b.len, status == 401 ? "WWW-Authenticate: Bearer\r\n" : (status == 429 ? "Retry-After: 1\r\n" : NULL));
    sb_free(&b);
    return rc;
}

/* maps an RPC / FSE error text to an HTTP status */
static int err_status(const char *err, int anonymous) {
    if (strncmp(err, "denied", 6) == 0) return anonymous ? 401 : 403;
    if (strstr(err, "no such") || strstr(err, "unknown method") || strstr(err, "No such")) return 404;
    if (strstr(err, "File exists") || strstr(err, "exists")) return 409;
    if (strstr(err, "exceed") || strstr(err, "too large") || strstr(err, "too much")) return 413;
    return 400;
}

/* ── parsing ───────────────────────────────────────────────────────────────── */
static int pct_decode(const char *in, char *out, size_t n) {
    size_t o = 0;
    while (*in) {
        unsigned char c = (unsigned char)*in++;
        if (c == '%') {
            int a = hexv(in[0]), b = a >= 0 ? hexv(in[1]) : -1;
            if (a < 0 || b < 0) return -1;
            c = (unsigned char)(a * 16 + b);
            in += 2;
            if (c == 0) return -1;
        }
        if (c < 0x20 || c == 0x7f) return -1;
        if (o + 1 >= n) return -1;
        out[o++] = (char)c;
    }
    out[o] = '\0';
    return 0;
}

static int query_get(const char *q, const char *key, char *out, size_t n) {
    size_t kl = strlen(key);
    while (*q) {
        if (strncmp(q, key, kl) == 0 && (q[kl] == '=' || q[kl] == '&' || q[kl] == '\0')) {
            const char *v = q[kl] == '=' ? q + kl + 1 : "";
            size_t l = strcspn(v, "&");
            char tmp[400];
            if (l >= sizeof(tmp)) return -1;
            memcpy(tmp, v, l); tmp[l] = '\0';
            return pct_decode(tmp, out, n);
        }
        q += strcspn(q, "&");
        if (*q == '&') q++;
    }
    return -1;
}

/* Reads one request. Returns 0 ok, -1 connection closed/timeout with nothing read, >0 error status to send. */
static int http_read_request(hctx_t *h, char *buf, size_t *have) {
    hreq_t *rq = &h->rq;
    size_t he = 0, i;
    char *hdr, *line, *save = NULL;
    int first = 1, seen_clen = 0;
    memset(rq, 0, sizeof(*rq));
    for (;;) {
        ssize_t n;
        if (*have >= 4) {
            for (i = 0; i + 3 < *have; i++) if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') { he = i + 4; break; }
        }
        if (he) break;
        if (*have >= HDR_MAX) return 431;
        n = recv(h->fd, buf + *have, HDR_MAX - *have, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) return -1;
        if (n < 0) return *have ? 408 : -1;
        *have += (size_t)n;
    }
    hdr = (char *)malloc(he + 1);
    if (!hdr) return 500;
    memcpy(hdr, buf, he - 2);
    hdr[he - 2] = '\0';
    rq->keepalive = 1;
    for (line = strtok_r(hdr, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        size_t l = strlen(line);
        if (l && line[l - 1] == '\r') line[--l] = '\0';
        if (first) {
            char *m = line, *t, *v;
            char target[2100], pathraw[2100];
            first = 0;
            t = strchr(m, ' ');
            if (!t) { free(hdr); return 400; }
            *t++ = '\0';
            v = strchr(t, ' ');
            if (!v) { free(hdr); return 400; }
            *v++ = '\0';
            if (strlen(m) >= sizeof(rq->method)) { free(hdr); return 501; }
            snprintf(rq->method, sizeof(rq->method), "%s", m);
            if (strcmp(v, "HTTP/1.1") == 0) rq->minor = 1; else if (strcmp(v, "HTTP/1.0") == 0) { rq->minor = 0; rq->keepalive = 0; }
            else { free(hdr); return 505; }
            if (strcmp(m, "GET") && strcmp(m, "HEAD") && strcmp(m, "POST") && strcmp(m, "PUT") && strcmp(m, "DELETE") && strcmp(m, "OPTIONS")) { free(hdr); return 501; }
            if (t[0] != '/' || strlen(t) >= sizeof(target)) { free(hdr); return 400; }
            snprintf(target, sizeof(target), "%s", t);
            {
                char *q = strchr(target, '?');
                if (q) { *q++ = '\0'; if (strlen(q) >= sizeof(rq->query)) { free(hdr); return 400; } snprintf(rq->query, sizeof(rq->query), "%s", q); }
            }
            snprintf(pathraw, sizeof(pathraw), "%s", target);
            if (pct_decode(pathraw, rq->path, sizeof(rq->path)) < 0) { free(hdr); return 400; }
            continue;
        }
        if (!l) continue;
        if (line[0] == ' ' || line[0] == '\t') { free(hdr); return 400; }       /* obsolete line folding */
        {
            char *colon = strchr(line, ':'), *val;
            size_t nl;
            if (!colon || colon == line) { free(hdr); return 400; }
            *colon = '\0';
            nl = strlen(line);
            for (i = 0; i < nl; i++) if (line[i] <= 0x20 || line[i] == 0x7f) { free(hdr); return 400; }
            val = colon + 1;
            while (*val == ' ' || *val == '\t') val++;
            if (!strcasecmp(line, "content-length")) {
                char *end;
                unsigned long long v;
                if (seen_clen || !isdigit((unsigned char)*val)) { free(hdr); return 400; }
                errno = 0; v = strtoull(val, &end, 10);
                while (*end == ' ' || *end == '\t') end++;
                if (*end || errno || v > (1ull << 40)) { free(hdr); return 400; }
                seen_clen = 1; rq->clen = (size_t)v;
            } else if (!strcasecmp(line, "transfer-encoding")) { free(hdr); return 501; }
            else if (!strcasecmp(line, "authorization")) snprintf(rq->authz, sizeof(rq->authz), "%s", val);
            else if (!strcasecmp(line, "origin")) snprintf(rq->origin, sizeof(rq->origin), "%s", val);
            else if (!strcasecmp(line, "content-type")) snprintf(rq->ctype, sizeof(rq->ctype), "%s", val);
            else if (!strcasecmp(line, "range")) snprintf(rq->range, sizeof(rq->range), "%s", val);
            else if (!strcasecmp(line, "expect")) rq->expect100 = strcasecmp(val, "100-continue") == 0;
            else if (!strcasecmp(line, "connection")) {
                if (strcasestr(val, "close")) rq->keepalive = 0;
                else if (strcasestr(val, "keep-alive")) rq->keepalive = 1;
            }
        }
    }
    free(hdr);
    if (first) return 400;
    if (rq->clen > g_http.max_body) { h->rq.keepalive = 0; return 413; }
    {   /* body */
        size_t have_body = *have - he, take;
        if (rq->clen) {
            rq->body = (uint8_t *)malloc(rq->clen + 1);
            if (!rq->body) return 500;
            take = have_body < rq->clen ? have_body : rq->clen;
            memcpy(rq->body, buf + he, take);
            rq->nbody = take;
            if (take < rq->clen && rq->expect100) send_all(h->fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
            while (rq->nbody < rq->clen) {
                ssize_t n = recv(h->fd, rq->body + rq->nbody, rq->clen - rq->nbody, 0);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { free(rq->body); rq->body = NULL; return 408; }
                rq->nbody += (size_t)n;
            }
            rq->body[rq->nbody] = '\0';
            memmove(buf, buf + he + take, have_body - take);
            *have = have_body - take;
        } else {
            memmove(buf, buf + he, have_body);
            *have = have_body;
        }
    }
    return 0;
}

/* ── auth + CORS ───────────────────────────────────────────────────────────── */
/* 0 = ok (anonymous or authenticated), -1 = a token was sent and is not valid */
static int http_auth(hctx_t *h) {
    sp_caller_t *c = &h->caller;
    memset(c, 0, sizeof(*c));
    c->kind = CALLER_HTTP;
    c->ip = h->ip;
    if (!h->rq.authz[0]) return 0;
    if (strncasecmp(h->rq.authz, "Bearer ", 7) != 0) return -1;
    if (!tok_lookup(h->rq.authz + 7, &c->caps, c->name, sizeof(c->name), c->role, sizeof(c->role))) return -1;
    return 0;
}

static void http_cors(hctx_t *h) {
    int i;
    h->cors_origin[0] = '\0';
    if (!h->rq.origin[0]) return;
    pthread_mutex_lock(&g_http.lock);
    for (i = 0; i < g_http.ncors; i++)
        if (!strcmp(g_http.cors[i], "*") || !strcmp(g_http.cors[i], h->rq.origin)) { snprintf(h->cors_origin, sizeof(h->cors_origin), "%s", h->rq.origin); break; }
    pthread_mutex_unlock(&g_http.lock);
}

/* ── handlers ──────────────────────────────────────────────────────────────── */
static const char *mime_of(const char *p) {
    static const struct { const char *ext, *mime; } t[] = {
        { ".txt", "text/plain; charset=utf-8" }, { ".html", "text/html; charset=utf-8" }, { ".css", "text/css" }, { ".js", "text/javascript" },
        { ".json", "application/json" }, { ".png", "image/png" }, { ".jpg", "image/jpeg" }, { ".jpeg", "image/jpeg" }, { ".gif", "image/gif" },
        { ".svg", "image/svg+xml" }, { ".pdf", "application/pdf" }, { ".csv", "text/csv" }, { ".xml", "application/xml" }, { ".md", "text/markdown; charset=utf-8" },
    };
    const char *dot = strrchr(p, '.');
    size_t i;
    if (dot) for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) if (strcasecmp(dot, t[i].ext) == 0) return t[i].mime;
    return "application/octet-stream";
}

static void rq_from_ctx(const hctx_t *h, rpc_req_t *rq) {
    memset(rq, 0, sizeof(*rq));
    rq->caller = h->caller;
    rq->t0_us = sp_now_us();
}

/* GET/HEAD of one FSE file (Range supported) */
static int serve_file(hctx_t *h, const char *fsepath) {
    rpc_req_t rq;
    struct stat st;
    char canon[FSE_MAXPATH + 2], err[200] = "", extra[256];
    int fd;
    uint64_t from = 0, to, total;
    int partial = 0;
    rq_from_ctx(h, &rq);
    snprintf(rq.mname, sizeof(rq.mname), "http.file");
    fd = fse_open_read(fsepath, &st, canon, sizeof(canon), &rq, err, sizeof(err));
    if (fd < 0) { rpc_run_logged_done(&rq, "fse.read", fsepath, -1, err); return http_error(h, err_status(err, !h->caller.name[0]), err); }
    total = (uint64_t)st.st_size;
    to = total ? total - 1 : 0;
    if (h->rq.range[0]) {
        unsigned long long a, b;
        char *dash;
        if (strncmp(h->rq.range, "bytes=", 6) != 0 || strchr(h->rq.range, ',')) goto bad_range;
        dash = strchr(h->rq.range + 6, '-');
        if (!dash) goto bad_range;
        if (dash == h->rq.range + 6) {                                  /* suffix: last N bytes */
            b = strtoull(dash + 1, NULL, 10);
            if (b == 0) goto bad_range;
            from = b > total ? 0 : total - b;
        } else {
            a = strtoull(h->rq.range + 6, NULL, 10);
            from = a;
            if (dash[1]) { b = strtoull(dash + 1, NULL, 10); to = b < to ? b : to; }
        }
        if (from >= total || from > to) goto bad_range;
        partial = 1;
    }
    {
        uint64_t len = total ? to - from + 1 : 0;
        off_t off = (off_t)from;
        int rc = 0;
        snprintf(extra, sizeof(extra), "Content-Security-Policy: sandbox\r\nAccept-Ranges: bytes\r\n%s", "");
        if (partial) {
            size_t l = strlen(extra);
            snprintf(extra + l, sizeof(extra) - l, "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n", from, to, total);
        }
        h->more = len && !h->head_only;
        if (http_head(h, partial ? 206 : 200, mime_of(canon), len, extra) < 0) { close(fd); return -1; }
        if (!h->head_only) {
            uint64_t left = len;
            while (left) {
                ssize_t n = sendfile(h->fd, fd, &off, left > (1u << 20) ? (1u << 20) : (size_t)left);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { rc = -1; break; }
                left -= (uint64_t)n;
                h->bytes += (uint64_t)n;
            }
            g_fse.bytes_read += len - left;
        }
        close(fd);
        rpc_run_logged_done(&rq, "fse.read", canon, rc, rc ? "connection lost" : NULL);
        return rc;
    }
bad_range:
    close(fd);
    snprintf(extra, sizeof(extra), "Content-Range: bytes */%" PRIu64 "\r\n", total);
    http_head(h, 416, "application/json", 22, extra);
    return send_all(h->fd, "{\"error\":\"bad range\"}\n", 22) < 0 ? -1 : 0;
}

static void json_envelope(sb_t *r, int ok, const char *body, const uint8_t *idraw) {
    (void)idraw;
    sb_putn(r, "{", 1);
    if (ok) { sb_puts(r, "\"ok\":true,\"result\":"); sb_puts(r, body ? body : "null"); }
    else { sb_puts(r, "\"ok\":false,\"error\":"); sb_json_str(r, body ? body : "error"); }
    sb_putn(r, "}", 1);
}

/* POST /rpc and RT_RPC routes */
static int run_rpc(hctx_t *h, const char *method, const char *params) {
    sb_t out, env;
    char err[240] = "";
    int rc, status;
    sb_init(&out); sb_init(&env);
    rc = rpc_call_as(&h->caller, method, params, &out, err, sizeof(err));
    json_envelope(&env, rc == 0, rc == 0 ? out.p : err, NULL);
    status = rc == 0 ? 200 : err_status(err, !h->caller.name[0]);
    rc = http_reply(h, status, "application/json", env.p, env.len, status == 401 ? "WWW-Authenticate: Bearer\r\n" : NULL);
    sb_free(&out); sb_free(&env);
    return rc;
}

static int h_rpc(hctx_t *h) {
    char *method, *params;
    int rc;
    if (strcmp(h->rq.method, "POST")) return http_error(h, 405, "use POST");
    if (!h->rq.nbody) return http_error(h, 400, "JSON body required: {\"method\":\"...\",\"params\":{...}}");
    method = json_str_dup((const char *)h->rq.body, "method");
    params = json_raw_dup((const char *)h->rq.body, "params");
    if (!method) { free(params); return http_error(h, 400, "method required"); }
    rc = run_rpc(h, method, params ? params : "{}");
    free(method); free(params);
    return rc;
}

static int h_files(hctx_t *h) {
    const char *sub = h->rq.path + 6;
    char fsepath[1100], mode[16] = "write", tmp[16];
    rpc_req_t rq;
    char err[240] = "", canon[FSE_MAXPATH + 2];
    int anon = !h->caller.name[0];
    snprintf(fsepath, sizeof(fsepath), "%s", *sub ? sub : "/");
    if (*sub && *sub != '/') return http_error(h, 404, "not found");
    if (!strcmp(h->rq.method, "GET") || !strcmp(h->rq.method, "HEAD")) {
        size_t l = strlen(fsepath);
        if (l > 1 && fsepath[l - 1] == '/') {                            /* directory listing */
            sb_t out, p, env;
            int rc, status;
            sb_init(&out); sb_init(&p); sb_init(&env);
            fsepath[l - 1] = '\0';
            sb_puts(&p, "{\"path\":"); sb_json_str(&p, fsepath);
            {
                char cur[24];
                if (query_get(h->rq.query, "cursor", cur, sizeof(cur)) == 0) sb_printf(&p, ",\"cursor\":%lld", atoll(cur));
            }
            sb_putn(&p, "}", 1);
            rc = rpc_call_as(&h->caller, "fse.ls", p.p, &out, err, sizeof(err));
            json_envelope(&env, rc == 0, rc == 0 ? out.p : err, NULL);
            status = rc == 0 ? 200 : err_status(err, anon);
            rc = http_reply(h, status, "application/json", env.p, env.len, NULL);
            sb_free(&out); sb_free(&p); sb_free(&env);
            return rc;
        }
        if (l == 1) { sb_t out, env; char e2[240] = ""; int rc, status; sb_init(&out); sb_init(&env);
            rc = rpc_call_as(&h->caller, "fse.ls", "{\"path\":\"/\"}", &out, e2, sizeof(e2));
            json_envelope(&env, rc == 0, rc == 0 ? out.p : e2, NULL);
            status = rc == 0 ? 200 : err_status(e2, anon);
            rc = http_reply(h, status, "application/json", env.p, env.len, NULL);
            sb_free(&out); sb_free(&env); return rc; }
        return serve_file(h, fsepath);
    }
    if (!strcmp(h->rq.method, "PUT")) {
        uint64_t newsize = 0;
        sb_t b;
        int rc;
        char perm[16] = "";
        mode_t pm = 0640;
        if (query_get(h->rq.query, "mode", tmp, sizeof(tmp)) == 0) snprintf(mode, sizeof(mode), "%s", tmp);
        if (query_get(h->rq.query, "perm", perm, sizeof(perm)) == 0) pm = parse_perm(perm, 0640);
        if (pm == (mode_t)-1) return http_error(h, 400, "perm must be octal like 0640");
        rq_from_ctx(h, &rq);
        snprintf(rq.mname, sizeof(rq.mname), "http.put");
        rc = fse_write_core(fsepath, h->rq.body ? h->rq.body : (const uint8_t *)"", h->rq.nbody, mode, 0, pm,
                            query_get(h->rq.query, "parents", tmp, sizeof(tmp)) == 0 && tmp[0] == '1', &rq, &newsize, canon, sizeof(canon), err, sizeof(err));
        rpc_run_logged_done(&rq, "fse.write", rc == 0 ? canon : fsepath, rc, err);
        if (rc < 0) return http_error(h, err_status(err, anon), err);
        sb_init(&b);
        sb_puts(&b, "{\"path\":"); sb_json_str(&b, canon);
        sb_printf(&b, ",\"written\":%zu,\"size\":%" PRIu64 "}", h->rq.nbody, newsize);
        rc = http_reply(h, 200, "application/json", b.p, b.len, NULL);
        sb_free(&b);
        return rc;
    }
    if (!strcmp(h->rq.method, "DELETE")) {
        sb_t b;
        int rc;
        rq_from_ctx(h, &rq);
        snprintf(rq.mname, sizeof(rq.mname), "http.delete");
        rc = fse_rm_core(fsepath, query_get(h->rq.query, "recursive", tmp, sizeof(tmp)) == 0 && tmp[0] == '1', &rq, canon, sizeof(canon), err, sizeof(err));
        rpc_run_logged_done(&rq, "fse.rm", rc == 0 ? canon : fsepath, rc, err);
        if (rc < 0) return http_error(h, err_status(err, anon), err);
        sb_init(&b);
        sb_puts(&b, "{\"removed\":"); sb_json_str(&b, canon); sb_putn(&b, "}", 1);
        rc = http_reply(h, 200, "application/json", b.p, b.len, NULL);
        sb_free(&b);
        return rc;
    }
    return http_error(h, 405, "method not allowed here");
}

static int h_health(hctx_t *h) {
    char body[200];
    int n = snprintf(body, sizeof(body), "{\"status\":\"%s\",\"uptime_s\":%" PRIu64 ",\"audit_log\":\"%s\"}",
                     g_log.failed ? "degraded" : "ok", (sp_now_ms() - g_sp.start_ms) / 1000, g_log.failed ? "failing" : "ok");
    if (strcmp(h->rq.method, "GET") && strcmp(h->rq.method, "HEAD")) return http_error(h, 405, "use GET");
    return http_reply(h, g_log.failed ? 503 : 200, "application/json", body, (size_t)n, NULL);
}

static int h_metrics(hctx_t *h) {
    sb_t b;
    char why[100];
    int rc;
    size_t ready;
    if (strcmp(h->rq.method, "GET") && strcmp(h->rq.method, "HEAD")) return http_error(h, 405, "use GET");
    if (!h->caller.name[0]) return http_error(h, 401, "token required");
    if (!(h->caller.caps & SPCAP_LOGR)) return http_error(h, 403, "denied: needs cap logr");
    if (!policy_check(&h->caller, "http.GET", "/metrics", why, sizeof(why))) return http_error(h, 403, "denied by policy");
    pthread_mutex_lock(&g_sp.peers_lock);
    ready = g_sp.ready_count;
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_init(&b);
    sb_printf(&b, "le_uptime_seconds %" PRIu64 "\nle_peers_ready %zu\nle_http_requests_total %" PRIu64 "\n"
              "le_http_responses_total{class=\"2xx\"} %" PRIu64 "\nle_http_responses_total{class=\"3xx\"} %" PRIu64 "\n"
              "le_http_responses_total{class=\"4xx\"} %" PRIu64 "\nle_http_responses_total{class=\"5xx\"} %" PRIu64 "\n"
              "le_http_rate_limited_total %" PRIu64 "\nle_rpc_total %" PRIu64 "\nle_rpc_denied_total %" PRIu64 "\nle_rpc_errors_total %" PRIu64 "\n"
              "le_auth_failures_total %" PRIu64 "\nle_policy_checks_total %" PRIu64 "\nle_policy_denies_total %" PRIu64 "\n"
              "le_fse_ops_total %" PRIu64 "\nle_fse_bytes_read_total %" PRIu64 "\nle_fse_bytes_written_total %" PRIu64 "\nle_fse_exec_total %" PRIu64 "\n"
              "le_audit_entries_total %" PRIu64 "\nle_audit_failed %d\n",
              (sp_now_ms() - g_sp.start_ms) / 1000, ready, SP_LD(g_http.req_total), SP_LD(g_http.st2xx), SP_LD(g_http.st3xx), SP_LD(g_http.st4xx), SP_LD(g_http.st5xx),
              SP_LD(g_http.rate_limited), SP_LD(g_stat.rpc_total), SP_LD(g_stat.rpc_denied), SP_LD(g_stat.rpc_errors), SP_LD(g_stat.auth_fail),
              SP_LD(g_pol.checks), SP_LD(g_pol.denies), SP_LD(g_fse.ops), SP_LD(g_fse.bytes_read), SP_LD(g_fse.bytes_written), SP_LD(g_fse.exec_total),
              g_log.entries, g_log.failed ? 1 : 0);
    rc = http_reply(h, 200, "text/plain; version=0.0.4", b.p, b.len, NULL);
    sb_free(&b);
    return rc;
}

static int h_user_route(hctx_t *h, const route_t *r) {
    char why[100], act[24];
    if (!r->is_public) {
        if (!h->caller.name[0]) return http_error(h, 401, "token required");
        snprintf(act, sizeof(act), "http.%s", h->rq.method);
        if (!policy_check(&h->caller, act, h->rq.path, why, sizeof(why))) return http_error(h, 403, "denied by policy");
    }
    switch (r->type) {
    case RT_TEXT:
    case RT_JSON:
        return http_reply(h, r->status, r->ctype, r->target, strlen(r->target), NULL);
    case RT_FILE: {
        char fp[1100];
        size_t pl = strlen(r->pattern);
        if (pl >= 2 && r->pattern[pl - 1] == '*' && r->pattern[pl - 2] == '/') {
            size_t tl = strlen(r->target);
            const char *rest = h->rq.path + (pl - 1);
            if (tl && r->target[tl - 1] == '/') tl--;
            snprintf(fp, sizeof(fp), "%.*s/%s", (int)tl, r->target, rest);
        } else snprintf(fp, sizeof(fp), "%s", r->target);
        return serve_file(h, fp);
    }
    case RT_RPC: {
        const char *p = h->rq.body && *json_skip_ws((const char *)h->rq.body) == '{' ? (const char *)h->rq.body : "{}";
        return run_rpc(h, r->target, p);
    }
    }
    return http_error(h, 500, "bad route");
}

static int http_handle(hctx_t *h) {
    hreq_t *rq = &h->rq;
    route_t rt;
    h->head_only = strcmp(rq->method, "HEAD") == 0;
    if (!rate_ok(h->ip)) { SP_INC(g_http.rate_limited); return http_error(h, 429, "rate limit exceeded"); }
    http_cors(h);
    if (!strcmp(rq->method, "OPTIONS")) {
        if (rq->origin[0] && !h->cors_origin[0]) return http_error(h, 403, "origin not allowed");
        return http_reply(h, 204, "text/plain", NULL, 0, "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS\r\n");
    }
    if (http_auth(h) < 0) { SP_INC(g_http.unauthorized); return http_error(h, 401, "invalid or expired token"); }
    if (!strcmp(rq->path, "/health")) return h_health(h);
    if (!strcmp(rq->path, "/metrics")) return h_metrics(h);
    if (!strcmp(rq->path, "/rpc")) return h_rpc(h);
    if (!strncmp(rq->path, "/files", 6) && (rq->path[6] == '\0' || rq->path[6] == '/')) return h_files(h);
    if (route_find(h->head_only ? "GET" : rq->method, rq->path, &rt)) return h_user_route(h, &rt);
    return http_error(h, 404, "not found");
}

/* ── connections ───────────────────────────────────────────────────────────── */
static void http_log(hctx_t *h, uint64_t t0_us) {
    ev_t e;
    char path[220];
    snprintf(path, sizeof(path), "%.200s", h->rq.path);
    ev_begin(&e, "http");
    ev_s(&e, "ip", h->ipstr); ev_s(&e, "req", h->reqid);
    ev_s(&e, "method", h->rq.method); ev_s(&e, "path", path);
    ev_i(&e, "status", h->status); ev_u(&e, "bytes", h->bytes);
    if (h->caller.name[0]) ev_s(&e, "principal", h->caller.name);
    ev_u(&e, "dur_us", sp_now_us() - t0_us);
    le_emit(&e);
}

typedef struct { int fd; uint32_t ip; } hjob_t;

static void *http_conn_thread(void *arg) {
    hjob_t *job = (hjob_t *)arg;
    hctx_t *h = (hctx_t *)calloc(1, sizeof(*h));
    char *buf = (char *)malloc(HDR_MAX + 1);
    size_t have = 0;
    struct timeval tv = { 10, 0 };
    struct in_addr a;
    int nreq = 0;
    if (!h || !buf) goto out;
    h->fd = job->fd; h->ip = job->ip;
    a.s_addr = job->ip;
    inet_ntop(AF_INET, &a, h->ipstr, sizeof(h->ipstr));
    { int one = 1; setsockopt(h->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
    setsockopt(h->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(h->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    while (SP_IS_RUNNING() && nreq < 100) {
        uint64_t t0;
        int rc;
        unsigned char rid[8];
        int i;
        h->status = 0; h->bytes = 0; h->head_only = 0; h->more = 0;
        memset(&h->caller, 0, sizeof(h->caller));
        rc = http_read_request(h, buf, &have);
        if (rc < 0) break;
        t0 = sp_now_us();
        le_random(rid, sizeof(rid));
        for (i = 0; i < 8; i++) sprintf(h->reqid + 2 * i, "%02x", rid[i]);
        SP_INC(g_http.req_total);
        if (nreq >= 99) h->rq.keepalive = 0;            /* announce the close on the last request of a connection */
        if (rc > 0) {
            h->rq.keepalive = 0;
            http_error(h, rc, http_reason(rc));
            snprintf(h->rq.method, sizeof(h->rq.method), "?");
            stat_status(h->status);
            http_log(h, t0);
            break;
        }
        rc = http_handle(h);
        stat_status(h->status ? h->status : 500);
        http_log(h, t0);
        free(h->rq.body); h->rq.body = NULL;
        nreq++;
        if (rc < 0 || !h->rq.keepalive) break;
    }
    if (h) free(h->rq.body);
out:
    close(job->fd);
    ip_release(job->ip);
    __atomic_fetch_sub(&g_http.conns, 1, __ATOMIC_RELAXED);
    free(h); free(buf); free(job);
    return NULL;
}

static void *http_server_thread(void *arg) {
    (void)arg;
    SP_LOG("SPPServer listening on http://%s:%d", g_http.bind, g_http.port);
    while (SP_IS_RUNNING()) {
        struct pollfd pf;
        struct sockaddr_in ca;
        socklen_t al = sizeof(ca);
        int fd;
        hjob_t *job;
        pthread_t t;
        pthread_attr_t at;
        pf.fd = g_http.listen_fd; pf.events = POLLIN;
        if (poll(&pf, 1, 500) <= 0) continue;
        fd = accept4(g_http.listen_fd, (struct sockaddr *)&ca, &al, SOCK_CLOEXEC);
        if (fd < 0) continue;
        if (__atomic_load_n(&g_http.conns, __ATOMIC_RELAXED) >= g_http.max_conns || !ip_acquire(ca.sin_addr.s_addr)) {
            static const char r503[] = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\nRetry-After: 1\r\n\r\n";
            send(fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        job = (hjob_t *)malloc(sizeof(*job));
        if (!job) { close(fd); ip_release(ca.sin_addr.s_addr); continue; }
        job->fd = fd; job->ip = ca.sin_addr.s_addr;
        __atomic_fetch_add(&g_http.conns, 1, __ATOMIC_RELAXED);
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 512 * 1024);
        if (pthread_create(&t, &at, http_conn_thread, job) != 0) {
            close(fd); ip_release(job->ip); __atomic_fetch_sub(&g_http.conns, 1, __ATOMIC_RELAXED); free(job);
        }
        pthread_attr_destroy(&at);
    }
    close(g_http.listen_fd);
    return NULL;
}

static int http_start(void) {
    struct sockaddr_in addr;
    int opt = 1;
    g_http.listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_http.listen_fd < 0) { SP_ERR("http socket: %s", strerror(errno)); return -1; }
    setsockopt(g_http.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_http.port);
    if (inet_pton(AF_INET, g_http.bind, &addr.sin_addr) != 1) { SP_ERR("--http-bind: not an IPv4 address: %s", g_http.bind); return -1; }
    if (bind(g_http.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { SP_ERR("http bind %s:%d: %s", g_http.bind, g_http.port, strerror(errno)); return -1; }
    if (listen(g_http.listen_fd, 512) < 0) { SP_ERR("http listen: %s", strerror(errno)); return -1; }
    if (g_http.port == 0) { socklen_t l = sizeof(addr); getsockname(g_http.listen_fd, (struct sockaddr *)&addr, &l); g_http.port = ntohs(addr.sin_port); }
    if (strcmp(g_http.bind, "127.0.0.1") != 0) SP_WARN("SPPServer is bound to %s without TLS: API tokens travel in clear text; put a TLS proxy in front", g_http.bind);
    return pthread_create(&g_http.thread, NULL, http_server_thread, NULL) == 0 ? 0 : -1;
}


/* ── terminal (the administrator; never subject to policy) ─────────────────── */
static void le_terminal_loop(void) {
    static char line[70000];
    SP_LOG("LocalEnterprise terminal ready. Type 'help' for commands.");
    printf("\n\033[1;36mlocalenterprise>\033[0m ");
    fflush(stdout);
    while (SP_IS_RUNNING() && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  help                 this message\n");
            printf("  status               ports, peers, policy, log, FSE\n");
            printf("  peers                list connected peers (first 50)\n");
            printf("  rpc <method> [json]  call any API as the administrator, e.g. rpc rpc.methods\n");
            printf("                       rpc server.token.add {\"name\":\"alice\",\"caps\":\"fsr,fsw\",\"role\":\"dev\"}\n");
            printf("                       rpc policy.rule.add {\"effect\":\"allow\",\"who\":\"role:dev\",\"action\":\"fse.*\",\"resource\":\"/projects/**\"}\n");
            printf("  logverify [file]     check the audit log's hash chain\n");
            printf("  loghead              print the audit log's seq and head hash (record it somewhere safe)\n");
            printf("  stop                 shut down\n");
        } else if (strcmp(line, "status") == 0) {
            size_t ready;
            pthread_mutex_lock(&g_sp.peers_lock);
            ready = g_sp.ready_count;
            pthread_mutex_unlock(&g_sp.peers_lock);
            printf("SPP port:   %d   peers %zu / %zu   default caps 0x%02x\n", g_sp.port, ready, g_sp.max_peers, g_sp.default_caps);
            if (g_http.enabled) printf("SPPServer:  http://%s:%d   rate %d/s per IP   %d routes\n", g_http.bind, g_http.port, g_http.rate, ({ int c = 0, i; for (i = 0; i < HTTP_MAX_ROUTES; i++) c += g_http.routes[i].used; c; }));
            else printf("SPPServer:  disabled\n");
            printf("SPPPolicyE: %d rule(s), default %s, mode %s%s\n", g_pol.n, g_pol.def_allow ? "allow" : "deny", g_pol.audit_only ? "audit" : "enforce", g_pol.lockdown ? ", LOCKDOWN" : "");
            printf("SPPLogE:    %s   seq %" PRIu64 "   %s\n", g_log.path, g_log.seq, g_log.failed ? "\033[31mFAILING\033[0m" : "ok");
            printf("FSE:        %s   exec %s\n", g_fse.ready ? g_fse.root : "off", g_fse.exec_enabled ? "ENABLED" : "disabled");
        } else if (strcmp(line, "peers") == 0) {
            size_t i, shown = 0, total;
            pthread_mutex_lock(&g_sp.peers_lock);
            total = g_sp.ready_count;
            for (i = 0; i < g_sp.peer_hi && shown < 50; i++) {
                spp_peer_t *p = &g_sp.peers[i];
                char ip[INET_ADDRSTRLEN];
                struct in_addr a;
                if (!p->active) continue;
                a.s_addr = p->addr;
                inet_ntop(AF_INET, &a, ip, sizeof(ip));
                printf("  conn=%" PRIu64 " %s %s principal=%s role=%s caps=0x%02x\n", p->conn_id, ip, p->spmention, p->principal[0] ? p->principal : "-", p->role[0] ? p->role : "-", sp_caps_get(p));
                shown++;
            }
            pthread_mutex_unlock(&g_sp.peers_lock);
            if (!total) printf("  no peers connected\n");
            else if (total > shown) printf("  ... and %zu more (rpc peer.list pages through all)\n", total - shown);
        } else if (strncmp(line, "rpc", 3) == 0 && (line[3] == ' ' || line[3] == '\0')) {
            char *m = line + 3, *params;
            while (*m == ' ') m++;
            params = m;
            while (*params && *params != ' ') params++;
            if (*params) { *params++ = '\0'; while (*params == ' ') params++; }
            if (!*m) printf("usage: rpc <method> [json-params]   (try: rpc rpc.methods)\n");
            else {
                sb_t out;
                char err[240] = "";
                sb_init(&out);
                if (rpc_call_terminal(m, *params ? params : "{}", &out, err, sizeof(err)) == 0) printf("%s\n", out.p ? out.p : "null");
                else printf("\033[31merror:\033[0m %s\n", err);
                sb_free(&out);
            }
        } else if (strncmp(line, "logverify", 9) == 0 && (line[9] == ' ' || line[9] == '\0')) {
            sb_t out;
            char path[400];
            const char *f = line + 9;
            ev_t e;
            while (*f == ' ') f++;
            snprintf(path, sizeof(path), "%s", *f ? f : g_log.path);
            ev_begin(&e, "terminal"); ev_s(&e, "cmd", "logverify"); ev_s(&e, "file", path); le_emit(&e);
            sb_init(&out);
            le_log_verify(path, NULL, *f ? 0 : g_log.size, &out);
            printf("%s\n", out.p);
            sb_free(&out);
        } else if (strcmp(line, "loghead") == 0) {
            pthread_mutex_lock(&g_log.lock);
            printf("seq %" PRIu64 "  head %s\n", g_log.seq, g_log.head);
            pthread_mutex_unlock(&g_log.lock);
        } else if (strcmp(line, "stop") == 0) {
            SP_ST(g_sp.running, 0);
            break;
        } else if (strlen(line) > 0) {
            printf("unknown command (type 'help')\n");
        }
        printf("\n\033[1;36mlocalenterprise>\033[0m ");
        fflush(stdout);
    }
}

static void on_signal(int sig) { (void)sig; SP_ST(g_sp.running, 0); }

static void le_usage(void) {
    printf("LocalEnterprise " LE_VERSION " (SPPLogE / SPPServer / SPPPolicyE / FSE)\n\n");
    printf("Usage: localenterprise [options]\n\n");
    printf("  --state-dir <d>        policy, tokens and audit log live here (default ./le_state, mode 0700)\n");
    printf("  --port <n>             SPP listen port (default %d)\n", SPP_DEFAULT_PORT);
    printf("  --max-peers <n>        peer table size (default %d; needs ulimit -n above n)\n", SPP_MAX_PEERS);
    printf("  --default-caps <mask>  caps a new SPP peer starts with, e.g. 0 or \"fsr\" (default 0)\n");
    printf("  --fse-root <d>         the enterprise root FSE works in (default ./enterprise_root; created if missing)\n");
    printf("  --fse-exec             allow fse.exec (off by default; programs run as this process's user)\n");
    printf("  --fse-max-mb <n>       largest file FSE reads/writes/copies (default 256)\n");
    printf("  --http-port <n>        SPPServer port (default 5223, 0 = pick one)\n");
    printf("  --http-bind <ip>       SPPServer address (default 127.0.0.1)\n");
    printf("  --no-http              do not start SPPServer\n");
    printf("  --http-rate <n>        requests per second per IP, burst 2n (default 50, 0 = off)\n");
    printf("  --http-max-body-mb <n> largest request body (default 8)\n");
    printf("  --http-max-conns <n>   concurrent connections (default 256) / --http-per-ip <n> (default 32)\n");
    printf("  --http-cors <origin>   allow a browser origin (repeatable, or *)\n");
    printf("  --policy-default <d>   allow | deny (default deny)\n");
    printf("  --policy-mode <m>      enforce | audit (default enforce; audit logs would-be denials and allows)\n");
    printf("  --log-file <f>         audit log path (default <state-dir>/audit.log)\n");
    printf("  --log-max-mb <n>       rotate the audit log at this size (default 64)\n");
    printf("  --log-sync             fdatasync after every entry (default: once a second)\n");
    printf("  --log-fail-open        keep serving if the audit log cannot be written (default: deny everything)\n");
    printf("  --no-terminal          no interactive terminal; run until SIGINT/SIGTERM\n");
    printf("  --verify-log <f>       verify an audit log's hash chain and exit (with --expect-head <sha256>)\n");
    printf("  --verbose --help\n\n");
}

static int path_inside(const char *a, const char *b) {   /* is a equal to or below b? */
    size_t lb = strlen(b);
    if (strncmp(a, b, lb) != 0) return 0;
    return a[lb] == '\0' || a[lb] == '/' || (lb > 0 && b[lb - 1] == '/');
}

int main(int argc, char *argv[]) {
    int i, no_terminal = 0, have_log_file = 0;
    char state_dir[300] = "./le_state", fse_root[300] = "./enterprise_root", verify_file[300] = "", expect_head[80] = "";
    char log_file[330] = "", real_state[PATH_MAX], real_root[PATH_MAX], real_log[PATH_MAX];
    uint64_t log_max = 64u << 20;
    ev_t e;

    g_sp.port = SPP_DEFAULT_PORT;
    g_sp.running = 1;
    g_sp.max_peers = SPP_MAX_PEERS;
    g_sp.epfd = -1;
    g_pol.def_allow = 0;

    for (i = 1; i < argc; i++) {
#define ARG(name) (strcmp(argv[i], name) == 0 && i + 1 < argc)
        if (ARG("--port")) g_sp.port = atoi(argv[++i]);
        else if (ARG("--max-peers")) { long v = atol(argv[++i]); if (v < 1) v = 1; if (v > SPP_MAX_PEERS_HARD) v = SPP_MAX_PEERS_HARD; g_sp.max_peers = (size_t)v; }
        else if (ARG("--default-caps")) { if (parse_caps_str(argv[++i], &g_sp.default_caps) < 0) { fprintf(stderr, "--default-caps: bad value\n"); return 1; } }
        else if (ARG("--state-dir")) snprintf(state_dir, sizeof(state_dir), "%s", argv[++i]);
        else if (ARG("--fse-root")) snprintf(fse_root, sizeof(fse_root), "%s", argv[++i]);
        else if (strcmp(argv[i], "--fse-exec") == 0) g_fse.exec_enabled = 1;
        else if (ARG("--fse-max-mb")) { long v = atol(argv[++i]); if (v < 1 || v > 65536) { fprintf(stderr, "--fse-max-mb: 1..65536\n"); return 1; } g_fse.max_file = (uint64_t)v << 20; }
        else if (ARG("--http-port")) g_http.port = atoi(argv[++i]);
        else if (ARG("--http-bind")) snprintf(g_http.bind, sizeof(g_http.bind), "%s", argv[++i]);
        else if (strcmp(argv[i], "--no-http") == 0) g_http.enabled = 0;
        else if (ARG("--http-rate")) g_http.rate = atoi(argv[++i]);
        else if (ARG("--http-max-body-mb")) { long v = atol(argv[++i]); if (v < 1 || v > 1024) { fprintf(stderr, "--http-max-body-mb: 1..1024\n"); return 1; } g_http.max_body = (uint64_t)v << 20; }
        else if (ARG("--http-max-conns")) g_http.max_conns = atoi(argv[++i]);
        else if (ARG("--http-per-ip")) g_http.per_ip = atoi(argv[++i]);
        else if (ARG("--http-cors")) { if (g_http.ncors < 8) snprintf(g_http.cors[g_http.ncors++], 200, "%s", argv[i + 1]); i++; }
        else if (ARG("--policy-default")) {
            i++;
            if (strcmp(argv[i], "allow") == 0) g_pol.def_allow = 1; else if (strcmp(argv[i], "deny") == 0) g_pol.def_allow = 0;
            else { fprintf(stderr, "--policy-default: allow or deny\n"); return 1; }
        } else if (ARG("--policy-mode")) {
            i++;
            if (strcmp(argv[i], "audit") == 0) g_pol.audit_only = 1; else if (strcmp(argv[i], "enforce") == 0) g_pol.audit_only = 0;
            else { fprintf(stderr, "--policy-mode: enforce or audit\n"); return 1; }
        } else if (ARG("--log-file")) { if (strlen(argv[i + 1]) > 300) { fprintf(stderr, "--log-file path too long\n"); return 1; } snprintf(log_file, sizeof(log_file), "%s", argv[++i]); have_log_file = 1; }
        else if (ARG("--log-max-mb")) { long v = atol(argv[++i]); if (v < 1 || v > 65536) { fprintf(stderr, "--log-max-mb: 1..65536\n"); return 1; } log_max = (uint64_t)v << 20; }
        else if (strcmp(argv[i], "--log-sync") == 0) g_log.sync_each = 1;
        else if (strcmp(argv[i], "--log-fail-open") == 0) g_log.fail_closed = 0;
        else if (strcmp(argv[i], "--no-terminal") == 0) no_terminal = 1;
        else if (ARG("--verify-log")) snprintf(verify_file, sizeof(verify_file), "%s", argv[++i]);
        else if (ARG("--expect-head")) snprintf(expect_head, sizeof(expect_head), "%s", argv[++i]);
        else if (strcmp(argv[i], "--verbose") == 0) g_sp.verbose = 1;
        else if (strcmp(argv[i], "--help") == 0) { le_usage(); return 0; }
        else { fprintf(stderr, "unknown or incomplete option: %s (try --help)\n", argv[i]); return 1; }
#undef ARG
    }

    if (verify_file[0]) {                         /* offline verification */
        sb_t out;
        int rc;
        if (expect_head[0] && !hex64_ok(expect_head)) { fprintf(stderr, "--expect-head must be 64 hex characters\n"); return 2; }
        sb_init(&out);
        rc = le_log_verify(verify_file, expect_head, 0, &out);
        printf("%s\n", out.p);
        return rc == 0 ? 0 : 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);                     /* a full / limited disk must surface as a write error, not a kill */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    g_sp.start_ms = sp_now_ms();

    /* state directory, audit log */
    if (mkdir(state_dir, 0700) < 0 && errno != EEXIST) { SP_ERR("state dir %s: %s", state_dir, strerror(errno)); return 1; }
    if (!realpath(state_dir, real_state)) { SP_ERR("state dir: %s", strerror(errno)); return 1; }
    if (strlen(real_state) > 240 || strlen(state_dir) > 290) { SP_ERR("state directory path is too long"); return 1; }
    if (!have_log_file) snprintf(log_file, sizeof(log_file), "%s/audit.log", real_state);
    snprintf(g_pol.file, sizeof(g_pol.file), "%s/policy.db", real_state);
    snprintf(g_tok_file, sizeof(g_tok_file), "%s/tokens.db", real_state);

    /* FSE root, kept apart from the state directory so files can never touch the audit trail */
    if (mkdir(fse_root, 0750) < 0 && errno != EEXIST) { SP_ERR("fse root %s: %s", fse_root, strerror(errno)); return 1; }
    if (!realpath(fse_root, real_root)) { SP_ERR("fse root: %s", strerror(errno)); return 1; }
    {
        char logdir[330], *sl;
        snprintf(logdir, sizeof(logdir), "%s", log_file);
        sl = strrchr(logdir, '/');
        if (sl) *sl = '\0'; else snprintf(logdir, sizeof(logdir), ".");
        if (!realpath(logdir, real_log)) { SP_ERR("log directory %s: %s", logdir, strerror(errno)); return 1; }
    }
    if (path_inside(real_state, real_root) || path_inside(real_root, real_state) || path_inside(real_log, real_root) || path_inside(real_root, real_log)) {
        SP_ERR("the FSE root (%s) and the state / log directories (%s, %s) must not contain each other", real_root, real_state, real_log);
        return 1;
    }
    snprintf(g_fse.root, sizeof(g_fse.root), "%s", real_root);
    g_fse.root_fd = open(real_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_fse.root_fd < 0) { SP_ERR("open fse root: %s", strerror(errno)); return 1; }
    g_fse.ready = 1;
    if (g_fse.exec_enabled && geteuid() == 0) SP_WARN("fse.exec is enabled and this process runs as root: executed programs get root. Run LocalEnterprise as an unprivileged user.");

    if (le_log_start(log_file, log_max) < 0) { SP_ERR("cannot open the audit log %s: %s", log_file, strerror(errno)); return 1; }
    pol_load();
    tok_load();
    sp_gen_mention(g_sp.spmention, sizeof(g_sp.spmention));
    SP_LOG("LocalEnterprise " LE_VERSION "  %s", g_sp.spmention);
    SP_LOG("SPPLogE: %s (seq %" PRIu64 ")   FSE root: %s   exec %s   policy default %s%s",
           log_file, g_log.seq, g_fse.root, g_fse.exec_enabled ? "ON" : "off", g_pol.def_allow ? "allow" : "deny", g_pol.audit_only ? " (audit mode)" : "");
    ev_begin(&e, "server.start");
    ev_s(&e, "version", LE_VERSION); ev_u(&e, "spp_port", (uint64_t)g_sp.port); ev_u(&e, "http_port", g_http.enabled ? (uint64_t)g_http.port : 0);
    ev_s(&e, "fse_root", g_fse.root); ev_b(&e, "exec", g_fse.exec_enabled); ev_s(&e, "policy_default", g_pol.def_allow ? "allow" : "deny");
    ev_s(&e, "policy_mode", g_pol.audit_only ? "audit" : "enforce"); ev_u(&e, "rules", (uint64_t)g_pol.n); ev_u(&e, "default_caps", g_sp.default_caps);
    ev_u(&e, "pid", (uint64_t)getpid());
    le_emit(&e);

    /* SPP engine: fd limit, peer table, epoll, listener */
    {
        struct rlimit rl;
        size_t k;
        struct sockaddr_in addr = {0};
        int opt = 1;
        spp_crc32_build_table();
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rlim_t want = (rlim_t)g_sp.max_peers + 128 + (rlim_t)g_http.max_conns;
            if (rl.rlim_cur < want) {
                rl.rlim_cur = (want > rl.rlim_max) ? rl.rlim_max : want;
                setrlimit(RLIMIT_NOFILE, &rl);
                getrlimit(RLIMIT_NOFILE, &rl);
            }
            if ((rlim_t)g_sp.max_peers + 128 + (rlim_t)g_http.max_conns > rl.rlim_cur) {
                size_t reserve = 128 + (size_t)g_http.max_conns;
                size_t cap = rl.rlim_cur > reserve ? (size_t)rl.rlim_cur - reserve : 1;
                SP_WARN("RLIMIT_NOFILE is %llu: capping max peers %zu -> %zu (raise it with ulimit -n)", (unsigned long long)rl.rlim_cur, g_sp.max_peers, cap);
                g_sp.max_peers = cap;
            }
        }
        g_sp.peers      = (spp_peer_t *)calloc(g_sp.max_peers, sizeof(spp_peer_t));
        g_sp.free_slots = (uint32_t *)malloc(g_sp.max_peers * sizeof(uint32_t));
        if (!g_sp.peers || !g_sp.free_slots) { SP_ERR("out of memory for %zu peer slots", g_sp.max_peers); return 1; }
        for (k = 0; k < g_sp.max_peers; k++) g_sp.free_slots[k] = (uint32_t)(g_sp.max_peers - 1 - k);
        g_sp.free_top = g_sp.max_peers;
        pthread_mutex_init(&g_sp.peers_lock, NULL);
        g_sp.epfd = epoll_create1(EPOLL_CLOEXEC);
        if (g_sp.epfd < 0) { SP_ERR("epoll_create1: %s", strerror(errno)); return 1; }

        g_sp.server_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (g_sp.server_sock < 0) { SP_ERR("socket: %s", strerror(errno)); return 1; }
        setsockopt(g_sp.server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((uint16_t)g_sp.port);
        if (bind(g_sp.server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { SP_ERR("bind %d: %s", g_sp.port, strerror(errno)); return 1; }
        if (listen(g_sp.server_sock, 4096) < 0) { SP_ERR("listen: %s", strerror(errno)); return 1; }
        {
            struct epoll_event ev;
            fcntl(g_sp.server_sock, F_SETFL, fcntl(g_sp.server_sock, F_GETFL, 0) | O_NONBLOCK);
            ev.events = EPOLLIN;
            ev.data.u64 = UINT64_MAX;
            epoll_ctl(g_sp.epfd, EPOLL_CTL_ADD, g_sp.server_sock, &ev);
        }
        SP_LOG("peer table: %zu slots", g_sp.max_peers);
    }

    pthread_create(&g_sp.server_thread, NULL, spp_server_thread, NULL);
    if (g_http.enabled && http_start() < 0) { SP_ERR("SPPServer failed to start"); SP_ST(g_sp.running, 0); g_http.enabled = 0; }

    if (no_terminal || !isatty(0)) {
        if (!no_terminal) SP_LOG("stdin is not a terminal: reading commands from it (EOF stops the server; use --no-terminal to run as a daemon)");
        if (no_terminal) while (SP_IS_RUNNING()) sleep(1);
        else le_terminal_loop();
    } else le_terminal_loop();

    SP_ST(g_sp.running, 0);
    SP_LOG("shutting down...");
    pthread_join(g_sp.server_thread, NULL);
    if (g_http.enabled) {
        int w;
        pthread_join(g_http.thread, NULL);
        for (w = 0; w < 40 && __atomic_load_n(&g_http.conns, __ATOMIC_RELAXED) > 0; w++) usleep(50000);
    }
    sp_close_socket(g_sp.server_sock);
    ev_begin(&e, "server.stop"); ev_u(&e, "uptime_s", (sp_now_ms() - g_sp.start_ms) / 1000); ev_u(&e, "audit_entries", g_log.entries);
    le_emit(&e);
    pthread_mutex_lock(&g_log.lock);
    if (g_log.fd >= 0) { fdatasync(g_log.fd); close(g_log.fd); g_log.fd = -1; }
    pthread_mutex_unlock(&g_log.lock);
    return 0;
}
