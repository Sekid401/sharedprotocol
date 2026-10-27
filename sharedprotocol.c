/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Sekid
 * Licensed under the MIT License; see the LICENSE file for the full text.
 */

/*
 * sharedprotocol.c — SharedProtocol Terminal App v1.1.0
 *
 * Single-file C implementation of the SharedProtocol runtime.
 * Boots SPP, launches headless Chromium, bridges to SP in the browser,
 * runs host daemons (SPAI, SPRegistry, SPReport, SPPolicy, SP-CRON, SharedWorkers).
 *
 * Build:
 *   Linux/Android:  gcc -o sharedprotocol sharedprotocol.c -lpthread -lm -ldl
 *   Windows:        cl sharedprotocol.c ws2_32.lib
 *
 * Usage:
 *   sharedprotocol               — start with defaults
 *   sharedprotocol --port 5221   — custom SPP port
 *   sharedprotocol --no-browser  — SPP + daemons only, no headless browser
 *   sharedprotocol --spc <file>  — run a .spc script on host and exit
 *   sharedprotocol --max-peers N — peer table size (default 131072; needs ulimit -n > N)
 *   sharedprotocol --default-caps 0xEF — capabilities new peers start with (default 0)
 *   sharedprotocol --bridge-origin <o> — extra web origin allowed on the bridge
 *   sharedprotocol --bridge-token <t>  (fixed bridge token; default: random per run)
 *   sharedprotocol --chromium-no-sandbox  (pass --no-sandbox to Chromium)
 *   sharedprotocol --drivers-dir <dir>    (where SPP drivers live; default ./sp_drivers)
 *   sharedprotocol --browser-used <b>     (chromium (default) | chrome | firefox | brave)
 *   sharedprotocol --site-used <site>     (open this site instead of the built-in bootstrap page; only it may use the bridge)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* ── Platform detection ────────────────────────────────────────────────────── */
#if defined(_WIN32) || defined(_WIN64)
  #define SP_PLATFORM_WINDOWS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <process.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET sp_socket_t;
  #define SP_INVALID_SOCKET INVALID_SOCKET
  #define sp_close_socket(s) closesocket(s)
  #define SP_PATH_SEP "\\"
#elif defined(__ANDROID__)
  #define SP_PLATFORM_ANDROID
  #define SP_PLATFORM_UNIX
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <pthread.h>
  #include <sys/wait.h>
  typedef int sp_socket_t;
  #define SP_INVALID_SOCKET (-1)
  #define sp_close_socket(s) close(s)
  #define SP_PATH_SEP "/"
#else
  #define SP_PLATFORM_LINUX
  #define SP_PLATFORM_UNIX
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <pthread.h>
  #include <sys/wait.h>
  typedef int sp_socket_t;
  #define SP_INVALID_SOCKET (-1)
  #define sp_close_socket(s) close(s)
  #define SP_PATH_SEP "/"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <strings.h>
#if defined(__linux__)
  #include <sys/prctl.h>
  #include <sys/syscall.h>
#endif
#ifdef SP_PLATFORM_UNIX
  #include <fcntl.h>
  #include <dlfcn.h>
  #include <dirent.h>
  #include <ftw.h>
  #include <sys/stat.h>
  #include <sys/epoll.h>
  #include <sys/resource.h>
#endif

/* ── SPP Constants ─────────────────────────────────────────────────────────── */
#define SPP_VERSION         0x0101   /* v1.1 (adds SPP_RPC / SPP_RPC_RESULT) */
#define SPP_MAGIC           "\x53\x50\x50\x01"  /* "SPP\x01" */
#define SPP_MAGIC_LEN       4
#define SPP_DEFAULT_PORT    5221
#define SPP_BRIDGE_PORT     5222     /* local WebSocket bridge to headless browser */
#define SPP_MAX_PEERS       131072   /* default peer ceiling, change at runtime with --max-peers */
#define SPP_MAX_PAYLOAD     65536
#define SPP_RETRANSMIT_MS   500
#define SPP_MAX_RETRIES     5
#define SPP_TIMEOUT_MS      5000
#define SPP_PING_INTERVAL   30000   /* ms between keepalive pings */

/* ── SPP Message Types ─────────────────────────────────────────────────────── */
#define SPP_CONNECT         0x0001
#define SPP_CONNECT_ACK     0x0002
#define SPP_DATA            0x0003
#define SPP_CLOSE           0x0004
#define SPP_PING            0x0005
#define SPP_PONG            0x0006
#define SPP_DELEGATE_HOST   0x0007
#define SPP_DELEGATE_BRW    0x0008
#define SPP_ERROR           0x0009
#define SPP_DAEMON_START    0x000A
#define SPP_DAEMON_STOP     0x000B
#define SPP_IO_INPUT        0x000C  /* terminal input → SP */
#define SPP_IO_OUTPUT       0x000D  /* SP output → terminal */
#define SPP_SPC_RUN         0x000E  /* run .spc on host */
#define SPP_SPC_RESULT      0x000F  /* .spc result */
#define SPP_RPC             0x0010  /* JSON request: {"id":N,"method":"..","params":{..}} */
#define SPP_RPC_RESULT      0x0011  /* JSON reply:   {"id":N,"ok":true,"result":..} | {"id":N,"ok":false,"error":".."} */

/* relaxed atomics for flags/counters shared between threads */
#define SP_LD(x)        __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define SP_ST(x, v)     __atomic_store_n(&(x), (v), __ATOMIC_RELAXED)
#define SP_IS_RUNNING() SP_LD(g_sp.running)

/* ── SPP v1.1 engine limits ────────────────────────────────────────────────── */
#define SPP_MAX_PEERS_HARD  1048576
#define SPP_HS_MAX_PAYLOAD  1024              /* CONNECT is tiny; bounds memory of half-open peers */
#define SPP_HS_TIMEOUT_MS   5000              /* drop peers that do not finish the handshake */
#define SPP_TX_CAP          (1u << 20)        /* per-peer send queue cap; slower consumers are dropped */
#define SPP_TX_TOTAL_CAP    ((size_t)256 << 20) /* all peers together; over this, backlogged peers (> SPP_TX_FAIR) are dropped */
#define SPP_TX_FAIR         (16u << 10)       /* a queue this small is never dropped for the global budget */
#define SPP_RX_BUDGET       (256u << 20)      /* total bytes buffered for partial messages */
#define SPP_RPC_PENDING     4096              /* in-flight requests forwarded to the JS layer */
#define SPP_RPC_TIMEOUT_MS  10000
#define SP_BASE_ID          5221              /* host UID; peer UID = SP_BASE_ID + conn id (matches SP_BASE_ID in sharedprotocol.js) */

/* ── SP capability bits — identical values to the JS runtime ───────────────── */
#define SPCAP_PID           0x01   /* start/stop daemons */
#define SPCAP_UID           0x02   /* kick peers */
#define SPCAP_GID           0x04
#define SPCAP_OP            0x08   /* shared memory, spc.run, forwarding data to the bridge */
#define SPCAP_JS            0x10   /* JS-layer APIs forwarded to the browser: spmem.*, audit.*, time.*, ... */
#define SPCAP_POLICY        0x20   /* grant / revoke capabilities */
#define SPCAP_MOVE          0x40
#define SPCAP_FS            0x80   /* fs.* (served by the JS layer, never the host disk) */
#define SPCAP_ALL           (SPCAP_PID | SPCAP_UID | SPCAP_GID | SPCAP_OP | SPCAP_JS | SPCAP_POLICY | SPCAP_MOVE | SPCAP_FS)

/* ── Daemon IDs ────────────────────────────────────────────────────────────── */
#define SP_DAEMON_SPAI      0x01
#define SP_DAEMON_REGISTRY  0x02
#define SP_DAEMON_REPORT    0x03
#define SP_DAEMON_POLICY    0x04
#define SP_DAEMON_CRON      0x05
#define SP_DAEMON_WORKER    0x06
#define SP_DAEMON_MAX       6

/* ── SPP Packet ────────────────────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];       /* SPP\x01 */
    uint16_t msg_type;
    uint32_t payload_len;
    uint64_t seq;
    uint64_t timestamp_ms;
    /* payload follows */
    /* uint32_t crc32 after payload */
} spp_header_t;
#pragma pack(pop)

#define SPP_HEADER_SIZE     sizeof(spp_header_t)  /* 26 bytes: 4+2+4+8+8 */
#define SPP_CRC_SIZE        4

/* ── SPP Peer ──────────────────────────────────────────────────────────────── */
typedef struct {
    sp_socket_t  sock;
    char         spmention[64];
    char         session_id[37];  /* UUID */
    uint64_t     seq_local;
    uint64_t     seq_remote;
    uint8_t      caps;            /* bitmask: 0x01=browser 0x02=daemon 0x04=host 0x08=mesh */
    int          active;          /* 1 once the SPP handshake is done */
    time_t       last_ping;
    /* v1.1 */
    uint64_t     conn_id;         /* unique per connection, never reused */
    uint8_t      hs;              /* 1 = TCP accepted, handshake pending */
    uint8_t      sp_caps;         /* SPCAP_* bits granted to this peer */
    uint8_t      want_out;        /* EPOLLOUT armed (send queue non-empty) */
    uint32_t     addr;            /* IPv4, network order */
    uint64_t     connected_ms, last_rx_ms, ping_sent_ms, next_ping_ms;
    uint32_t     rtt_ms;
    uint8_t     *rx;  size_t rx_len;               /* partial inbound message */
    uint8_t     *tx;  size_t tx_len, tx_off;       /* queued outbound bytes */
} spp_peer_t;

/* ── Daemon State ──────────────────────────────────────────────────────────── */
typedef struct {
    int      id;
    char     name[32];
    int      running;
    char     spc_path[256];  /* path to .spc script for this daemon */
    uint64_t start_time;
    int      restart_count;
    volatile int alive;        /* thread is running (running=0 means stopping) */
    volatile int restart_req;  /* sp.daemon.restart */
} sp_daemon_t;

/* ── Global State ──────────────────────────────────────────────────────────── */
static struct {
    sp_socket_t   server_sock;
    sp_socket_t   bridge_sock;    /* bridge to headless browser */
    spp_peer_t   *peers;          /* heap array, max_peers slots */
    size_t        max_peers, peer_hi, peer_count, ready_count;
    uint32_t     *free_slots;     /* stack of free slot indexes */
    size_t        free_top;
    uint64_t      next_conn_id, bcast_seq, rx_buffered;
    uint8_t       default_caps;   /* caps for new peers */
    uint8_t       bridge_caps;    /* caps for calls coming from the browser */
    uint32_t      bridge_rtt_ms;
    int           epfd;
    char          bridge_origin[128];
    sp_daemon_t   daemons[SP_DAEMON_MAX];
    int           running;
    int           port;
    int           bridge_port;
    char          spmention[64];
    int           no_browser;
    char          spc_file[256];  /* --spc mode */
    int           spc_mode;
    char          chromium_bin[256];
    char          bridge_token[33];   /* shared secret the browser must present on the bridge */
    int           chromium_no_sandbox;
    char          drivers_dir[256];     /* SPP drivers (the one place the host disk is written) */
    char          browser_kind[16];     /* chromium | chrome | firefox | brave */
    char          site_url[512];        /* --site-used: normalised launch URL (no fragment) */
    char          site_origin[300];     /* ...and the only web origin the bridge accepts */
    char          ff_profile[64];       /* throw-away Firefox profile dir (removed at exit) */
#ifdef SP_PLATFORM_UNIX
    pid_t         browser_pid;
    pthread_t     server_thread;
    pthread_t     bridge_thread;
    pthread_t     daemon_threads[SP_DAEMON_MAX];
    pthread_mutex_t peers_lock;
    pthread_mutex_t bridge_tx_lock;
    pthread_t     io_thread;
#endif
    int           verbose;
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

/* ── Logging ───────────────────────────────────────────────────────────────── */
static void sp_log(const char *level, const char *fmt, ...) {
    va_list ap;
    time_t t = time(NULL);
    struct tm tmbuf, *tm = &tmbuf;
#ifdef SP_PLATFORM_WINDOWS
    localtime_s(&tmbuf, &t);
#else
    localtime_r(&t, &tmbuf);
#endif
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
    fprintf(stderr, "[%s] [SP/%s] ", timebuf, level);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define SP_LOG(fmt, ...)  sp_log("INFO",  fmt, ##__VA_ARGS__)
#define SP_WARN(fmt, ...) sp_log("WARN",  fmt, ##__VA_ARGS__)
#define SP_ERR(fmt, ...)  sp_log("ERROR", fmt, ##__VA_ARGS__)
#define SP_DBG(fmt, ...)  do { if (g_sp.verbose) sp_log("DBG", fmt, ##__VA_ARGS__); } while(0)

/* ── UUID generation ───────────────────────────────────────────────────────── */
static void sp_gen_uuid(char *out) {
    /* Simple pseudo-UUID using rand — good enough for session IDs */
    {
        static int seeded = 0;
        if (!seeded) {
            unsigned seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)out;
#ifdef SP_PLATFORM_UNIX
            FILE *rf = fopen("/dev/urandom", "rb");
            if (rf) { unsigned r; if (fread(&r, sizeof(r), 1, rf) == 1) seed ^= r; fclose(rf); }
            seed ^= (unsigned)getpid() << 16;
#endif
            srand(seed);
            seeded = 1;
        }
    }
    snprintf(out, 37,
        "%08x-%04x-4%03x-%04x-%08x%04x",
        rand() & 0xFFFFFFFF,
        rand() & 0xFFFF,
        rand() & 0x0FFF,
        (rand() & 0x3FFF) | 0x8000,
        rand() & 0xFFFFFFFF,
        rand() & 0xFFFF);
}

/* ── Timestamp ─────────────────────────────────────────────────────────────── */
static uint64_t sp_now_ms(void) {
#ifdef SP_PLATFORM_WINDOWS
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

/* ── SPP Packet build/send ─────────────────────────────────────────────────── */
static int spp_send(sp_socket_t sock, uint16_t msg_type, uint64_t seq,
                    const uint8_t *payload, uint32_t payload_len) {
    uint8_t  buf[SPP_HEADER_SIZE + SPP_MAX_PAYLOAD + SPP_CRC_SIZE];
    spp_header_t *hdr = (spp_header_t *)buf;
    uint32_t crc;
    size_t   total;
    ssize_t  sent;

    if (payload_len > SPP_MAX_PAYLOAD) {
        SP_ERR("spp_send: payload too large (%u)", payload_len);
        return -1;
    }

    memcpy(hdr->magic, SPP_MAGIC, SPP_MAGIC_LEN);
    hdr->msg_type    = msg_type;
    hdr->payload_len = payload_len;
    hdr->seq         = seq;
    hdr->timestamp_ms = sp_now_ms();

    if (payload && payload_len > 0)
        memcpy(buf + SPP_HEADER_SIZE, payload, payload_len);

    crc = spp_crc32(buf, SPP_HEADER_SIZE + payload_len);
    memcpy(buf + SPP_HEADER_SIZE + payload_len, &crc, SPP_CRC_SIZE);

    total = SPP_HEADER_SIZE + payload_len + SPP_CRC_SIZE;

#ifdef SP_PLATFORM_WINDOWS
    sent = send(sock, (const char *)buf, (int)total, 0);
#else
    sent = send(sock, buf, total, MSG_NOSIGNAL);
#endif

    if (sent < 0) {
        SP_ERR("spp_send: send() failed: %s", strerror(errno));
        return -1;
    }
    SP_DBG("spp_send: type=0x%04x seq=%llu len=%u", msg_type, (unsigned long long)seq, payload_len);
    return 0;
}

/* ── SPP Packet receive ────────────────────────────────────────────────────── */
static int spp_recv(sp_socket_t sock, spp_header_t *hdr_out,
                    uint8_t *payload_out, uint32_t *payload_len_out) {
    uint8_t  raw[SPP_HEADER_SIZE + SPP_MAX_PAYLOAD + SPP_CRC_SIZE];
    ssize_t  n;
    uint32_t crc_recv, crc_calc;
    spp_header_t *hdr;

#ifdef SP_PLATFORM_WINDOWS
    n = recv(sock, (char *)raw, SPP_HEADER_SIZE, 0);
#else
    n = recv(sock, raw, SPP_HEADER_SIZE, MSG_WAITALL);
#endif
    if (n <= 0) return -1;
    if (n < (ssize_t)SPP_HEADER_SIZE) return -1;

    hdr = (spp_header_t *)raw;

    if (memcmp(hdr->magic, SPP_MAGIC, SPP_MAGIC_LEN) != 0) {
        SP_ERR("spp_recv: bad magic");
        return -1;
    }

    if (hdr->payload_len > SPP_MAX_PAYLOAD) {
        SP_ERR("spp_recv: payload too large (%u)", hdr->payload_len);
        return -1;
    }

    if (hdr->payload_len > 0) {
#ifdef SP_PLATFORM_WINDOWS
        n = recv(sock, (char *)(raw + SPP_HEADER_SIZE), hdr->payload_len + SPP_CRC_SIZE, 0);
#else
        n = recv(sock, raw + SPP_HEADER_SIZE, hdr->payload_len + SPP_CRC_SIZE, MSG_WAITALL);
#endif
        if (n < (ssize_t)(hdr->payload_len + SPP_CRC_SIZE)) return -1;
    } else {
#ifdef SP_PLATFORM_WINDOWS
        n = recv(sock, (char *)(raw + SPP_HEADER_SIZE), SPP_CRC_SIZE, 0);
#else
        n = recv(sock, raw + SPP_HEADER_SIZE, SPP_CRC_SIZE, MSG_WAITALL);
#endif
        if (n < (ssize_t)SPP_CRC_SIZE) return -1;
    }

    memcpy(&crc_recv, raw + SPP_HEADER_SIZE + hdr->payload_len, SPP_CRC_SIZE);
    crc_calc = spp_crc32(raw, SPP_HEADER_SIZE + hdr->payload_len);
    if (crc_recv != crc_calc) {
        SP_ERR("spp_recv: CRC mismatch (got %08x, expected %08x)", crc_recv, crc_calc);
        return -1;
    }

    memcpy(hdr_out, hdr, SPP_HEADER_SIZE);
    if (payload_out && hdr->payload_len > 0)
        memcpy(payload_out, raw + SPP_HEADER_SIZE, hdr->payload_len);
    if (payload_len_out)
        *payload_len_out = hdr->payload_len;

    SP_DBG("spp_recv: type=0x%04x seq=%llu len=%u",
           hdr->msg_type, (unsigned long long)hdr->seq, hdr->payload_len);
    return 0;
}

/* ── SPMention ─────────────────────────────────────────────────────────────── */
/* SPMention format: @host:port/identity  e.g. @localhost:5221/sharedprotocol */
static void sp_gen_mention(char *out, size_t sz) {
    char hostname[128] = "localhost";
    gethostname(hostname, sizeof(hostname));
    snprintf(out, sz, "@%s:%d/sharedprotocol", hostname, g_sp.port);
}

/* ── SPP Handshake ─────────────────────────────────────────────────────────── */
/* Blocking variant, kept for outbound/test use; the IO engine does its own non-blocking handshake. */
__attribute__((unused))
static int spp_do_handshake_server(sp_socket_t client_sock, spp_peer_t *peer) {
    spp_header_t hdr;
    uint8_t      payload[SPP_MAX_PAYLOAD];
    uint32_t     payload_len;
    char         ack[256];
    char         session[37];

    /* Wait for SPP_CONNECT */
    if (spp_recv(client_sock, &hdr, payload, &payload_len) < 0) return -1;
    if (hdr.msg_type != SPP_CONNECT) {
        SP_ERR("handshake: expected CONNECT, got 0x%04x", hdr.msg_type);
        return -1;
    }

    payload[payload_len] = '\0';
    SP_LOG("handshake: CONNECT from: %s", payload);

    /* Parse spmention from payload (JSON: {"spmention":"...", "version":..., "caps":...}) */
    /* Minimal JSON parse — just extract spmention field */
    {
        char *p = strstr((char *)payload, "\"spmention\"");
        if (p) {
            p = strchr(p, ':');
            if (p) {
                p++; while (*p == ' ' || *p == '"') p++;
                char *end = strchr(p, '"');
                if (end) {
                    size_t len = (size_t)(end - p);
                    if (len >= sizeof(peer->spmention)) len = sizeof(peer->spmention) - 1;
                    strncpy(peer->spmention, p, len);
                    peer->spmention[len] = '\0';
                }
            }
        }
    }

    sp_gen_uuid(session);
    strncpy(peer->session_id, session, sizeof(peer->session_id) - 1);
    peer->sock   = client_sock;
    peer->active = 1;
    peer->seq_local = 1;
    peer->caps   = 0x04; /* host */

    /* Send SPP_CONNECT_ACK */
    snprintf(ack, sizeof(ack),
        "{\"spmention\":\"%s\",\"session_id\":\"%s\",\"accepted_caps\":[\"host\",\"daemon\",\"spc\"]}",
        g_sp.spmention, session);

    if (spp_send(client_sock, SPP_CONNECT_ACK, peer->seq_local++,
                 (uint8_t *)ack, (uint32_t)strlen(ack)) < 0) return -1;

    SP_LOG("handshake: accepted peer %s session=%s", peer->spmention, session);
    return 0;
}

__attribute__((unused))
static int spp_do_handshake_client(sp_socket_t sock, spp_peer_t *peer,
                                   const char *target_host, int target_port) {
    char         connect_payload[256];
    spp_header_t hdr;
    uint8_t      payload[SPP_MAX_PAYLOAD];
    uint32_t     payload_len;

    snprintf(connect_payload, sizeof(connect_payload),
        "{\"spmention\":\"%s\",\"version\":%d,\"caps\":[\"host\",\"daemon\",\"spc\"]}",
        g_sp.spmention, SPP_VERSION);

    peer->seq_local = 1;
    if (spp_send(sock, SPP_CONNECT, peer->seq_local++,
                 (uint8_t *)connect_payload, (uint32_t)strlen(connect_payload)) < 0) return -1;

    if (spp_recv(sock, &hdr, payload, &payload_len) < 0) return -1;
    if (hdr.msg_type != SPP_CONNECT_ACK) {
        SP_ERR("handshake client: expected CONNECT_ACK, got 0x%04x", hdr.msg_type);
        return -1;
    }

    payload[payload_len] = '\0';
    SP_LOG("handshake client: connected to %s:%d", target_host, target_port);
    peer->sock   = sock;
    peer->active = 1;
    return 0;
}

/* ── SPCode (QuickJS-lite) host runner ─────────────────────────────────────── */
/*
 * Host-side SPCode runner.
 * Without QuickJS linked, this is a minimal interpreter that handles
 * the most common .spc patterns: print(), sp.* calls, basic JS.
 *
 * To use full QuickJS: compile with -DUSE_QUICKJS and link libquickjs.a
 * Then sp.* calls are bridged to the C daemon layer.
 */

/* QuickJS is not thread-safe and spc_run is reachable from the terminal, peers, the
 * bridge and daemon threads: serialise it, and bound how long a script may run. */
#if defined(SP_PLATFORM_UNIX) && defined(USE_QUICKJS)
static pthread_mutex_t g_spc_lock = PTHREAD_MUTEX_INITIALIZER;
  #define SPC_LOCK()   pthread_mutex_lock(&g_spc_lock)
  #define SPC_UNLOCK() pthread_mutex_unlock(&g_spc_lock)
#else
  #define SPC_LOCK()   ((void)0)
  #define SPC_UNLOCK() ((void)0)
#endif
#define SPC_TIMEOUT_MS 5000

#ifdef USE_QUICKJS
  #include "quickjs.h"

  static JSRuntime *qjs_rt  = NULL;
  static JSContext *qjs_ctx = NULL;

  /* sp.print() binding */
  static JSValue js_sp_print(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
      const char *str = JS_ToCString(ctx, argv[0]);
      if (str) { printf("%s\n", str); JS_FreeCString(ctx, str); }
      return JS_UNDEFINED;
  }

  /* sp.daemon.start(id) binding */
  static JSValue js_sp_daemon_start(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv) {
      int id;
      JS_ToInt32(ctx, &id, argv[0]);
      if (id >= 1 && id <= SP_DAEMON_MAX) {
          g_sp.daemons[id-1].running = 1;
          SP_LOG("SPCode: daemon %d started via .spc", id);
      }
      return JS_UNDEFINED;
  }

  static uint64_t g_spc_deadline_ms = 0;

  static int spc_interrupt(JSRuntime *rt, void *opaque) {
      (void)rt; (void)opaque;
      return sp_now_ms() > g_spc_deadline_ms;       /* non-zero aborts the running script */
  }

  static void spc_init_quickjs(void) {
      qjs_rt  = JS_NewRuntime();
      qjs_ctx = JS_NewContext(qjs_rt);
      JS_SetMemoryLimit(qjs_rt, 16 * 1024 * 1024); /* 16MB */
      JS_SetMaxStackSize(qjs_rt, 512 * 1024);       /* 512KB */
      JS_SetInterruptHandler(qjs_rt, spc_interrupt, NULL);
      SP_LOG("SPCode: QuickJS runtime ready");
  }

  /* caps: what the caller may do. sp.daemon.* needs cap pid, so a peer that only
   * holds cap op cannot reach daemon control through a script. */
  static int spc_run_caps(const char *src, const char *filename, uint8_t caps) {
      JSValue result, global, sp_obj, print_fn;
      int ret = 0;

      SPC_LOCK();
      g_spc_deadline_ms = sp_now_ms() + SPC_TIMEOUT_MS;

      global   = JS_GetGlobalObject(qjs_ctx);
      sp_obj   = JS_NewObject(qjs_ctx);
      print_fn = JS_NewCFunction(qjs_ctx, js_sp_print, "print", 1);

      /* JS_SetPropertyStr consumes one reference per call, so print_fn needs a Dup */
      JS_SetPropertyStr(qjs_ctx, sp_obj, "print", JS_DupValue(qjs_ctx, print_fn));
      if (caps & SPCAP_PID) {
          JSValue daemon_obj = JS_NewObject(qjs_ctx);
          JS_SetPropertyStr(qjs_ctx, daemon_obj, "start",
                            JS_NewCFunction(qjs_ctx, js_sp_daemon_start, "start", 1));
          JS_SetPropertyStr(qjs_ctx, sp_obj, "daemon", daemon_obj);
      }
      JS_SetPropertyStr(qjs_ctx, global, "sp", sp_obj);
      JS_SetPropertyStr(qjs_ctx, global, "print", print_fn);
      JS_FreeValue(qjs_ctx, global);

      result = JS_Eval(qjs_ctx, src, strlen(src), filename,
                       JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_ASYNC);
      if (JS_IsException(result)) {
          JSValue exc = JS_GetException(qjs_ctx);
          const char *msg = JS_ToCString(qjs_ctx, exc);
          SP_ERR("SPCode runtime error: %s", msg ? msg : "(unknown)");
          JS_FreeCString(qjs_ctx, msg);
          JS_FreeValue(qjs_ctx, exc);
          ret = -1;
      }
      JS_FreeValue(qjs_ctx, result);
      SPC_UNLOCK();
      return ret;
  }

#else
  /* Minimal .spc runner without QuickJS — handles print() and basic sp.* */
  static void spc_init_quickjs(void) {
      SP_LOG("SPCode: minimal host runner active (build with -DUSE_QUICKJS for full JS)");
  }

  static int spc_run_caps(const char *src, const char *filename, uint8_t caps) {
      /* Very minimal: just handle print("...") lines for now */
      (void)caps;
      const char *p = src;
      char line[1024];
      while (*p) {
          const char *end = strchr(p, '\n');
          size_t len = end ? (size_t)(end - p) : strlen(p);
          if (len >= sizeof(line)) len = sizeof(line) - 1;
          strncpy(line, p, len);
          line[len] = '\0';

          /* strip leading whitespace */
          char *l = line;
          while (*l == ' ' || *l == '\t') l++;

          /* handle print("...") */
          if (strncmp(l, "print(", 6) == 0) {
              char *s = strchr(l, '"');
              if (s) {
                  s++;
                  char *e = strchr(s, '"');
                  if (e) { *e = '\0'; printf("%s\n", s); }
              }
          }
          /* sp.log(...) */
          else if (strncmp(l, "sp.log(", 7) == 0) {
              char *s = strchr(l, '"');
              if (s) {
                  s++;
                  char *e = strchr(s, '"');
                  if (e) { *e = '\0'; SP_LOG("spc: %s", s); }
              }
          }
          /* ignore unknown lines silently */

          if (!end) break;
          p = end + 1;
      }
      SP_DBG("SPCode: ran %s", filename);
      return 0;
  }
#endif

/* trusted callers (terminal, daemons, --spc): full capabilities */
static int spc_run(const char *src, const char *filename) {
    return spc_run_caps(src, filename, SPCAP_ALL);
}

static int spc_run_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { SP_ERR("spc_run_file: cannot open %s: %s", path, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *src = (char *)malloc(sz + 1);
    if (!src) { fclose(f); return -1; }
    fread(src, 1, sz, f);
    src[sz] = '\0';
    fclose(f);
    int ret = spc_run(src, path);
    free(src);
    return ret;
}

/* ── Daemons ───────────────────────────────────────────────────────────────── */
static void sp_daemon_init(void) {
    static const struct { int id; const char *name; const char *spc; } defs[] = {
        { SP_DAEMON_SPAI,     "SPAI",      "/sp/daemons/spai.spc"     },
        { SP_DAEMON_REGISTRY, "SPRegistry","/sp/daemons/registry.spc" },
        { SP_DAEMON_REPORT,   "SPReport",  "/sp/daemons/report.spc"   },
        { SP_DAEMON_POLICY,   "SPPolicy",  "/sp/daemons/policy.spc"   },
        { SP_DAEMON_CRON,     "SP-CRON",   "/sp/daemons/cron.spc"     },
        { SP_DAEMON_WORKER,   "SPWorker",  "/sp/daemons/worker.spc"   },
    };
    for (int i = 0; i < SP_DAEMON_MAX; i++) {
        g_sp.daemons[i].id      = defs[i].id;
        g_sp.daemons[i].running = 0;
        strncpy(g_sp.daemons[i].name,     defs[i].name, 31);
        strncpy(g_sp.daemons[i].spc_path, defs[i].spc,  255);
    }
}

#ifdef SP_PLATFORM_UNIX
static void *sp_daemon_thread(void *arg) {
    sp_daemon_t *d = (sp_daemon_t *)arg;
    SP_LOG("daemon[%s]: starting", d->name);
    SP_ST(d->running, 1);
    SP_ST(d->alive, 1);
    SP_ST(d->start_time, sp_now_ms());

    while (SP_IS_RUNNING() && SP_LD(d->running)) {
        if (SP_LD(d->restart_req)) {   /* sp.daemon.restart */
            SP_ST(d->restart_req, 0);
            __atomic_fetch_add(&d->restart_count, 1, __ATOMIC_RELAXED);
            SP_ST(d->start_time, sp_now_ms());
            SP_LOG("daemon[%s]: restarted", d->name);
        }
        /* Run daemon .spc if it exists */
        FILE *f = fopen(d->spc_path, "r");
        if (f) {
            fclose(f);
            if (spc_run_file(d->spc_path) < 0) {
                SP_WARN("daemon[%s]: .spc error, restarting in 3s", d->name);
                __atomic_fetch_add(&d->restart_count, 1, __ATOMIC_RELAXED);
                sleep(3);
                continue;
            }
        }
        /* Daemon heartbeat — sleep and loop */
        sleep(1);
    }

    SP_LOG("daemon[%s]: stopped", d->name);
    SP_ST(d->running, 0);
    SP_ST(d->alive, 0);
    return NULL;
}

/* Starts daemon i (0-based) if its thread is not alive. Returns 0 on success. */
static int sp_daemon_spawn(int i) {
    sp_daemon_t *d = &g_sp.daemons[i];
    pthread_t t;
    if (SP_LD(d->alive)) return -1;
    SP_ST(d->running, 1);
    SP_ST(d->alive, 1);
    if (pthread_create(&t, NULL, sp_daemon_thread, d) != 0) { SP_ST(d->running, 0); SP_ST(d->alive, 0); return -1; }
    pthread_detach(t);
    return 0;
}
#endif

static void sp_daemons_start(void) {
#ifdef SP_PLATFORM_UNIX
    for (int i = 0; i < SP_DAEMON_MAX; i++) {
        sp_daemon_spawn(i);
        SP_LOG("daemon[%s]: thread started", g_sp.daemons[i].name);
    }
#else
    SP_WARN("daemons: pthread not available on this platform");
#endif
}

static void sp_daemon_handle_msg(uint8_t daemon_id, uint8_t *payload, uint32_t len) {
    if (daemon_id < 1 || daemon_id > SP_DAEMON_MAX) return;
    sp_daemon_t *d = &g_sp.daemons[daemon_id - 1];
    payload[len] = '\0';
    SP_LOG("daemon[%s]: message: %s", d->name, payload);
    /* Run received SPCode payload on this daemon */
    spc_run((char *)payload, d->name);
}

/* ── Chromium launcher ─────────────────────────────────────────────────────── */
/* Looks for the browser named by --browser-used: fixed install paths first, then PATH. */
static int sp_find_browser(const char *kind, char *out, size_t sz) {
#ifdef SP_PLATFORM_WINDOWS
    static const char *const p_chromium[] = { "C:\\Program Files\\Chromium\\Application\\chromium.exe", NULL };
    static const char *const p_chrome[]   = { "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", NULL };
    static const char *const p_brave[]    = { "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", NULL };
    static const char *const p_firefox[]  = { "C:\\Program Files\\Mozilla Firefox\\firefox.exe", NULL };
    static const char *const n_chromium[] = { "chromium", NULL };
    static const char *const n_chrome[]   = { "chrome", NULL };
    static const char *const n_brave[]    = { "brave", NULL };
    static const char *const n_firefox[]  = { "firefox", NULL };
#elif defined(SP_PLATFORM_ANDROID)
    static const char *const p_chromium[] = { "/data/local/tmp/chromium", "/system/bin/chromium", NULL };
    static const char *const p_chrome[]   = { NULL };
    static const char *const p_brave[]    = { NULL };
    static const char *const p_firefox[]  = { NULL };
    static const char *const n_chromium[] = { "chromium", NULL };
    static const char *const n_chrome[]   = { "google-chrome", NULL };
    static const char *const n_brave[]    = { "brave", NULL };
    static const char *const n_firefox[]  = { "firefox", NULL };
#else
    static const char *const p_chromium[] = { "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium", "/usr/local/bin/chromium", NULL };
    static const char *const p_chrome[]   = { "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/opt/google/chrome/chrome", NULL };
    static const char *const p_brave[]    = { "/usr/bin/brave-browser", "/usr/bin/brave", "/snap/bin/brave", "/opt/brave.com/brave/brave-browser", NULL };
    static const char *const p_firefox[]  = { "/usr/bin/firefox", "/snap/bin/firefox", "/usr/local/bin/firefox", "/usr/lib/firefox/firefox", NULL };
    static const char *const n_chromium[] = { "chromium-browser", "chromium", NULL };
    static const char *const n_chrome[]   = { "google-chrome", "google-chrome-stable", "chrome", NULL };
    static const char *const n_brave[]    = { "brave-browser", "brave", NULL };
    static const char *const n_firefox[]  = { "firefox", NULL };
#endif
    static const struct { const char *kind; const char *const *paths; const char *const *names; } tab[] = {
        { "chromium", p_chromium, n_chromium },
        { "chrome",   p_chrome,   n_chrome   },
        { "brave",    p_brave,    n_brave    },
        { "firefox",  p_firefox,  n_firefox  },
    };
    size_t t, i;
    for (t = 0; t < sizeof(tab) / sizeof(tab[0]); t++) {
        if (strcmp(tab[t].kind, kind) != 0) continue;
        for (i = 0; tab[t].paths[i]; i++) {
            FILE *f = fopen(tab[t].paths[i], "r");
            if (f) { fclose(f); snprintf(out, sz, "%s", tab[t].paths[i]); return 1; }
        }
        for (i = 0; tab[t].names[i]; i++) {              /* names are fixed strings from the table above */
            char cmd[96], line[256] = {0};
            FILE *p;
#ifdef SP_PLATFORM_WINDOWS
            snprintf(cmd, sizeof(cmd), "where %s 2>nul", tab[t].names[i]);
            p = _popen(cmd, "r");
#else
            snprintf(cmd, sizeof(cmd), "which %s 2>/dev/null", tab[t].names[i]);
            p = popen(cmd, "r");
#endif
            if (!p) continue;
            if (fgets(line, sizeof(line), p)) {
                line[strcspn(line, "\r\n")] = '\0';
                if (line[0]) {
#ifdef SP_PLATFORM_WINDOWS
                    _pclose(p);
#else
                    pclose(p);
#endif
                    snprintf(out, sz, "%s", line);
                    return 1;
                }
            }
#ifdef SP_PLATFORM_WINDOWS
            _pclose(p);
#else
            pclose(p);
#endif
        }
    }
    return 0;
}

/* --site-used: "example.com", "https://example.com/app?x=1", "http://localhost:3000".
 * Fills the launch URL (no fragment) and the exact Origin the bridge will accept. */
static int sp_parse_site(const char *in, char *url, size_t usz, char *origin, size_t osz, char *why, size_t wsz) {
    char buf[480], scheme[8], host[260], rest[400];
    const char *p, *auth, *e;
    size_t i, hl = 0, port = 0, n;
    int has_port = 0;

    while (*in == ' ' || *in == '\t') in++;
    n = strlen(in);
    while (n && (in[n - 1] == ' ' || in[n - 1] == '\t')) n--;
    if (n == 0 || n >= sizeof(buf)) { snprintf(why, wsz, "empty or too long"); return -1; }
    memcpy(buf, in, n); buf[n] = '\0';
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c <= 0x20 || c >= 0x7f || strchr("\"'<>\\`^{}|", c)) { snprintf(why, wsz, "illegal character '%c'", c > 0x20 && c < 0x7f ? c : '?'); return -1; }
        if (c == '#') { snprintf(why, wsz, "no #fragment allowed (the host adds its own)"); return -1; }
    }
    p = strstr(buf, "://");
    if (p) {
        size_t sl = (size_t)(p - buf);
        if (sl >= sizeof(scheme)) { snprintf(why, wsz, "scheme must be http or https"); return -1; }
        for (i = 0; i < sl; i++) scheme[i] = (char)tolower((unsigned char)buf[i]);
        scheme[sl] = '\0';
        if (strcmp(scheme, "http") != 0 && strcmp(scheme, "https") != 0) { snprintf(why, wsz, "scheme must be http or https"); return -1; }
        auth = p + 3;
    } else {
        snprintf(scheme, sizeof(scheme), "https");
        auth = buf;
    }
    e = auth + strcspn(auth, "/?");
    snprintf(rest, sizeof(rest), "%s", e);
    for (p = auth; p < e; p++)
        if (*p == '@') { snprintf(why, wsz, "user:password@ is not allowed"); return -1; }
    for (p = auth; p < e; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '@') { snprintf(why, wsz, "user:password@ is not allowed"); return -1; }
        if (c == ':') break;
        if (!isalnum(c) && c != '.' && c != '-') { snprintf(why, wsz, "bad host name"); return -1; }
        if (hl + 1 < sizeof(host)) host[hl++] = (char)tolower(c);
    }
    host[hl] = '\0';
    if (hl == 0 || host[0] == '.' || host[0] == '-' || host[hl - 1] == '-' || strstr(host, "..")) { snprintf(why, wsz, "bad host name"); return -1; }
    if (p < e && *p == ':') {
        p++;
        if (p == e) { snprintf(why, wsz, "empty port"); return -1; }
        for (; p < e; p++) {
            if (!isdigit((unsigned char)*p)) { snprintf(why, wsz, "bad port"); return -1; }
            port = port * 10 + (size_t)(*p - '0');
            if (port > 65535) { snprintf(why, wsz, "bad port"); return -1; }
        }
        has_port = port != 0;
        if (!has_port) { snprintf(why, wsz, "bad port"); return -1; }
    }
    {   /* Origin headers omit the scheme's default port */
        int dflt = has_port && ((strcmp(scheme, "https") == 0 && port == 443) || (strcmp(scheme, "http") == 0 && port == 80));
        if (has_port && !dflt) {
            snprintf(origin, osz, "%s://%s:%zu", scheme, host, port);
            snprintf(url, usz, "%s://%s:%zu%s", scheme, host, port, rest[0] ? rest : "/");
        } else {
            snprintf(origin, osz, "%s://%s", scheme, host);
            snprintf(url, usz, "%s://%s%s", scheme, host, rest[0] ? rest : "/");
        }
    }
    why[0] = '\0';
    return 0;
}

static int sp_rm_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)type; (void)ftw;
    remove(path);
    return 0;
}
/* removes our own mkdtemp'd Firefox profile (nftw never follows symlinks with FTW_PHYS) */
static void sp_rm_profile(void) {
    if (g_sp.ff_profile[0] && strncmp(g_sp.ff_profile, "/tmp/sp-firefox-", 16) == 0)
        nftw(g_sp.ff_profile, sp_rm_cb, 16, FTW_DEPTH | FTW_PHYS);
    g_sp.ff_profile[0] = '\0';
}

/* -- Secrets ----------------------------------------------------------------- */
static int sp_random_hex(char *out, size_t nbytes) {
#ifdef SP_PLATFORM_UNIX
    uint8_t raw[32];
    size_t i;
    FILE *rf;
    if (nbytes == 0 || nbytes > sizeof(raw)) return -1;
    rf = fopen("/dev/urandom", "rb");
    if (!rf) return -1;
    if (fread(raw, 1, nbytes, rf) != nbytes) { fclose(rf); return -1; }
    fclose(rf);
    for (i = 0; i < nbytes; i++) sprintf(out + 2 * i, "%02x", raw[i]);
    out[2 * nbytes] = '\0';
    return 0;
#else
    (void)out; (void)nbytes;
    return -1;
#endif
}

/* Constant-time string equality (length is not secret: tokens are fixed-size). */
static int sp_ct_streq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b), i;
    unsigned char d = (unsigned char)(la != lb);
    for (i = 0; i < la && i < lb; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

/* The bridge token can be rotated at runtime (token.rotate): always read it through token_copy(). */
static pthread_mutex_t g_token_lock = PTHREAD_MUTEX_INITIALIZER;
static void token_copy(char out[33]) {
    pthread_mutex_lock(&g_token_lock);
    memcpy(out, g_sp.bridge_token, 33);
    pthread_mutex_unlock(&g_token_lock);
}

static int sp_launch_browser(void) {
    char cmd[2048];
    char tok[33];
    char sp_url[1024];   /* was 256: the bootstrap script is ~440 bytes and got truncated */

    const char *kind = g_sp.browser_kind[0] ? g_sp.browser_kind : "chromium";
    int is_firefox = strcmp(kind, "firefox") == 0;
    char target[1100];

    if (!sp_find_browser(kind, g_sp.chromium_bin, sizeof(g_sp.chromium_bin))) {
        SP_WARN("browser: %s not found: SP browser layer disabled", kind);
        SP_WARN("browser: install it, or pick another with --browser-used chromium|chrome|firefox|brave");
        return -1;
    }

    SP_LOG("browser: using %s (%s)", g_sp.chromium_bin, kind);
    token_copy(tok);

    /* Bootstrap HTML: injects bridge config then fetches SP from sharedpro.pages.dev */
    snprintf(sp_url, sizeof(sp_url),
        "data:text/html,<script>"
        "window.__SP_BRIDGE_PORT__=%d;"
        "window.__SP_BRIDGE_TOKEN__='%s';"
        "window.__SP_MENTION__='%s';"
        "fetch('https://sharedpro.pages.dev/sharedprotocol.js')"
        ".then(r=>r.text())"
        ".then(src=>{"
          "const s=document.createElement('script');"
          "s.textContent=src;"
          "document.head.appendChild(s);"
          "console.log('[sharedprotocol] SP loaded');"
        "})"
        ".catch(e=>console.error('[sharedprotocol] SP fetch failed:',e));"
        "</script>",
        g_sp.bridge_port, tok, g_sp.spmention);

    if (g_sp.site_url[0]) {                      /* --site-used: the site itself talks to the bridge */
        char menc[160];
        size_t mi, mo = 0;
        for (mi = 0; g_sp.spmention[mi] && mo + 4 < sizeof(menc); mi++) {
            unsigned char c = (unsigned char)g_sp.spmention[mi];
            if (isalnum(c) || c == '-' || c == '_' || c == '.') menc[mo++] = (char)c;
            else mo += (size_t)snprintf(menc + mo, sizeof(menc) - mo, "%%%02X", c);
        }
        menc[mo] = '\0';
        /* the fragment never reaches a server; SPTerminal reads it and strips it from the address */
        snprintf(target, sizeof(target), "%s#spp_port=%d&spp_token=%s&spp_mention=%s", g_sp.site_url, g_sp.bridge_port, tok, menc);
        SP_LOG("browser: opening site %s (bridge accepts only origin %s)", g_sp.site_url, g_sp.site_origin);
    } else {
        snprintf(target, sizeof(target), "%s", sp_url);
    }

    snprintf(cmd, sizeof(cmd),
        "\"%s\" "
        "--headless=new "
        "--disable-gpu "
        "--disable-dev-shm-usage "
        "--js-flags=--max-old-space-size=128 "   /* limit RAM */
        "--disk-cache-size=0 "
        "--app=\"%s\"",
        g_sp.chromium_bin, target);

#ifdef SP_PLATFORM_UNIX
    if (is_firefox && !g_sp.ff_profile[0]) {         /* one throw-away profile per run, never the user's own */
        snprintf(g_sp.ff_profile, sizeof(g_sp.ff_profile), "/tmp/sp-firefox-XXXXXX");
        if (!mkdtemp(g_sp.ff_profile)) { SP_ERR("browser: cannot create a Firefox profile dir: %s", strerror(errno)); g_sp.ff_profile[0] = '\0'; return -1; }
    }
    g_sp.browser_pid = fork();
    if (g_sp.browser_pid == 0) {
        /* child: exec Chromium directly (no shell, so paths/URLs cannot inject commands) */
        char  app_arg[1120];
        char *av[12];
        int   n = 0, closed = 0;
        snprintf(app_arg, sizeof(app_arg), "--app=%s", target);
        av[n++] = g_sp.chromium_bin;
        if (is_firefox) {
            av[n++] = "--headless";
            av[n++] = "--no-remote";
            av[n++] = "-profile";
            av[n++] = g_sp.ff_profile;
            av[n++] = target;
        } else {
            av[n++] = "--headless=new";
            av[n++] = "--disable-gpu";
            if (g_sp.chromium_no_sandbox || geteuid() == 0) av[n++] = "--no-sandbox";
            av[n++] = "--disable-dev-shm-usage";
            av[n++] = "--js-flags=--max-old-space-size=128";   /* limit RAM */
            av[n++] = "--disk-cache-size=0";
            av[n++] = app_arg;
        }
        av[n]   = NULL;
#if defined(__linux__)
        prctl(PR_SET_PDEATHSIG, SIGKILL);            /* never outlive the host: no orphan page retrying the bridge */
        if (getppid() == 1) _exit(1);
#endif
        /* the listening sockets and the epoll set must not leak into the browser */
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0) closed = 1;
#endif
        if (!closed) {
            long fd, mx = sysconf(_SC_OPEN_MAX);
            if (mx < 0 || mx > 65536) mx = 65536;
            for (fd = 3; fd < mx; fd++) close((int)fd);
        }
        execv(g_sp.chromium_bin, av);
        _exit(127);
    } else if (g_sp.browser_pid < 0) {
        SP_ERR("browser: fork failed: %s", strerror(errno));
        return -1;
    }
    SP_LOG("browser: launched pid=%d", (int)g_sp.browser_pid);
#else
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        SP_ERR("browser: CreateProcess failed");
        return -1;
    }
    SP_LOG("browser: launched");
#endif
    return 0;
}

/* ── Bridge (local WebSocket-lite to headless browser) ─────────────────────── */
/*
 * Minimal HTTP upgrade + WebSocket framing to talk to SP in the headless browser.
 * SP in the browser connects to ws://127.0.0.1:SPP_BRIDGE_PORT
 */

/* ── WebSocket helpers (SHA-1 + base64 for the RFC 6455 handshake) ─────────── */
#define SP_ROL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void sp_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu,
             h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
    size_t total = ((len + 8) / 64 + 1) * 64;   /* padded length */
    size_t off;
    int i, t;

    for (off = 0; off < total; off += 64) {
        uint8_t  blk[64];
        uint32_t w[80], a, b, c, d, e;

        for (i = 0; i < 64; i++) {
            size_t pos = off + (size_t)i;
            blk[i] = pos < len ? data[pos] : (pos == len ? 0x80 : 0x00);
        }
        if (off + 64 == total) {
            uint64_t bits = (uint64_t)len * 8;
            for (i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
        }
        for (t = 0; t < 16; t++)
            w[t] = ((uint32_t)blk[t*4] << 24) | ((uint32_t)blk[t*4+1] << 16)
                 | ((uint32_t)blk[t*4+2] << 8) | (uint32_t)blk[t*4+3];
        for (t = 16; t < 80; t++)
            w[t] = SP_ROL32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);

        a = h0; b = h1; c = h2; d = h3; e = h4;
        for (t = 0; t < 80; t++) {
            uint32_t f, k, tmp;
            if      (t < 20) { f = (b & c) | (~b & d);          k = 0x5A827999u; }
            else if (t < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1u; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6u; }
            tmp = SP_ROL32(a, 5) + f + e + k + w[t];
            e = d; d = c; c = SP_ROL32(b, 30); b = a; a = tmp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    {
        uint32_t hv[5]; hv[0] = h0; hv[1] = h1; hv[2] = h2; hv[3] = h3; hv[4] = h4;
        for (i = 0; i < 20; i++) out[i] = (uint8_t)(hv[i / 4] >> (24 - 8 * (i % 4)));
    }
}

static void sp_b64(const uint8_t *in, size_t in_len, char *out) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    for (i = 0; i < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16)
                   | (i + 1 < in_len ? (uint32_t)in[i+1] << 8 : 0)
                   | (i + 2 < in_len ? (uint32_t)in[i+2]      : 0);
        *out++ = b64[(v >> 18) & 0x3F];
        *out++ = b64[(v >> 12) & 0x3F];
        *out++ = (i + 1 < in_len) ? b64[(v >> 6) & 0x3F] : '=';
        *out++ = (i + 2 < in_len) ? b64[v & 0x3F]        : '=';
    }
    *out = '\0';
}

/* case-insensitive strstr (strcasestr is not portable) */
static const char *sp_stristr(const char *hay, const char *needle) {
    size_t nl = strlen(needle), i;
    if (!nl) return hay;
    for (; *hay; hay++) {
        for (i = 0; i < nl; i++) {
            if (!hay[i]) return NULL;
            if (tolower((unsigned char)hay[i]) != tolower((unsigned char)needle[i])) break;
        }
        if (i == nl) return hay;
    }
    return NULL;
}

#ifdef SP_PLATFORM_UNIX
  #define BRIDGE_LOCK()   pthread_mutex_lock(&g_sp.bridge_tx_lock)
  #define BRIDGE_UNLOCK() pthread_mutex_unlock(&g_sp.bridge_tx_lock)
#else
  #define BRIDGE_LOCK()   ((void)0)
  #define BRIDGE_UNLOCK() ((void)0)
#endif

static int bridge_recv_all(sp_socket_t sock, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
#ifdef SP_PLATFORM_WINDOWS
        int r = recv(sock, (char *)buf + got, (int)(n - got), 0);
#else
        ssize_t r = recv(sock, buf + got, n - got, 0);
        if (r < 0 && errno == EINTR) continue;
#endif
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static void bridge_set_timeouts(sp_socket_t s, int rcv_ms, int snd_ms) {
#ifdef SP_PLATFORM_WINDOWS
    DWORD r = (DWORD)rcv_ms, w = (DWORD)snd_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&r, sizeof(r));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&w, sizeof(w));
#else
    struct timeval r, w;
    r.tv_sec = rcv_ms / 1000; r.tv_usec = (rcv_ms % 1000) * 1000;
    w.tv_sec = snd_ms / 1000; w.tv_usec = (snd_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &r, sizeof(r));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &w, sizeof(w));
#endif
}

static int bridge_ws_handshake(sp_socket_t client) {
    char buf[4096];
    size_t have = 0;
    char response[512];
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char key[128] = {0};
    char accept[64] = {0};
    char combined[256];
    uint8_t digest[20];
    const char *p, *end;
    size_t klen;

    bridge_set_timeouts(client, 5000, 2000);   /* a stalled client must not wedge the bridge */

    while (have < sizeof(buf) - 1) {
#ifdef SP_PLATFORM_WINDOWS
        int n = recv(client, buf + have, (int)(sizeof(buf) - 1 - have), 0);
#else
        ssize_t n = recv(client, buf + have, sizeof(buf) - 1 - have, 0);
#endif
        if (n <= 0) return -1;
        have += (size_t)n;
        buf[have] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (!strstr(buf, "\r\n\r\n")) { SP_ERR("bridge: handshake request too large"); return -1; }

    /* Origin check: a normal web page must not be able to drive the bridge.
     * (Defense in depth: the token checked in bridge_authenticate() is the real gate.)
     * Allowed: no Origin (non-browser client), "null" (data: page of the headless
     * browser we launch), or the one origin given with --bridge-origin. */
    p = sp_stristr(buf, "\r\norigin:");
    if (p) {
        char origin[160] = {0};
        size_t ol;
        int ok;
        p += 9;
        while (*p == ' ') p++;
        end = strstr(p, "\r\n");
        ol = end ? (size_t)(end - p) : 0;
        if (ol >= sizeof(origin)) ol = sizeof(origin) - 1;
        memcpy(origin, p, ol);
        /* with --site-used the one named site is the only page that may use the bridge ("null" is refused) */
        ok = (g_sp.site_origin[0] ? strcmp(origin, g_sp.site_origin) == 0 : strcmp(origin, "null") == 0) ||
             (g_sp.bridge_origin[0] && strcmp(origin, g_sp.bridge_origin) == 0);
        if (!ok) {
            static const char deny[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            SP_WARN("bridge: rejected WebSocket from origin '%s' (allowed: %s; --bridge-origin adds one)", origin, g_sp.site_origin[0] ? g_sp.site_origin : "null");
#ifdef SP_PLATFORM_WINDOWS
            send(client, deny, (int)sizeof(deny) - 1, 0);
#else
            send(client, deny, sizeof(deny) - 1, MSG_NOSIGNAL);
#endif
            return -1;
        }
    }

    /* Sec-WebSocket-Key */
    p = sp_stristr(buf, "\r\nsec-websocket-key:");
    if (!p) { SP_ERR("bridge: no WebSocket key in handshake"); return -1; }
    p += 20;
    while (*p == ' ') p++;
    end = strstr(p, "\r\n");
    if (!end) return -1;
    klen = (size_t)(end - p);
    while (klen && (p[klen-1] == ' ')) klen--;
    if (klen == 0 || klen >= sizeof(key)) return -1;
    memcpy(key, p, klen);

    /* Sec-WebSocket-Accept = base64(SHA1(key + magic)) — RFC 6455 */
    snprintf(combined, sizeof(combined), "%s%s", key, magic);
    sp_sha1((const uint8_t *)combined, strlen(combined), digest);
    sp_b64(digest, 20, accept);

    snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        accept);

#ifdef SP_PLATFORM_WINDOWS
    send(client, response, (int)strlen(response), 0);
#else
    send(client, response, strlen(response), MSG_NOSIGNAL);
#endif
    bridge_set_timeouts(client, 0, 2000);      /* reads block (idle bridge is normal); writes may not */
    SP_LOG("bridge: WebSocket handshake complete");
    return 0;
}

/* opcode: 0x1 text, 0x2 binary, 0x9 ping, 0xA pong. Caller serialises via BRIDGE_LOCK. */
static int bridge_ws_send_op(sp_socket_t sock, int opcode, const uint8_t *data, size_t len) {
    uint8_t frame[14 + SPP_MAX_PAYLOAD];
    size_t  hdr_len, total, off = 0;
    int     i;

    if (len > SPP_MAX_PAYLOAD) return -1;

    frame[0] = (uint8_t)(0x80 | (opcode & 0x0F));   /* FIN + opcode */
    if (len <= 125) {
        frame[1] = (uint8_t)len;
        hdr_len  = 2;
    } else if (len <= 65535) {
        frame[1] = 126;
        frame[2] = (uint8_t)((len >> 8) & 0xFF);
        frame[3] = (uint8_t)(len & 0xFF);
        hdr_len  = 4;
    } else {
        frame[1] = 127;
        for (i = 0; i < 8; i++) frame[2 + i] = (uint8_t)(((uint64_t)len) >> (56 - 8 * i));
        hdr_len = 10;
    }

    if (len) memcpy(frame + hdr_len, data, len);
    total = hdr_len + len;

    while (off < total) {
#ifdef SP_PLATFORM_WINDOWS
        int n = send(sock, (const char *)frame + off, (int)(total - off), 0);
#else
        ssize_t n = send(sock, frame + off, total - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
#endif
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Receives one complete data message (text/binary, fragments reassembled).
 * Control frames are handled here: ping -> pong, pong -> RTT sample, close -> -1. */
static int bridge_ws_recv(sp_socket_t sock, uint8_t *out, size_t *out_len) {
    size_t total = 0;

    for (;;) {
        uint8_t  hdr[2], ext[8], mask[4] = {0};
        uint64_t payload_len;
        int      fin, op, masked, i;

        if (bridge_recv_all(sock, hdr, 2) < 0) return -1;
        fin         = (hdr[0] & 0x80) != 0;
        op          = hdr[0] & 0x0F;
        masked      = (hdr[1] & 0x80) != 0;
        payload_len = hdr[1] & 0x7F;

        if (payload_len == 126) {
            if (bridge_recv_all(sock, ext, 2) < 0) return -1;
            payload_len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            if (bridge_recv_all(sock, ext, 8) < 0) return -1;
            payload_len = 0;
            for (i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];   /* big-endian */
        }
        if (masked && bridge_recv_all(sock, mask, 4) < 0) return -1;

        if (op >= 0x8) {                       /* control frame */
            uint8_t ctl[125];
            if (payload_len > 125) return -1;
            if (payload_len && bridge_recv_all(sock, ctl, (size_t)payload_len) < 0) return -1;
            if (masked) for (i = 0; i < (int)payload_len; i++) ctl[i] ^= mask[i & 3];
            if (op == 0x8) return -1;          /* close */
            if (op == 0x9) {                   /* ping -> pong */
                BRIDGE_LOCK();
                bridge_ws_send_op(sock, 0xA, ctl, (size_t)payload_len);
                BRIDGE_UNLOCK();
            } else if (op == 0xA && payload_len == 8) {   /* pong for our latency ping */
                uint64_t sent;
                memcpy(&sent, ctl, 8);
                g_sp.bridge_rtt_ms = (uint32_t)(sp_now_ms() - sent);
            }
            continue;
        }

        if (payload_len > (uint64_t)(SPP_MAX_PAYLOAD - total)) return -1;
        if (payload_len && bridge_recv_all(sock, out + total, (size_t)payload_len) < 0) return -1;
        if (masked) for (i = 0; i < (int)payload_len; i++) out[total + (size_t)i] ^= mask[i & 3];
        total += (size_t)payload_len;
        if (fin) { *out_len = total; return 0; }
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  SPP v1.1 engine — peer table, queued sends, JSON, policy, memory, RPC
 *  (Linux / Android: needs epoll + pthreads)
 * ══════════════════════════════════════════════════════════════════════════ */
#ifdef SP_PLATFORM_UNIX

typedef struct { uint32_t slot; uint64_t conn; } peer_ref_t;

enum { CALLER_TERMINAL = 0, CALLER_BRIDGE = 1, CALLER_PEER = 2 };

typedef struct {
    int        kind;
    peer_ref_t ref;     /* CALLER_PEER only */
    uint8_t    caps;    /* SPCAP_* resolved at dispatch time */
} sp_caller_t;

typedef struct {
    sp_caller_t caller;
    uint64_t    id;
    int         has_id;
    uint64_t    t0_us;      /* start (monotonic), for trace.* */
    char        mname[40];  /* method name as called, for trace.* */
} rpc_req_t;

static uint64_t sp_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
static void trace_record(int kind, uint64_t conn, const char *method, int ok, const char *err, uint64_t t0_us);

static inline uint8_t sp_caps_get(const spp_peer_t *p) {
    return __atomic_load_n(&p->sp_caps, __ATOMIC_RELAXED);
}

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

static void mem_free_owner(uint64_t owner);   /* defined below */

/* Frees a slot. IO thread only (it owns rx buffers and the epoll set). */
static size_t g_tx_total;                      /* queued outbound bytes, all peers (peers_lock) */
static void peer_release_locked(uint32_t slot) {
    spp_peer_t *p = &g_sp.peers[slot];
    uint64_t conn;
    if (!p->active && !p->hs) return;
    conn = p->conn_id;
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
    mem_free_owner(conn);                      /* lock order: peers_lock -> mem lock */
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
static void spp_broadcast_ready(uint16_t type, const uint8_t *payload, uint32_t len) {
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

/* ── capabilities / policy ──────────────────────────────────────────────────── */
static const struct { const char *name; uint8_t bit; } g_capnames[] = {
    { "pid", SPCAP_PID }, { "uid", SPCAP_UID }, { "gid", SPCAP_GID }, { "op", SPCAP_OP }, { "js", SPCAP_JS },
    { "policy", SPCAP_POLICY }, { "move", SPCAP_MOVE }, { "fs", SPCAP_FS },
};
#define N_CAPNAMES ((int)(sizeof(g_capnames) / sizeof(g_capnames[0])))

static const char *capname(uint8_t bit) {
    int i;
    for (i = 0; i < N_CAPNAMES; i++) if (g_capnames[i].bit == bit) return g_capnames[i].name;
    return "?";
}

/* "js+op" for a mask of one or more capabilities (denial messages) */
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

/* "caps": 128 | "0x88" | "fs,op" | "all" */
static int parse_caps(const char *params, uint8_t *out) {
    const char *p = json_find(params, "caps");
    unsigned v = 0;
    if (!p) return -1;
    if (*p == '"') {
        char *s = json_str_dup(params, "caps"), *tok, *save = NULL;
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
    } else if (isdigit((unsigned char)*p)) {
        v = (unsigned)strtoul(p, NULL, 0);
    } else {
        return -1;
    }
    *out = (uint8_t)(v & SPCAP_ALL);
    return 0;
}

/* ── shared memory regions (sp.mem.*) ───────────────────────────────────────── */
#define SP_MEM_MAX_REGIONS 1024
#define SP_MEM_MAX_REGION  (16u << 20)
#define SP_MEM_MAX_TOTAL   (256u << 20)
#define SP_MEM_IO_MAX      16384          /* bytes per read/write call (hex doubles it on the wire) */

typedef struct { uint32_t id; uint8_t *p; size_t size; uint64_t owner; } mem_region_t;
static mem_region_t    g_mem[SP_MEM_MAX_REGIONS];
static size_t          g_mem_total;
static uint32_t        g_mem_next_id = 1;
static pthread_mutex_t g_mem_lock = PTHREAD_MUTEX_INITIALIZER;

static mem_region_t *mem_find_locked(uint32_t id) {
    int i;
    for (i = 0; i < SP_MEM_MAX_REGIONS; i++) if (g_mem[i].p && g_mem[i].id == id) return &g_mem[i];
    return NULL;
}

static void mem_free_owner(uint64_t owner) {   /* regions die with the peer that made them */
    int i;
    if (!owner) return;
    pthread_mutex_lock(&g_mem_lock);
    for (i = 0; i < SP_MEM_MAX_REGIONS; i++) {
        if (g_mem[i].p && g_mem[i].owner == owner) {
            g_mem_total -= g_mem[i].size;
            free(g_mem[i].p);
            memset(&g_mem[i], 0, sizeof(g_mem[i]));
        }
    }
    pthread_mutex_unlock(&g_mem_lock);
}

/* ── bridge send (text/binary WebSocket frames to the JS layer) ─────────────── */
static int bridge_send_op(int op, const void *data, size_t len) {
    int rc = -1;
    BRIDGE_LOCK();
    if (g_sp.bridge_sock != SP_INVALID_SOCKET)
        rc = bridge_ws_send_op(g_sp.bridge_sock, op, (const uint8_t *)data, len);
    BRIDGE_UNLOCK();
    return rc;
}
static int bridge_send_text(const char *s, size_t n) { return bridge_send_op(0x1, s, n); }

static int bridge_connected(void) {
    int up;
    BRIDGE_LOCK();
    up = g_sp.bridge_sock != SP_INVALID_SOCKET;
    BRIDGE_UNLOCK();
    return up;
}

static void bridge_ping(void) {                /* latency probe: browsers answer with an automatic pong */
    uint64_t now = sp_now_ms();
    BRIDGE_LOCK();
    if (g_sp.bridge_sock != SP_INVALID_SOCKET)
        bridge_ws_send_op(g_sp.bridge_sock, 0x9, (const uint8_t *)&now, sizeof(now));
    BRIDGE_UNLOCK();
}

/* ── in-flight requests forwarded to the JS layer ───────────────────────────── */
typedef struct {
    int         used, waiter;          /* waiter: the terminal thread blocks on this entry */
    uint64_t    bid, req_id;
    int         has_id;
    sp_caller_t caller;
    uint64_t    deadline_ms;
    int         done, ok;
    char       *result;                /* waiter: raw JSON result or error text */
    uint64_t    t0_us;                 /* trace.* */
    char        mname[40];
} rpc_pending_t;

static rpc_pending_t   g_pending[SPP_RPC_PENDING];
static uint64_t        g_next_bid;
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_pending_cv;

static void sp_rpc_init(void) {
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_pending_cv, &ca);
    pthread_condattr_destroy(&ca);
}

/* ── replies ────────────────────────────────────────────────────────────────── */
static void rpc_reply(const sp_caller_t *c, int has_id, uint64_t id, int ok, const char *body) {
    sb_t r;
    sb_init(&r);
    sb_puts(&r, c->kind == CALLER_BRIDGE ? "{\"spp\":\"rpc_result\"," : "{");
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
    if (c->kind == CALLER_PEER)        spp_peer_send(c->ref, SPP_RPC_RESULT, (const uint8_t *)r.p, (uint32_t)r.len);
    else if (c->kind == CALLER_BRIDGE) bridge_send_text(r.p, r.len);
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

#define RPC_ERR(...) do { snprintf(err, errsz, __VA_ARGS__); return -1; } while (0)

/* ── sp.identity ────────────────────────────────────────────────────────────── */
static int rpc_identity(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    size_t ready;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_sp.peers_lock);
    ready = g_sp.ready_count;
    pthread_mutex_unlock(&g_sp.peers_lock);
    sb_puts(out, "{\"spmention\":");
    sb_json_str(out, g_sp.spmention);
    sb_printf(out, ",\"uid\":%d,\"version\":\"1.1.0\",\"spp\":\"%d.%d\",\"port\":%d,\"bridge_port\":%d,"
                   "\"max_peers\":%zu,\"peers\":%zu}",
              SP_BASE_ID, SPP_VERSION >> 8, SPP_VERSION & 0xFF, g_sp.port, g_sp.bridge_port,
              g_sp.max_peers, ready);
    return 0;
}

/* ── sp.peer.* ──────────────────────────────────────────────────────────────── */
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
        sb_printf(out, "%s{\"conn\":%" PRIu64 ",\"uid\":%" PRIu64 ",\"slot\":%zu,\"state\":\"%s\",\"ip\":\"%s\",\"spmention\":",
                  first ? "" : ",", p->conn_id, (uint64_t)SP_BASE_ID + p->conn_id, i,
                  p->active ? "ready" : "handshake", ip);
        sb_json_str(out, p->spmention);
        sb_printf(out, ",\"session\":\"%s\",", p->session_id);
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

/* Resolves {"target":"bridge"} | {"conn":N} | (caller itself) to a caps byte.
 * Caller holds g_sp.peers_lock and keeps it while using the pointer. */
static int caps_ptr_locked(const rpc_req_t *rq, const char *params, uint8_t **pp, char *err, size_t errsz) {
    int64_t conn;
    char *target = json_str_dup(params, "target");
    if (target) {
        int is_bridge = strcmp(target, "bridge") == 0;
        free(target);
        if (!is_bridge) RPC_ERR("target must be \"bridge\" (or use conn)");
        *pp = &g_sp.bridge_caps;
        return 0;
    }
    if (json_get_i64(params, "conn", &conn) == 0) {
        int slot = peer_find_conn_locked((uint64_t)conn);
        if (slot < 0) RPC_ERR("no such peer");
        *pp = &g_sp.peers[slot].sp_caps;
        return 0;
    }
    if (rq->caller.kind == CALLER_PEER) {
        spp_peer_t *p = peer_by_ref(rq->caller.ref);
        if (!p) RPC_ERR("peer gone");
        *pp = &p->sp_caps;
        return 0;
    }
    if (rq->caller.kind == CALLER_BRIDGE) { *pp = &g_sp.bridge_caps; return 0; }
    RPC_ERR("conn or target required");
}

/* ── sp.policy.* ────────────────────────────────────────────────────────────── */
static int rpc_policy_get(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    uint8_t *cp, caps;
    int rc;
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    caps = rc == 0 ? __atomic_load_n(cp, __ATOMIC_RELAXED) : 0;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0) return -1;
    sb_putn(out, "{", 1);
    sb_caps(out, caps);
    sb_putn(out, "}", 1);
    return 0;
}

static int rpc_policy_check(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    uint8_t *cp, caps, mask;
    int rc;
    if (parse_caps(params, &mask) < 0) RPC_ERR("caps required (number, \"fs,op\" ...)");
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    caps = rc == 0 ? __atomic_load_n(cp, __ATOMIC_RELAXED) : 0;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0) return -1;
    sb_printf(out, "{\"has\":%s}", (caps & mask) == mask ? "true" : "false");
    return 0;
}

static int rpc_policy_change(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz, int grant) {
    uint8_t *cp, mask, now;
    int rc;
    if (parse_caps(params, &mask) < 0) RPC_ERR("caps required (number, \"fs,op\" ...)");
    /* you can only hand out or take away capabilities you hold yourself */
    if (mask & ~rq->caller.caps) RPC_ERR("cannot %s capabilities you do not hold", grant ? "grant" : "revoke");
    pthread_mutex_lock(&g_sp.peers_lock);
    rc = caps_ptr_locked(rq, params, &cp, err, errsz);
    if (rc == 0 && cp == &g_sp.bridge_caps && rq->caller.kind == CALLER_PEER) {
        snprintf(err, errsz, "peers cannot change the browser bridge's capabilities");
        rc = -1;
    }
    if (rc == 0) {
        if (grant) __atomic_fetch_or(cp, mask, __ATOMIC_RELAXED);
        else       __atomic_fetch_and(cp, (uint8_t)~mask, __ATOMIC_RELAXED);
        now = __atomic_load_n(cp, __ATOMIC_RELAXED);
    } else now = 0;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (rc < 0) return -1;
    sb_putn(out, "{", 1);
    sb_caps(out, now);
    sb_putn(out, "}", 1);
    return 0;
}
static int rpc_policy_grant(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    return rpc_policy_change(rq, params, out, err, errsz, 1);
}
static int rpc_policy_revoke(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    return rpc_policy_change(rq, params, out, err, errsz, 0);
}

/* ── sp.daemon.* ────────────────────────────────────────────────────────────── */
static int daemon_arg(const char *params, int *idx, char *err, size_t errsz) {
    int64_t id;
    char *name;
    int i;
    if (json_get_i64(params, "id", &id) == 0 && id >= 1 && id <= SP_DAEMON_MAX) { *idx = (int)id - 1; return 0; }
    name = json_str_dup(params, "name");
    if (name) {
        for (i = 0; i < SP_DAEMON_MAX; i++)
            if (strcasecmp(name, g_sp.daemons[i].name) == 0) { *idx = i; free(name); return 0; }
        free(name);
    }
    snprintf(err, errsz, "daemon id (1-%d) or name required", SP_DAEMON_MAX);
    return -1;
}

static void daemon_json(sb_t *out, int i) {
    sp_daemon_t *d = &g_sp.daemons[i];
    int run = SP_LD(d->running);
    uint64_t st = SP_LD(d->start_time);
    uint64_t up = (run && st) ? sp_now_ms() - st : 0;
    sb_printf(out, "{\"id\":%d,\"name\":\"%s\",\"running\":%s,\"alive\":%s,\"restarts\":%d,\"uptime_ms\":%" PRIu64 "}",
              d->id, d->name, run ? "true" : "false", SP_LD(d->alive) ? "true" : "false",
              SP_LD(d->restart_count), up);
}

static int rpc_daemon_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"daemons\":[");
    for (i = 0; i < SP_DAEMON_MAX; i++) { if (i) sb_putn(out, ",", 1); daemon_json(out, i); }
    sb_puts(out, "]}");
    return 0;
}

static int rpc_daemon_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq;
    if (daemon_arg(params, &i, err, errsz) < 0) return -1;
    daemon_json(out, i);
    return 0;
}

static int rpc_daemon_start(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq;
    if (daemon_arg(params, &i, err, errsz) < 0) return -1;
    if (SP_LD(g_sp.daemons[i].alive)) {
        if (SP_LD(g_sp.daemons[i].running)) RPC_ERR("%s is already running", g_sp.daemons[i].name);
        RPC_ERR("%s is still stopping, retry in a second", g_sp.daemons[i].name);
    }
    if (sp_daemon_spawn(i) < 0) RPC_ERR("could not start %s", g_sp.daemons[i].name);
    daemon_json(out, i);
    return 0;
}

static int rpc_daemon_stop(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq;
    if (daemon_arg(params, &i, err, errsz) < 0) return -1;
    SP_ST(g_sp.daemons[i].running, 0);
    daemon_json(out, i);
    return 0;
}

static int rpc_daemon_restart(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq;
    if (daemon_arg(params, &i, err, errsz) < 0) return -1;
    if (SP_LD(g_sp.daemons[i].alive)) {        /* running or stopping: cancel stop, re-run */
        SP_ST(g_sp.daemons[i].running, 1);
        SP_ST(g_sp.daemons[i].restart_req, 1);
    } else if (sp_daemon_spawn(i) < 0) {
        RPC_ERR("could not start %s", g_sp.daemons[i].name);
    }
    daemon_json(out, i);
    return 0;
}

/* ── sp.bridge.* ────────────────────────────────────────────────────────────── */
static int rpc_bridge_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, pend = 0;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_pending_lock);
    for (i = 0; i < SPP_RPC_PENDING; i++) if (g_pending[i].used) pend++;
    pthread_mutex_unlock(&g_pending_lock);
    sb_printf(out, "{\"connected\":%s,\"port\":%d,\"rtt_ms\":%d,\"pending\":%d,", bridge_connected() ? "true" : "false",
              g_sp.bridge_port, bridge_connected() && g_sp.bridge_rtt_ms != UINT32_MAX ? (int)g_sp.bridge_rtt_ms : -1, pend);
    sb_caps(out, __atomic_load_n(&g_sp.bridge_caps, __ATOMIC_RELAXED));
    sb_putn(out, "}", 1);
    return 0;
}

static int rpc_bridge_latency(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    uint64_t sum = 0;
    size_t i, n = 0;
    int up = bridge_connected();
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_sp.peers_lock);
    for (i = 0; i < g_sp.peer_hi; i++) {
        spp_peer_t *p = &g_sp.peers[i];
        if (p->active && p->rtt_ms) { sum += p->rtt_ms; n++; }
    }
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (up) bridge_ping();                      /* refresh for the next call */
    sb_printf(out, "{\"bridge_ms\":%d,\"peer_avg_ms\":%" PRIu64 ",\"peer_samples\":%zu}",
              up && g_sp.bridge_rtt_ms != UINT32_MAX ? (int)g_sp.bridge_rtt_ms : -1, n ? sum / n : 0, n);
    return 0;
}

/* ── sp.spc.* (host-side SPCode runner) ─────────────────────────────────────── */
static int rpc_spc_run(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *src = json_str_dup(params, "src");
    int r;
    (void)rq;
    if (!src) RPC_ERR("src required");
    r = spc_run_caps(src, "<rpc>", rq->caller.caps);
    free(src);
    sb_printf(out, "{\"ok\":%s}", r == 0 ? "true" : "false");
    return 0;
}

static int rpc_spc_runfile(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *path = json_str_dup(params, "path");
    int r;
    (void)rq;
    if (!path) RPC_ERR("path required");
    r = spc_run_file(path);
    free(path);
    sb_printf(out, "{\"ok\":%s}", r == 0 ? "true" : "false");
    return 0;
}

/* ── sp.mem.* ───────────────────────────────────────────────────────────────── */
static int rpc_mem_alloc(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t size;
    int i, slot = -1;
    uint8_t *mem;
    if (json_get_i64(params, "size", &size) < 0 || size <= 0 || size > (int64_t)SP_MEM_MAX_REGION)
        RPC_ERR("size must be 1..%u", SP_MEM_MAX_REGION);
    mem = (uint8_t *)calloc(1, (size_t)size);
    if (!mem) RPC_ERR("out of memory");
    pthread_mutex_lock(&g_mem_lock);
    for (i = 0; i < SP_MEM_MAX_REGIONS; i++) if (!g_mem[i].p) { slot = i; break; }
    if (slot < 0 || g_mem_total + (size_t)size > SP_MEM_MAX_TOTAL) {
        int full = slot < 0;
        pthread_mutex_unlock(&g_mem_lock);
        free(mem);
        if (full) RPC_ERR("too many regions (max %d)", SP_MEM_MAX_REGIONS);
        RPC_ERR("memory limit reached (%u bytes total)", SP_MEM_MAX_TOTAL);
    }
    g_mem[slot].id = g_mem_next_id++;
    g_mem[slot].p = mem;
    g_mem[slot].size = (size_t)size;
    g_mem[slot].owner = rq->caller.kind == CALLER_PEER ? rq->caller.ref.conn : 0;
    g_mem_total += (size_t)size;
    sb_printf(out, "{\"id\":%u,\"size\":%zu}", g_mem[slot].id, g_mem[slot].size);
    pthread_mutex_unlock(&g_mem_lock);
    return 0;
}

static int rpc_mem_free(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t id;
    mem_region_t *r;
    (void)rq;
    if (json_get_i64(params, "id", &id) < 0) RPC_ERR("id required");
    pthread_mutex_lock(&g_mem_lock);
    r = mem_find_locked((uint32_t)id);
    if (r) { g_mem_total -= r->size; free(r->p); memset(r, 0, sizeof(*r)); }
    pthread_mutex_unlock(&g_mem_lock);
    if (!r) RPC_ERR("no such region");
    sb_puts(out, "{\"freed\":true}");
    return 0;
}

static int rpc_mem_read(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t id, off = 0, len;
    mem_region_t *r;
    size_t i;
    (void)rq;
    if (json_get_i64(params, "id", &id) < 0 || json_get_i64(params, "len", &len) < 0) RPC_ERR("id and len required");
    json_get_i64(params, "offset", &off);
    if (off < 0 || len < 0 || len > SP_MEM_IO_MAX) RPC_ERR("len must be 0..%d", SP_MEM_IO_MAX);
    pthread_mutex_lock(&g_mem_lock);
    r = mem_find_locked((uint32_t)id);
    if (!r) { pthread_mutex_unlock(&g_mem_lock); RPC_ERR("no such region"); }
    if ((uint64_t)off > r->size || (uint64_t)len > r->size - (uint64_t)off) {
        pthread_mutex_unlock(&g_mem_lock);
        RPC_ERR("out of bounds (size %zu)", r->size);
    }
    sb_puts(out, "{\"hex\":\"");
    for (i = 0; i < (size_t)len; i++) sb_printf(out, "%02x", r->p[(size_t)off + i]);
    sb_printf(out, "\",\"len\":%" PRId64 "}", len);
    pthread_mutex_unlock(&g_mem_lock);
    return 0;
}

static int rpc_mem_write(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t id, off = 0;
    char *hex;
    size_t hl, n, i;
    mem_region_t *r;
    (void)rq;
    if (json_get_i64(params, "id", &id) < 0) RPC_ERR("id required");
    json_get_i64(params, "offset", &off);
    hex = json_str_dup(params, "hex");
    if (!hex) RPC_ERR("hex required");
    hl = strlen(hex);
    n = hl / 2;
    if (off < 0 || (hl & 1) || n > SP_MEM_IO_MAX) { free(hex); RPC_ERR("hex must be an even length, at most %d bytes", SP_MEM_IO_MAX); }
    for (i = 0; i < hl; i++) if (hexv((unsigned char)hex[i]) < 0) { free(hex); RPC_ERR("bad hex"); }
    pthread_mutex_lock(&g_mem_lock);
    r = mem_find_locked((uint32_t)id);
    if (!r) { pthread_mutex_unlock(&g_mem_lock); free(hex); RPC_ERR("no such region"); }
    if ((uint64_t)off > r->size || (uint64_t)n > r->size - (uint64_t)off) {
        pthread_mutex_unlock(&g_mem_lock); free(hex);
        RPC_ERR("out of bounds (size %zu)", r->size);
    }
    for (i = 0; i < n; i++) r->p[(size_t)off + i] = (uint8_t)(hexv((unsigned char)hex[2*i]) * 16 + hexv((unsigned char)hex[2*i+1]));
    pthread_mutex_unlock(&g_mem_lock);
    free(hex);
    sb_printf(out, "{\"written\":%zu}", n);
    return 0;
}

static int rpc_mem_info(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, n = 0;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_mem_lock);
    for (i = 0; i < SP_MEM_MAX_REGIONS; i++) if (g_mem[i].p) n++;
    sb_printf(out, "{\"regions\":%d,\"bytes\":%zu,\"max_regions\":%d,\"max_bytes\":%u,\"max_region\":%u}",
              n, g_mem_total, SP_MEM_MAX_REGIONS, SP_MEM_MAX_TOTAL, SP_MEM_MAX_REGION);
    pthread_mutex_unlock(&g_mem_lock);
    return 0;
}

static int rpc_mem_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, first = 1;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"regions\":[");
    pthread_mutex_lock(&g_mem_lock);
    for (i = 0; i < SP_MEM_MAX_REGIONS; i++) {
        if (!g_mem[i].p) continue;
        sb_printf(out, "%s{\"id\":%u,\"size\":%zu,\"owner\":%" PRIu64 "}", first ? "" : ",", g_mem[i].id, g_mem[i].size, g_mem[i].owner);
        first = 0;
        if (out->len > SPP_MAX_PAYLOAD - 512) break;
    }
    pthread_mutex_unlock(&g_mem_lock);
    sb_puts(out, "]}");
    return 0;
}

/* ── forwarding to the JS layer (fs.*, spmem.*, audit.*, ... and the JS side of drivers) ────
 * C never touches the host disk for these: the browser's SP does the work and answers with an
 * {"spp":"rpc_result"} frame. Callers decide which methods may be forwarded (g_js_methods). */
static int rpc_forward_js(const rpc_req_t *rq, const char *method, const char *params,
                          sb_t *out, char *err, size_t errsz) {
    int i, idx = -1, waiter = rq->caller.kind == CALLER_TERMINAL;
    sb_t req;
    int sent;

    if (rq->caller.kind == CALLER_BRIDGE) RPC_ERR("%.32s is served by the JS layer, it cannot be called from it", method);
    if (!bridge_connected()) RPC_ERR("browser bridge is offline: the JS layer is unreachable");
    if (*json_skip_ws(params) != '{') RPC_ERR("params must be an object");
    if (strlen(params) > SPP_MAX_PAYLOAD - 512) RPC_ERR("params too large");

    pthread_mutex_lock(&g_pending_lock);
    for (i = 0; i < SPP_RPC_PENDING; i++) if (!g_pending[i].used) { idx = i; break; }
    if (idx < 0) { pthread_mutex_unlock(&g_pending_lock); RPC_ERR("too many pending requests"); }
    memset(&g_pending[idx], 0, sizeof(g_pending[idx]));
    g_pending[idx].used = 1;
    g_pending[idx].waiter = waiter;
    g_pending[idx].bid = ++g_next_bid;
    g_pending[idx].req_id = rq->id;
    g_pending[idx].has_id = rq->has_id;
    g_pending[idx].caller = rq->caller;
    g_pending[idx].t0_us = rq->t0_us;
    memcpy(g_pending[idx].mname, rq->mname, sizeof(g_pending[idx].mname));
    g_pending[idx].deadline_ms = sp_now_ms() + SPP_RPC_TIMEOUT_MS;
    {
        uint64_t bid = g_pending[idx].bid;
        pthread_mutex_unlock(&g_pending_lock);

        sb_init(&req);
        sb_printf(&req, "{\"spp\":\"rpc\",\"id\":%" PRIu64 ",\"method\":", bid);
        sb_json_str(&req, method);
        sb_puts(&req, ",\"params\":");
        sb_puts(&req, params);
        sb_putn(&req, "}", 1);
        sent = req.err ? -1 : bridge_send_text(req.p, req.len);
        sb_free(&req);
    }
    if (sent < 0) {
        pthread_mutex_lock(&g_pending_lock);
        g_pending[idx].used = 0;
        pthread_mutex_unlock(&g_pending_lock);
        RPC_ERR("could not send to the bridge");
    }
    if (!waiter) return 1;                      /* async: bridge_rpc_result() replies later */

    {   /* terminal: block until the JS layer answers (or the deadline passes) */
        struct timespec ts;
        int ok;
        char *res;
        uint64_t left;
        pthread_mutex_lock(&g_pending_lock);
        while (!g_pending[idx].done) {
            uint64_t now = sp_now_ms();
            if (now >= g_pending[idx].deadline_ms) break;
            left = g_pending[idx].deadline_ms - now;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            ts.tv_sec  += (time_t)(left / 1000);
            ts.tv_nsec += (long)(left % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            pthread_cond_timedwait(&g_pending_cv, &g_pending_lock, &ts);
        }
        ok  = g_pending[idx].done && g_pending[idx].ok;
        res = g_pending[idx].done ? g_pending[idx].result : strdup("timeout waiting for the JS layer");
        g_pending[idx].used = 0;
        pthread_mutex_unlock(&g_pending_lock);
        if (ok) { sb_puts(out, res ? res : "null"); free(res); return 0; }
        snprintf(err, errsz, "%s", res ? res : "error");
        free(res);
        return -1;
    }
}

/* Called by the bridge thread when the JS layer answers a forwarded request. */
static void bridge_rpc_result(const char *text) {
    uint64_t bid;
    const char *okp;
    int ok, i, idx = -1;
    char *res = NULL, *errs = NULL;
    rpc_pending_t snap;

    if (json_get_u64(text, "id", &bid) < 0) return;
    okp = json_find(text, "ok");
    ok = okp && strncmp(okp, "true", 4) == 0;
    if (ok) res = json_raw_dup(text, "result"); else errs = json_str_dup(text, "error");

    pthread_mutex_lock(&g_pending_lock);
    for (i = 0; i < SPP_RPC_PENDING; i++)
        if (g_pending[i].used && g_pending[i].bid == bid) { idx = i; break; }
    if (idx < 0) { pthread_mutex_unlock(&g_pending_lock); free(res); free(errs); return; }
    if (g_pending[idx].waiter) {
        g_pending[idx].ok = ok;
        g_pending[idx].result = ok ? (res ? res : strdup("null")) : (errs ? errs : strdup("error"));
        g_pending[idx].done = 1;
        pthread_cond_broadcast(&g_pending_cv);
        pthread_mutex_unlock(&g_pending_lock);
        free(ok ? errs : res);
        return;
    }
    snap = g_pending[idx];
    g_pending[idx].used = 0;
    pthread_mutex_unlock(&g_pending_lock);
    rpc_reply(&snap.caller, snap.has_id, snap.req_id, ok, ok ? (res ? res : "null") : (errs ? errs : "error"));
    trace_record(snap.caller.kind, snap.caller.ref.conn, snap.mname, ok, ok ? NULL : (errs ? errs : "error"), snap.t0_us);
    free(res);
    free(errs);
}

/* Fails forwarded requests: all of them (bridge went away) or only expired ones. */
static void pending_fail(const char *why, int only_expired) {
    for (;;) {
        rpc_pending_t snap;
        int i, found = -1;
        uint64_t now = sp_now_ms();
        pthread_mutex_lock(&g_pending_lock);
        for (i = 0; i < SPP_RPC_PENDING; i++) {
            rpc_pending_t *e = &g_pending[i];
            if (!e->used) continue;
            if (e->waiter) {                    /* terminal waiters enforce their own deadline */
                if (!only_expired && !e->done) {
                    e->ok = 0; e->result = strdup(why); e->done = 1;
                    pthread_cond_broadcast(&g_pending_cv);
                }
                continue;
            }
            if (only_expired && e->deadline_ms > now) continue;
            found = i;
            break;
        }
        if (found < 0) { pthread_mutex_unlock(&g_pending_lock); return; }
        snap = g_pending[found];
        g_pending[found].used = 0;
        pthread_mutex_unlock(&g_pending_lock);
        rpc_reply(&snap.caller, snap.has_id, snap.req_id, 0, why);
        trace_record(snap.caller.kind, snap.caller.ref.conn, snap.mname, 0, why, snap.t0_us);
    }
}

/* ── SPP drivers ──────────────────────────────────────────────────────────────
 * A driver is a local file the user installs into the drivers dir to extend SPP:
 *   kind "c"   a shared library (.so) loaded into this process with dlopen
 *   kind "js"  a script run by the JS layer (the browser) that registers methods there
 * Native code is arbitrary code, so the rules are strict:
 *   - install / approve / load / unload / remove are terminal-only, never reachable from peers
 *   - a driver can only be loaded after `driver.approve` with its exact SHA-256
 *   - the bytes that were hashed are the bytes that run (C drivers are dlopen'ed from a memfd copy)
 *   - names are [A-Za-z0-9_-]{1,39}; files are opened O_NOFOLLOW inside one directory that must be
 *     owned by us and not group/world writable
 * C driver ABI (version 1):
 *     #include <stddef.h>
 *     #include <stdint.h>
 *     typedef int (*sp_driver_fn)(const char *params, char *out, size_t outsz, char *err, size_t errsz);
 *     typedef struct { uint32_t abi; void (*log)(const char *msg);
 *                      int (*reg)(const char *method, sp_driver_fn fn, uint8_t need_caps); } sp_driver_host;
 *     int  sp_driver_init(const sp_driver_host *h);   // register methods with h->reg; return 0
 *     void sp_driver_fini(void);                       // optional
 *   A method writes a JSON value to out (or an error text to err) and returns 0 / -1.
 *   Calls are serialised (one driver call at a time) and run on the caller's thread.
 * JS driver source is the body of a function taking (sp, log) and returning
 *     { methods: { name: async (params) => value } }
 * Call a method with: driver.call {"name":"x","method":"m","params":{...}}                       */
#ifdef SP_PLATFORM_UNIX
#define SP_DRV_MAX        32
#define SP_DRV_METHODS    32
#define SP_DRV_ABI        1
#define SP_DRV_MAX_C      (8u << 20)
#define SP_DRV_MAX_JS     32000u

typedef int (*sp_driver_fn)(const char *params, char *out, size_t outsz, char *err, size_t errsz);
typedef struct sp_driver_host {
    uint32_t abi;
    void   (*log)(const char *msg);
    int    (*reg)(const char *method, sp_driver_fn fn, uint8_t need_caps);
} sp_driver_host;

typedef struct { char name[40]; sp_driver_fn fn; uint8_t need; } drv_method_t;
typedef struct {
    int      used, kind;                    /* 1 = js, 2 = c */
    char     name[40], sha[65];
    uint8_t  jscaps;                        /* extra caps a caller needs for a JS driver */
    void    *handle;
    void   (*fini)(void);
    int      nm;
    drv_method_t m[SP_DRV_METHODS];
} drv_t;

static drv_t g_drv[SP_DRV_MAX];
static pthread_mutex_t g_drv_lock = PTHREAD_MUTEX_INITIALIZER;
static drv_t *g_drv_loading;

/* SHA-256 (only used to pin driver files) */
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
static void sha256_hex(const uint8_t *d, size_t n, char out[65]) {
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint8_t tail[128];
    size_t i, full = n / 64, rem = n % 64, tl;
    uint64_t bits = (uint64_t)n * 8;
    for (i = 0; i < full; i++) sha256_block(h, d + 64 * i);
    memset(tail, 0, sizeof(tail));
    if (rem) memcpy(tail, d + 64 * full, rem);
    tail[rem] = 0x80;
    tl = rem < 56 ? 64 : 128;
    for (i = 0; i < 8; i++) tail[tl - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha256_block(h, tail);
    if (tl == 128) sha256_block(h, tail + 64);
    for (i = 0; i < 8; i++) sprintf(out + 8 * i, "%08x", h[i]);
    out[64] = '\0';
}

static int drv_name_ok(const char *s) {
    size_t n = s ? strlen(s) : 0, i;
    if (n < 1 || n > 39) return 0;
    for (i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-') return 0;
    return 1;
}

static int drv_dir_ok(char *err, size_t errsz) {
    struct stat st;
    const char *d = g_sp.drivers_dir[0] ? g_sp.drivers_dir : "sp_drivers";
    if (mkdir(d, 0700) < 0 && errno != EEXIST) { snprintf(err, errsz, "cannot create drivers dir: %s", strerror(errno)); return -1; }
    if (lstat(d, &st) < 0 || !S_ISDIR(st.st_mode)) { snprintf(err, errsz, "drivers dir is not a plain directory"); return -1; }
    if (st.st_uid != geteuid() || (st.st_mode & 022)) {
        snprintf(err, errsz, "drivers dir must be owned by this user and not group/world writable");
        return -1;
    }
    return 0;
}

static void drv_path(char *buf, size_t n, const char *name, const char *ext) {
    snprintf(buf, n, "%s/%s.%s", g_sp.drivers_dir[0] ? g_sp.drivers_dir : "sp_drivers", name, ext);
}

/* Reads a whole regular file (<= max bytes) from an open fd; result is NUL-terminated. */
static int drv_read_fd(int fd, size_t max, uint8_t **buf, size_t *len) {
    struct stat st;
    size_t off = 0;
    uint8_t *b;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || (size_t)st.st_size > max) return -1;
    b = (uint8_t *)malloc((size_t)st.st_size + 1);
    if (!b) return -1;
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, b + off, (size_t)st.st_size - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(b); return -1; }
        off += (size_t)n;
    }
    b[off] = 0;
    *buf = b; *len = off;
    return 0;
}

static int drv_write_file(const char *path, const uint8_t *d, size_t n) {
    char tmp[320];
    size_t off = 0;
    int fd;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (off < n) {
        ssize_t w = write(fd, d + off, n - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    if (close(fd) < 0 || rename(tmp, path) < 0) { unlink(tmp); return -1; }
    return 0;
}

typedef struct { char kind[4]; char sha[65]; char approved[65]; unsigned caps; } drv_meta_t;

static int drv_meta_read(const char *name, drv_meta_t *m) {
    char path[320], line[200];
    int fd;
    FILE *f;
    memset(m, 0, sizeof(*m));
    drv_path(path, sizeof(path), name, "meta");
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strncmp(line, "kind=", 5) == 0)          snprintf(m->kind, sizeof(m->kind), "%s", line + 5);
        else if (strncmp(line, "sha256=", 7) == 0)   snprintf(m->sha, sizeof(m->sha), "%s", line + 7);
        else if (strncmp(line, "approved=", 9) == 0) snprintf(m->approved, sizeof(m->approved), "%s", line + 9);
        else if (strncmp(line, "caps=", 5) == 0)     m->caps = (unsigned)strtoul(line + 5, NULL, 10) & SPCAP_ALL;
    }
    fclose(f);
    return (strcmp(m->kind, "js") == 0 || strcmp(m->kind, "c") == 0) && strlen(m->sha) == 64 ? 0 : -1;
}

static int drv_meta_write(const char *name, const drv_meta_t *m) {
    char path[320], body[300];
    int n = snprintf(body, sizeof(body), "kind=%s\nsha256=%s\napproved=%s\ncaps=%u\n", m->kind, m->sha, m->approved, m->caps);
    drv_path(path, sizeof(path), name, "meta");
    return drv_write_file(path, (const uint8_t *)body, (size_t)n);
}

/* Reads the installed driver file named by the meta. Returns NUL-terminated bytes. */
static int drv_file_bytes(const char *name, const drv_meta_t *m, uint8_t **buf, size_t *len) {
    char path[320];
    int fd, rc;
    drv_path(path, sizeof(path), name, strcmp(m->kind, "c") == 0 ? "so" : "js");
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    rc = drv_read_fd(fd, strcmp(m->kind, "c") == 0 ? SP_DRV_MAX_C : SP_DRV_MAX_JS, buf, len);
    close(fd);
    return rc;
}

static drv_t *drv_find_locked(const char *name) {
    int i;
    for (i = 0; i < SP_DRV_MAX; i++) if (g_drv[i].used && strcmp(g_drv[i].name, name) == 0) return &g_drv[i];
    return NULL;
}

static void drv_host_log(const char *msg) { SP_LOG("driver: %.200s", msg ? msg : ""); }

static int drv_host_reg(const char *method, sp_driver_fn fn, uint8_t need) {
    drv_t *d = g_drv_loading;       /* g_drv_lock is held by driver.load for the whole init call */
    size_t i, n = method ? strlen(method) : 0;
    int k;
    if (!d || !fn || n < 1 || n > 39 || d->nm >= SP_DRV_METHODS) return -1;
    for (i = 0; i < n; i++)
        if (!isalnum((unsigned char)method[i]) && method[i] != '_' && method[i] != '.' && method[i] != '-') return -1;
    for (k = 0; k < d->nm; k++) if (strcmp(d->m[k].name, method) == 0) return -1;
    snprintf(d->m[d->nm].name, sizeof(d->m[d->nm].name), "%s", method);
    d->m[d->nm].fn = fn;
    d->m[d->nm].need = need & SPCAP_ALL;
    d->nm++;
    return 0;
}

static int json_true(const char *params, const char *key) {
    const char *p = json_find(params, key);
    return p && strncmp(p, "true", 4) == 0;
}

#define DRV_FAIL(...) do { snprintf(err, errsz, __VA_ARGS__); goto done; } while (0)

static int rpc_driver_install(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name"), *kind = json_str_dup(params, "kind");
    char *path = json_str_dup(params, "path"), *src = json_str_dup(params, "source");
    uint8_t *data = NULL;
    size_t len = 0;
    char dst[320], other[320];
    drv_meta_t old, m;
    uint8_t caps = 0;
    int rc = -1, isc;
    (void)rq;

    if (!name || !drv_name_ok(name)) DRV_FAIL("name must be 1-39 characters of [A-Za-z0-9_-]");
    if (!kind || (strcmp(kind, "js") != 0 && strcmp(kind, "c") != 0)) DRV_FAIL("kind must be \"js\" or \"c\"");
    isc = strcmp(kind, "c") == 0;
    if (drv_dir_ok(err, errsz) < 0) goto done;
    if (json_find(params, "caps") && parse_caps(params, &caps) < 0) DRV_FAIL("bad caps");
    if (drv_meta_read(name, &old) == 0) {
        int busy;
        if (!json_true(params, "replace")) DRV_FAIL("driver exists (pass \"replace\":true; replacing resets its approval)");
        pthread_mutex_lock(&g_drv_lock);
        busy = drv_find_locked(name) != NULL;
        pthread_mutex_unlock(&g_drv_lock);
        if (busy) DRV_FAIL("driver is loaded: unload it first");
    }
    if (path) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) DRV_FAIL("cannot open %.100s: %s", path, strerror(errno));
        if (drv_read_fd(fd, isc ? SP_DRV_MAX_C : SP_DRV_MAX_JS, &data, &len) < 0) { close(fd); DRV_FAIL("not a regular file, or larger than %u bytes", isc ? SP_DRV_MAX_C : SP_DRV_MAX_JS); }
        close(fd);
    } else if (src && !isc) {
        len = strlen(src);
        if (len > SP_DRV_MAX_JS) DRV_FAIL("source larger than %u bytes", SP_DRV_MAX_JS);
        data = (uint8_t *)strdup(src);
        if (!data) DRV_FAIL("out of memory");
    } else {
        DRV_FAIL("give \"path\" (a local file) or, for kind js, \"source\"");
    }
    if (len == 0) DRV_FAIL("empty file");
    if (isc && (len < 4 || memcmp(data, "\x7f" "ELF", 4) != 0)) DRV_FAIL("not an ELF shared object");

    memset(&m, 0, sizeof(m));
    snprintf(m.kind, sizeof(m.kind), "%s", kind);
    sha256_hex(data, len, m.sha);
    m.caps = caps;
    drv_path(dst, sizeof(dst), name, isc ? "so" : "js");
    drv_path(other, sizeof(other), name, isc ? "js" : "so");
    if (drv_write_file(dst, data, len) < 0) DRV_FAIL("write failed: %s", strerror(errno));
    unlink(other);
    if (drv_meta_write(name, &m) < 0) DRV_FAIL("meta write failed: %s", strerror(errno));
    sb_printf(out, "{\"name\":\"%s\",\"kind\":\"%s\",\"size\":%zu,\"sha256\":\"%s\",\"approved\":false}", name, kind, len, m.sha);
    rc = 0;
done:
    free(name); free(kind); free(path); free(src); free(data);
    return rc;
}

static int rpc_driver_approve(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name"), *sha = json_str_dup(params, "sha256");
    drv_meta_t m;
    uint8_t *data = NULL;
    size_t len = 0;
    char now[65];
    int rc = -1;
    (void)rq;
    if (!name || !drv_name_ok(name)) DRV_FAIL("name required");
    if (drv_dir_ok(err, errsz) < 0) goto done;
    if (drv_meta_read(name, &m) < 0) DRV_FAIL("no such driver: %.40s", name);
    if (drv_file_bytes(name, &m, &data, &len) < 0) DRV_FAIL("driver file missing or unreadable");
    sha256_hex(data, len, now);
    if (strcmp(now, m.sha) != 0) DRV_FAIL("file changed since install (sha256 now %s): reinstall it", now);
    if (!sha || strcmp(sha, now) != 0) DRV_FAIL("sha256 required and must match the installed file: %s", now);
    snprintf(m.approved, sizeof(m.approved), "%s", now);
    if (drv_meta_write(name, &m) < 0) DRV_FAIL("meta write failed: %s", strerror(errno));
    sb_printf(out, "{\"name\":\"%s\",\"approved\":true,\"sha256\":\"%s\"}", name, now);
    rc = 0;
done:
    free(name); free(sha); free(data);
    return rc;
}

static int rpc_driver_remove(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    char path[320];
    int rc = -1, busy;
    (void)rq;
    if (!name || !drv_name_ok(name)) DRV_FAIL("name required");
    pthread_mutex_lock(&g_drv_lock);
    busy = drv_find_locked(name) != NULL;
    pthread_mutex_unlock(&g_drv_lock);
    if (busy) DRV_FAIL("driver is loaded: unload it first");
    drv_path(path, sizeof(path), name, "meta");
    if (unlink(path) < 0) DRV_FAIL("no such driver: %.40s", name);
    drv_path(path, sizeof(path), name, "so");  unlink(path);
    drv_path(path, sizeof(path), name, "js");  unlink(path);
    sb_printf(out, "{\"name\":\"%s\",\"removed\":true}", name);
    rc = 0;
done:
    free(name);
    return rc;
}

static int rpc_driver_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    DIR *d;
    struct dirent *e;
    int first = 1, i;
    (void)rq; (void)params;
    if (drv_dir_ok(err, errsz) < 0) return -1;
    d = opendir(g_sp.drivers_dir[0] ? g_sp.drivers_dir : "sp_drivers");
    if (!d) RPC_ERR("cannot read drivers dir: %s", strerror(errno));
    sb_printf(out, "{\"dir\":");
    sb_json_str(out, g_sp.drivers_dir[0] ? g_sp.drivers_dir : "sp_drivers");
    sb_puts(out, ",\"drivers\":[");
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        char name[40];
        drv_meta_t m;
        drv_t *l;
        if (n < 6 || n > 39 + 5 || strcmp(e->d_name + n - 5, ".meta") != 0) continue;
        memcpy(name, e->d_name, n - 5);
        name[n - 5] = '\0';
        if (!drv_name_ok(name) || drv_meta_read(name, &m) < 0) continue;
        pthread_mutex_lock(&g_drv_lock);
        l = drv_find_locked(name);
        sb_printf(out, "%s{\"name\":\"%s\",\"kind\":\"%s\",\"sha256\":\"%s\",\"approved\":%s,\"loaded\":%s,\"methods\":[",
                  first ? "" : ",", name, m.kind, m.sha, strcmp(m.approved, m.sha) == 0 ? "true" : "false", l ? "true" : "false");
        if (l && l->kind == 2)
            for (i = 0; i < l->nm; i++) sb_printf(out, "%s\"%s\"", i ? "," : "", l->m[i].name);
        pthread_mutex_unlock(&g_drv_lock);
        sb_puts(out, "]}");
        first = 0;
        if (out->len > SPP_MAX_PAYLOAD - 1024) break;
    }
    closedir(d);
    sb_puts(out, "]}");
    return 0;
}

static int rpc_driver_load(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    drv_meta_t m;
    uint8_t *data = NULL;
    size_t len = 0;
    char now[65];
    int rc = -1, i, slot = -1;
    if (!name || !drv_name_ok(name)) DRV_FAIL("name required");
    if (drv_dir_ok(err, errsz) < 0) goto done;
    if (drv_meta_read(name, &m) < 0) DRV_FAIL("no such driver: %.40s", name);
    if (strcmp(m.approved, m.sha) != 0 || !m.approved[0])
        DRV_FAIL("not approved: run driver.approve with sha256 %s", m.sha);
    if (drv_file_bytes(name, &m, &data, &len) < 0) DRV_FAIL("driver file missing or unreadable");
    sha256_hex(data, len, now);
    if (strcmp(now, m.approved) != 0) DRV_FAIL("file changed since approval (sha256 now %s): refusing to load", now);

    pthread_mutex_lock(&g_drv_lock);
    if (drv_find_locked(name)) { pthread_mutex_unlock(&g_drv_lock); DRV_FAIL("already loaded"); }
    for (i = 0; i < SP_DRV_MAX; i++) if (!g_drv[i].used) { slot = i; break; }
    pthread_mutex_unlock(&g_drv_lock);
    if (slot < 0) DRV_FAIL("too many drivers loaded");

    if (strcmp(m.kind, "c") == 0) {
        char so[96];
        int mfd = -1;
        void *h;
        int (*init)(const sp_driver_host *);
        void (*fini)(void);
        sp_driver_host host;
        int r;
        size_t off = 0;
#if defined(__linux__) && defined(SYS_memfd_create)
        mfd = (int)syscall(SYS_memfd_create, "spdrv", 0);     /* what we hashed is what we load */
#endif
        if (mfd >= 0) {
            while (off < len) {
                ssize_t w = write(mfd, data + off, len - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) break;
                off += (size_t)w;
            }
            if (off != len) { close(mfd); DRV_FAIL("could not stage the driver"); }
            snprintf(so, sizeof(so), "/proc/self/fd/%d", mfd);
        } else {
            drv_path(so, sizeof(so), name, "so");
        }
        h = dlopen(so, RTLD_NOW | RTLD_LOCAL);
        if (mfd >= 0) close(mfd);
        if (!h) DRV_FAIL("dlopen: %.150s", dlerror());
        *(void **)(&init) = dlsym(h, "sp_driver_init");
        *(void **)(&fini) = dlsym(h, "sp_driver_fini");
        if (!init) { dlclose(h); DRV_FAIL("driver has no sp_driver_init"); }
        host.abi = SP_DRV_ABI; host.log = drv_host_log; host.reg = drv_host_reg;
        pthread_mutex_lock(&g_drv_lock);
        memset(&g_drv[slot], 0, sizeof(g_drv[slot]));
        g_drv[slot].used = 1; g_drv[slot].kind = 2;
        snprintf(g_drv[slot].name, sizeof(g_drv[slot].name), "%s", name);
        snprintf(g_drv[slot].sha, sizeof(g_drv[slot].sha), "%s", now);
        g_drv[slot].handle = h; g_drv[slot].fini = fini;
        g_drv_loading = &g_drv[slot];
        r = init(&host);
        g_drv_loading = NULL;
        if (r != 0) {
            if (fini) fini();
            dlclose(h);
            memset(&g_drv[slot], 0, sizeof(g_drv[slot]));
            pthread_mutex_unlock(&g_drv_lock);
            DRV_FAIL("sp_driver_init returned %d", r);
        }
        sb_printf(out, "{\"name\":\"%s\",\"kind\":\"c\",\"sha256\":\"%s\",\"methods\":[", name, now);
        for (i = 0; i < g_drv[slot].nm; i++) sb_printf(out, "%s\"%s\"", i ? "," : "", g_drv[slot].m[i].name);
        sb_puts(out, "]}");
        pthread_mutex_unlock(&g_drv_lock);
        SP_LOG("driver '%s' loaded (c, %d methods)", name, g_drv[slot].nm);
        rc = 0;
    } else {
        sb_t req, res;
        int fr;
        sb_init(&req); sb_init(&res);
        sb_puts(&req, "{\"name\":\"");
        sb_puts(&req, name);
        sb_printf(&req, "\",\"caps\":%u,\"source\":", m.caps);
        sb_json_str(&req, (const char *)data);
        sb_putn(&req, "}", 1);
        if (req.err) { sb_free(&req); sb_free(&res); DRV_FAIL("out of memory"); }
        fr = rpc_forward_js(rq, "jsdriver.load", req.p, &res, err, errsz);
        sb_free(&req);
        if (fr == 0) {
            pthread_mutex_lock(&g_drv_lock);
            memset(&g_drv[slot], 0, sizeof(g_drv[slot]));
            g_drv[slot].used = 1; g_drv[slot].kind = 1;
            g_drv[slot].jscaps = (uint8_t)m.caps;
            snprintf(g_drv[slot].name, sizeof(g_drv[slot].name), "%s", name);
            snprintf(g_drv[slot].sha, sizeof(g_drv[slot].sha), "%s", now);
            pthread_mutex_unlock(&g_drv_lock);
            sb_printf(out, "{\"name\":\"%s\",\"kind\":\"js\",\"sha256\":\"%s\",\"js\":%s}", name, now, res.p ? res.p : "null");
            SP_LOG("driver '%s' loaded (js)", name);
            rc = 0;
        } else if (fr > 0) {
            snprintf(err, errsz, "internal: async forward from a terminal-only method");
        }
        sb_free(&res);
    }
done:
    free(name); free(data);
    return rc;
}

static int rpc_driver_unload(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    drv_t *d;
    int rc = -1, kind = 0;
    if (!name || !drv_name_ok(name)) DRV_FAIL("name required");
    pthread_mutex_lock(&g_drv_lock);
    d = drv_find_locked(name);
    if (!d) { pthread_mutex_unlock(&g_drv_lock); DRV_FAIL("not loaded"); }
    kind = d->kind;
    if (kind == 2) {
        if (d->fini) d->fini();
        dlclose(d->handle);
        memset(d, 0, sizeof(*d));
    }
    pthread_mutex_unlock(&g_drv_lock);
    if (kind == 1) {                            /* JS side: best effort, the slot is freed either way */
        sb_t req, res;
        sb_init(&req); sb_init(&res);
        sb_printf(&req, "{\"name\":\"%s\"}", name);
        rpc_forward_js(rq, "jsdriver.unload", req.p, &res, err, errsz);
        sb_free(&req); sb_free(&res);
        err[0] = '\0';
        pthread_mutex_lock(&g_drv_lock);
        d = drv_find_locked(name);
        if (d) memset(d, 0, sizeof(*d));
        pthread_mutex_unlock(&g_drv_lock);
    }
    sb_printf(out, "{\"name\":\"%s\",\"unloaded\":true}", name);
    SP_LOG("driver '%s' unloaded", name);
    rc = 0;
done:
    free(name);
    return rc;
}

static int rpc_driver_call(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name"), *method = json_str_dup(params, "method");
    char *pr = json_raw_dup(params, "params");
    char *obuf = NULL, ebuf[200] = "", nb[48];
    drv_t *d;
    int rc = -1, k;
    if (!name || !drv_name_ok(name) || !method) DRV_FAIL("name and method required");
    if (!pr) pr = strdup("{}");
    if (!pr) DRV_FAIL("out of memory");
    pthread_mutex_lock(&g_drv_lock);
    d = drv_find_locked(name);
    if (!d) { pthread_mutex_unlock(&g_drv_lock); DRV_FAIL("driver not loaded: %.40s", name); }
    if (d->kind == 2) {
        drv_method_t *dm = NULL;
        int r;
        for (k = 0; k < d->nm; k++) if (strcmp(d->m[k].name, method) == 0) dm = &d->m[k];
        if (!dm) { pthread_mutex_unlock(&g_drv_lock); DRV_FAIL("driver %.40s has no method %.40s", name, method); }
        if ((rq->caller.caps & dm->need) != dm->need) {
            pthread_mutex_unlock(&g_drv_lock);
            DRV_FAIL("denied: needs cap %s", need_str(dm->need, nb, sizeof(nb)));
        }
        obuf = (char *)calloc(1, 32768);
        if (!obuf) { pthread_mutex_unlock(&g_drv_lock); DRV_FAIL("out of memory"); }
        r = dm->fn(pr, obuf, 32768, ebuf, sizeof(ebuf));
        pthread_mutex_unlock(&g_drv_lock);
        obuf[32767] = '\0'; ebuf[sizeof(ebuf) - 1] = '\0';
        if (r != 0) DRV_FAIL("%s", ebuf[0] ? ebuf : "driver error");
        sb_puts(out, obuf[0] ? obuf : "null");
        rc = 0;
    } else {
        uint8_t need = (uint8_t)(SPCAP_JS | SPCAP_OP | d->jscaps);
        sb_t req;
        pthread_mutex_unlock(&g_drv_lock);
        if ((rq->caller.caps & need) != need) DRV_FAIL("denied: needs cap %s", need_str(need, nb, sizeof(nb)));
        sb_init(&req);
        sb_printf(&req, "{\"name\":\"%s\",\"method\":", name);
        sb_json_str(&req, method);
        sb_puts(&req, ",\"params\":");
        sb_puts(&req, pr);
        sb_putn(&req, "}", 1);
        if (req.err) { sb_free(&req); DRV_FAIL("out of memory"); }
        rc = rpc_forward_js(rq, "jsdriver.call", req.p, out, err, errsz);
        sb_free(&req);
    }
done:
    free(name); free(method); free(pr); free(obuf);
    return rc;
}
#undef DRV_FAIL
#endif /* SP_PLATFORM_UNIX */

/* ── host services: trace, config, browser supervisor, token, cron, peer messaging, relay ──── */
#ifdef SP_PLATFORM_UNIX
static int json_bool_arg(const char *params, const char *key, int dflt) {
    const char *p = json_find(params, key);
    if (!p) return dflt;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return dflt;
}

static const char *caller_name(int kind) { return kind == CALLER_TERMINAL ? "terminal" : (kind == CALLER_BRIDGE ? "bridge" : "peer"); }

/* who is calling, as a short string for envelopes: "terminal" | "bridge" | "peer:<conn>" */
static void caller_label(const rpc_req_t *rq, char *buf, size_t n) {
    if (rq->caller.kind == CALLER_PEER) snprintf(buf, n, "peer:%" PRIu64, rq->caller.ref.conn);
    else snprintf(buf, n, "%s", caller_name(rq->caller.kind));
}

/* ---- trace.*: every RPC is timed (also denied ones, with the error text) ---- */
#ifndef BLOG_RATE
#define BLOG_RATE     200
#endif
#define TRACE_N        512
#define TRACE_METHODS  96
typedef struct { uint64_t seq, ts_ms, dur_us, conn; int kind, ok; char method[40]; char err[80]; } trace_t;
typedef struct { char name[40]; uint64_t count, errors, total_us, max_us; } trace_stat_t;
static trace_t g_trace[TRACE_N];
static trace_stat_t g_tstat[TRACE_METHODS];
static int g_tstat_n;
static uint64_t g_trace_seq;
static int g_trace_on = 1;
static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;

static void trace_record(int kind, uint64_t conn, const char *method, int ok, const char *err, uint64_t t0_us) {
    uint64_t dur = sp_now_us() - t0_us;
    trace_t *e;
    trace_stat_t *st = NULL;
    int i;
    if (!__atomic_load_n(&g_trace_on, __ATOMIC_RELAXED)) return;
    pthread_mutex_lock(&g_trace_lock);
    e = &g_trace[g_trace_seq % TRACE_N];
    g_trace_seq++;
    e->seq = g_trace_seq; e->ts_ms = sp_now_ms(); e->dur_us = dur; e->conn = conn; e->kind = kind; e->ok = ok;
    snprintf(e->method, sizeof(e->method), "%s", method ? method : "?");
    snprintf(e->err, sizeof(e->err), "%s", err ? err : "");
    for (i = 0; i < g_tstat_n; i++) if (strcmp(g_tstat[i].name, e->method) == 0) { st = &g_tstat[i]; break; }
    if (!st && g_tstat_n < TRACE_METHODS - 1) { st = &g_tstat[g_tstat_n++]; snprintf(st->name, sizeof(st->name), "%s", e->method); }
    if (!st) {                                  /* table full: lump the rest together */
        st = &g_tstat[TRACE_METHODS - 1];
        if (!st->name[0]) snprintf(st->name, sizeof(st->name), "(other)");
        if (g_tstat_n < TRACE_METHODS) g_tstat_n = TRACE_METHODS;
    }
    st->count++; if (!ok) st->errors++;
    st->total_us += dur; if (dur > st->max_us) st->max_us = dur;
    pthread_mutex_unlock(&g_trace_lock);
}

static int rpc_trace_tail(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t n = 50, slower = 0;
    int cnt = 0, i, only_err = json_bool_arg(params, "errors_only", 0);
    uint64_t sel[200], seq, lowest;
    char *m = json_str_dup(params, "method");
    (void)rq; (void)err; (void)errsz;
    json_get_i64(params, "n", &n);
    json_get_i64(params, "slower_ms", &slower);
    if (n < 1) n = 1;
    if (n > 200) n = 200;
    pthread_mutex_lock(&g_trace_lock);
    lowest = g_trace_seq > TRACE_N ? g_trace_seq - TRACE_N + 1 : 1;
    for (seq = g_trace_seq; seq >= lowest && seq >= 1 && cnt < n; seq--) {
        const trace_t *e = &g_trace[(seq - 1) % TRACE_N];
        if (e->seq != seq) continue;
        if (m && strcmp(e->method, m) != 0) continue;
        if (only_err && e->ok) continue;
        if (slower > 0 && e->dur_us < (uint64_t)slower * 1000u) continue;
        sel[cnt++] = seq;
    }
    sb_puts(out, "{\"entries\":[");
    for (i = cnt - 1; i >= 0; i--) {
        const trace_t *e = &g_trace[(sel[i] - 1) % TRACE_N];
        sb_printf(out, "%s{\"seq\":%" PRIu64 ",\"ts\":%" PRIu64 ",\"caller\":\"%s\",\"conn\":%" PRIu64 ",\"method\":",
                  i == cnt - 1 ? "" : ",", e->seq, e->ts_ms, caller_name(e->kind), e->conn);
        sb_json_str(out, e->method);
        sb_printf(out, ",\"ok\":%s,\"us\":%" PRIu64 ",\"error\":", e->ok ? "true" : "false", e->dur_us);
        sb_json_str(out, e->err);
        sb_putn(out, "}", 1);
    }
    sb_printf(out, "],\"total\":%" PRIu64 ",\"enabled\":%s}", g_trace_seq, g_trace_on ? "true" : "false");
    pthread_mutex_unlock(&g_trace_lock);
    free(m);
    return 0;
}

static int rpc_trace_stats(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, first = 1;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_trace_lock);
    sb_printf(out, "{\"enabled\":%s,\"total\":%" PRIu64 ",\"methods\":[", g_trace_on ? "true" : "false", g_trace_seq);
    for (i = 0; i < g_tstat_n; i++) {
        const trace_stat_t *t = &g_tstat[i];
        if (!t->count) continue;
        sb_printf(out, "%s{\"method\":", first ? "" : ",");
        sb_json_str(out, t->name);
        sb_printf(out, ",\"count\":%" PRIu64 ",\"errors\":%" PRIu64 ",\"avg_us\":%" PRIu64 ",\"max_us\":%" PRIu64 "}",
                  t->count, t->errors, t->total_us / t->count, t->max_us);
        first = 0;
    }
    sb_puts(out, "]}");
    pthread_mutex_unlock(&g_trace_lock);
    return 0;
}

static int rpc_trace_clear(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_trace_lock);
    memset(g_trace, 0, sizeof(g_trace));
    memset(g_tstat, 0, sizeof(g_tstat));
    g_tstat_n = 0;
    pthread_mutex_unlock(&g_trace_lock);
    sb_puts(out, "{\"cleared\":true}");
    return 0;
}

static int rpc_trace_enable(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int on;
    (void)rq; (void)err; (void)errsz;
    on = json_bool_arg(params, "on", 1);
    __atomic_store_n(&g_trace_on, on, __ATOMIC_RELAXED);
    sb_printf(out, "{\"enabled\":%s}", on ? "true" : "false");
    return 0;
}

/* ---- browser supervisor (watchdog) ---- */
static int g_browser_watchdog = 1, g_browser_managed;
static unsigned g_browser_restarts, g_wd_window_n;
static uint64_t g_browser_start_ms, g_wd_window_ms;
static pthread_mutex_t g_browser_lock = PTHREAD_MUTEX_INITIALIZER;

static int browser_start_locked(void) {
    int r = sp_launch_browser();
    if (r == 0) { g_browser_start_ms = sp_now_ms(); g_browser_managed = 1; }
    return r;
}

static void browser_stop_locked(void) {
    pid_t pid = g_sp.browser_pid;
    int i, st;
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    for (i = 0; i < 40; i++) {                  /* up to 2 s, then SIGKILL */
        if (waitpid(pid, &st, WNOHANG) == pid) { g_sp.browser_pid = -1; return; }
        usleep(50000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    g_sp.browser_pid = -1;
}

static void browser_watchdog_tick(void) {
    int st;
    pthread_mutex_lock(&g_browser_lock);
    if (g_sp.browser_pid > 0 && waitpid(g_sp.browser_pid, &st, WNOHANG) == g_sp.browser_pid) {
        SP_WARN("browser: process %d exited (status %d)", (int)g_sp.browser_pid, st);
        g_sp.browser_pid = -1;
        if (g_browser_managed && g_browser_watchdog && SP_IS_RUNNING()) {
            uint64_t now = sp_now_ms();
            if (now - g_wd_window_ms > 300000) { g_wd_window_ms = now; g_wd_window_n = 0; }
            if (++g_wd_window_n > 5) {
                SP_ERR("browser: crashed more than 5 times in 5 minutes, watchdog giving up (use browser.restart)");
                g_browser_managed = 0;
            } else if (browser_start_locked() == 0) {
                g_browser_restarts++;
                SP_LOG("browser: watchdog restarted it (restart #%u)", g_browser_restarts);
            }
        }
    }
    pthread_mutex_unlock(&g_browser_lock);
}

static int rpc_browser_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    pid_t pid;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_browser_lock);
    pid = g_sp.browser_pid;
    sb_printf(out, "{\"managed\":%s,\"pid\":%d,\"running\":%s,\"uptime_ms\":%" PRIu64 ",\"restarts\":%u,\"watchdog\":%s,\"bridge_connected\":%s,\"binary\":",
              g_browser_managed || pid > 0 ? "true" : "false", (int)pid, pid > 0 && kill(pid, 0) == 0 ? "true" : "false",
              pid > 0 ? sp_now_ms() - g_browser_start_ms : (uint64_t)0, g_browser_restarts,
              g_browser_watchdog ? "true" : "false", bridge_connected() ? "true" : "false");
    sb_json_str(out, g_sp.chromium_bin);
    sb_printf(out, ",\"kind\":\"%s\",\"site\":", g_sp.browser_kind[0] ? g_sp.browser_kind : "chromium");
    sb_json_str(out, g_sp.site_url);
    sb_putn(out, "}", 1);
    pthread_mutex_unlock(&g_browser_lock);
    return 0;
}

static int rpc_browser_restart(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int rc;
    (void)rq; (void)params;
    if (g_sp.no_browser) RPC_ERR("the browser is not managed here (--no-browser)");
    pthread_mutex_lock(&g_browser_lock);
    browser_stop_locked();
    rc = browser_start_locked();
    if (rc == 0) g_browser_restarts++;
    pthread_mutex_unlock(&g_browser_lock);
    if (rc < 0) RPC_ERR("could not launch the browser (see the log)");
    sb_printf(out, "{\"restarted\":true,\"pid\":%d}", (int)g_sp.browser_pid);
    return 0;
}

static int rpc_browser_reload(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    static const char msg[] = "{\"spp\":\"ctl\",\"op\":\"reload\"}";
    (void)rq; (void)params;
    if (!bridge_connected()) RPC_ERR("browser bridge is offline");
    if (bridge_send_text(msg, sizeof(msg) - 1) < 0) RPC_ERR("could not send to the bridge");
    sb_puts(out, "{\"reload\":true}");
    return 0;
}

/* ---- token.* ---- */
static unsigned g_token_rotations;
static uint64_t g_token_ms;

static int rpc_token_rotate(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char nt[33], msg[160];
    int live = bridge_connected();
    if (!live && !(rq->caller.kind == CALLER_TERMINAL && json_bool_arg(params, "force", 0)))
        RPC_ERR("bridge offline: the browser could not learn the new token (terminal: pass \"force\":true)");
    if (sp_random_hex(nt, 16) < 0) RPC_ERR("no secure random source");
    if (live) {                                 /* the page gets the new token over the live, authenticated bridge */
        int n = snprintf(msg, sizeof(msg), "{\"spp\":\"ctl\",\"op\":\"token\",\"token\":\"%s\"}", nt);
        if (bridge_send_text(msg, (size_t)n) < 0) RPC_ERR("could not send the new token to the browser");
    }
    pthread_mutex_lock(&g_token_lock);
    memcpy(g_sp.bridge_token, nt, 33);
    g_token_rotations++;
    g_token_ms = sp_now_ms();
    pthread_mutex_unlock(&g_token_lock);
    SP_LOG("bridge token rotated (#%u)", g_token_rotations);
    sb_printf(out, "{\"rotated\":true,\"rotations\":%u", g_token_rotations);
    if (rq->caller.kind == CALLER_TERMINAL) sb_printf(out, ",\"token\":\"%s\"", nt);   /* only the terminal ever sees it */
    sb_putn(out, "}", 1);
    memset(nt, 0, sizeof(nt));
    return 0;
}

static int rpc_token_status(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_printf(out, "{\"rotations\":%u,\"age_ms\":%" PRIu64 ",\"bridge_connected\":%s}", g_token_rotations,
              g_token_ms ? sp_now_ms() - g_token_ms : (uint64_t)0, bridge_connected() ? "true" : "false");
    return 0;
}

/* ---- config.* ---- */
static int rpc_config_get(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *key = json_str_dup(params, "key");
    int first = 1, any = 0;
    (void)rq;
#define CFG_NUM(k, fmt, v) do { if (!key || strcmp(key, k) == 0) { sb_printf(out, "%s\"%s\":" fmt, first ? "" : ",", k, v); first = 0; any = 1; } } while (0)
#define CFG_BOOL(k, v) CFG_NUM(k, "%s", (v) ? "true" : "false")
#define CFG_STR(k, v) do { if (!key || strcmp(key, k) == 0) { sb_printf(out, "%s\"%s\":", first ? "" : ",", k); sb_json_str(out, v); first = 0; any = 1; } } while (0)
    sb_putn(out, "{", 1);
    CFG_NUM("spp_version", "%u", (unsigned)SPP_VERSION);
    CFG_NUM("port", "%d", g_sp.port);
    CFG_NUM("bridge_port", "%d", g_sp.bridge_port);
    CFG_NUM("max_peers", "%zu", g_sp.max_peers);
    CFG_NUM("peers", "%zu", g_sp.peer_count);
    CFG_NUM("default_caps", "%u", (unsigned)__atomic_load_n(&g_sp.default_caps, __ATOMIC_RELAXED));
    CFG_NUM("bridge_caps", "%u", (unsigned)__atomic_load_n(&g_sp.bridge_caps, __ATOMIC_RELAXED));
    CFG_STR("bridge_origin", g_sp.bridge_origin);
    CFG_STR("drivers_dir", g_sp.drivers_dir[0] ? g_sp.drivers_dir : "sp_drivers");
    CFG_STR("browser_used", g_sp.browser_kind[0] ? g_sp.browser_kind : "chromium");
    CFG_STR("site_used", g_sp.site_url);
    CFG_BOOL("verbose", g_sp.verbose);
    CFG_BOOL("no_browser", g_sp.no_browser);
    CFG_BOOL("browser_watchdog", g_browser_watchdog);
    CFG_BOOL("trace", g_trace_on);
    CFG_NUM("rpc_timeout_ms", "%d", SPP_RPC_TIMEOUT_MS);
    CFG_NUM("spc_timeout_ms", "%d", SPC_TIMEOUT_MS);
    CFG_NUM("tx_cap", "%u", (unsigned)SPP_TX_CAP);
    CFG_NUM("tx_total_cap", "%zu", (size_t)SPP_TX_TOTAL_CAP);
    CFG_NUM("log_rate_per_s", "%d", BLOG_RATE);
    CFG_NUM("ping_interval_ms", "%d", SPP_PING_INTERVAL);
    sb_putn(out, "}", 1);
#undef CFG_NUM
#undef CFG_BOOL
#undef CFG_STR
    if (key && !any) { snprintf(err, errsz, "unknown key: %.40s", key); free(key); return -1; }
    free(key);
    return 0;
}

/* Settable at runtime: verbose, default_caps, browser_watchdog, trace. Everything else needs a restart. */
static int rpc_config_set(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *key = json_str_dup(params, "key");
    const char *v = json_find(params, "value");
    int rc = -1;
    if (!key || !v) { free(key); RPC_ERR("key and value required"); }
    if (strcmp(key, "verbose") == 0 || strcmp(key, "browser_watchdog") == 0 || strcmp(key, "trace") == 0) {
        int b;
        if (strncmp(v, "true", 4) == 0) b = 1; else if (strncmp(v, "false", 5) == 0) b = 0;
        else { snprintf(err, errsz, "%s must be true or false", key); goto done; }
        if (strcmp(key, "verbose") == 0) g_sp.verbose = b;
        else if (strcmp(key, "trace") == 0) __atomic_store_n(&g_trace_on, b, __ATOMIC_RELAXED);
        else g_browser_watchdog = b;
    } else if (strcmp(key, "default_caps") == 0) {
        uint8_t mask = 0;
        char tmp[96];
        snprintf(tmp, sizeof(tmp), "{\"caps\":%s}", v);       /* reuse the caps parser: number or "fs,op" */
        { const char *e = v; size_t l = 0; while (*e && *e != ',' && *e != '}' && l < 80) { e++; l++; } if (*v == '"') snprintf(tmp, sizeof(tmp), "{\"caps\":%.*s}", (int)(strchr(v + 1, '"') ? (size_t)(strchr(v + 1, '"') - v + 1) : 0), v); else snprintf(tmp, sizeof(tmp), "{\"caps\":%.*s}", (int)l, v); }
        if (parse_caps(tmp, &mask) < 0) { snprintf(err, errsz, "bad caps"); goto done; }
        if (mask & ~rq->caller.caps) { snprintf(err, errsz, "cannot set default_caps beyond the capabilities you hold"); goto done; }
        __atomic_store_n(&g_sp.default_caps, mask, __ATOMIC_RELAXED);
    } else {
        snprintf(err, errsz, "%.40s cannot be changed at runtime (settable: verbose, default_caps, browser_watchdog, trace)", key);
        goto done;
    }
    sb_puts(out, "{\"set\":true}");
    rc = 0;
done:
    free(key);
    return rc;
}

/* ---- peer.send / peer.broadcast ---- */
#define SP_MSG_MAX 16384
static int build_msg_env(const rpc_req_t *rq, const char *data, sb_t *env) {
    char who[40];
    caller_label(rq, who, sizeof(who));
    sb_printf(env, "{\"spp\":\"msg\",\"from\":\"%s\",\"data\":", who);
    sb_json_str(env, data);
    sb_putn(env, "}", 1);
    return env->err ? -1 : 0;
}

static int rpc_peer_send(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t conn;
    char *data = json_str_dup(params, "data");
    sb_t env;
    peer_ref_t ref;
    int slot, rc = -1;
    if (!data || json_get_i64(params, "conn", &conn) < 0 || conn <= 0) { free(data); RPC_ERR("conn and data required"); }
    if (strlen(data) > SP_MSG_MAX) { free(data); RPC_ERR("data larger than %d bytes", SP_MSG_MAX); }
    sb_init(&env);
    if (build_msg_env(rq, data, &env) < 0) { snprintf(err, errsz, "out of memory"); goto done; }
    pthread_mutex_lock(&g_sp.peers_lock);
    slot = peer_find_conn_locked((uint64_t)conn);
    ref.slot = (uint32_t)slot; ref.conn = (uint64_t)conn;
    pthread_mutex_unlock(&g_sp.peers_lock);
    if (slot < 0 || spp_peer_send(ref, SPP_DATA, (const uint8_t *)env.p, (uint32_t)env.len) < 0) { snprintf(err, errsz, "no such peer"); goto done; }
    sb_puts(out, "{\"sent\":1}");
    rc = 0;
done:
    sb_free(&env);
    free(data);
    return rc;
}

static int rpc_peer_broadcast(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *data = json_str_dup(params, "data");
    sb_t env;
    size_t n;
    int rc = -1;
    if (!data) RPC_ERR("data required");
    if (strlen(data) > SP_MSG_MAX) { free(data); RPC_ERR("data larger than %d bytes", SP_MSG_MAX); }
    sb_init(&env);
    if (build_msg_env(rq, data, &env) < 0) { snprintf(err, errsz, "out of memory"); goto done; }
    pthread_mutex_lock(&g_sp.peers_lock);
    n = g_sp.ready_count;
    pthread_mutex_unlock(&g_sp.peers_lock);
    spp_broadcast_ready(SPP_DATA, (const uint8_t *)env.p, (uint32_t)env.len);
    sb_printf(out, "{\"sent\":%zu}", n);
    rc = 0;
done:
    sb_free(&env);
    free(data);
    return rc;
}

/* ---- relay.*: a topic hub. Peers and the browser subscribe; publish fans out to the rest ---- */
#define RELAY_MAX_SUBS      4096
#define RELAY_PER_CONN      32
#define RELAY_MAX_DATA      16384
typedef struct { int used, is_bridge; char topic[49]; peer_ref_t ref; } relay_sub_t;
static relay_sub_t g_relay[RELAY_MAX_SUBS];
static uint64_t g_relay_seq;
static pthread_mutex_t g_relay_lock = PTHREAD_MUTEX_INITIALIZER;

static int relay_topic_ok(const char *t) {
    size_t n = t ? strlen(t) : 0, i;
    if (n < 1 || n > 48) return 0;
    for (i = 0; i < n; i++)
        if (!isalnum((unsigned char)t[i]) && !strchr("_.:/-", t[i])) return 0;
    return 1;
}

static int relay_same(const relay_sub_t *s, const rpc_req_t *rq) {
    if (rq->caller.kind == CALLER_BRIDGE) return s->is_bridge;
    return !s->is_bridge && s->ref.conn == rq->caller.ref.conn;
}

static int rpc_relay_subscribe(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *topic = json_str_dup(params, "topic");
    int i, mine = 0, slot = -1, rc = -1;
    if (rq->caller.kind == CALLER_TERMINAL) { free(topic); RPC_ERR("only peers and the browser can subscribe"); }
    if (!relay_topic_ok(topic)) { free(topic); RPC_ERR("topic must be 1-48 characters of [A-Za-z0-9_.:/-]"); }
    pthread_mutex_lock(&g_relay_lock);
    for (i = 0; i < RELAY_MAX_SUBS; i++) {
        if (!g_relay[i].used) { if (slot < 0) slot = i; continue; }
        if (!relay_same(&g_relay[i], rq)) continue;
        mine++;
        if (strcmp(g_relay[i].topic, topic) == 0) { pthread_mutex_unlock(&g_relay_lock); sb_puts(out, "{\"subscribed\":true,\"already\":true}"); free(topic); return 0; }
    }
    if (mine >= RELAY_PER_CONN) snprintf(err, errsz, "too many subscriptions (max %d)", RELAY_PER_CONN);
    else if (slot < 0) snprintf(err, errsz, "relay table full");
    else {
        g_relay[slot].used = 1;
        g_relay[slot].is_bridge = rq->caller.kind == CALLER_BRIDGE;
        g_relay[slot].ref = rq->caller.ref;
        snprintf(g_relay[slot].topic, sizeof(g_relay[slot].topic), "%s", topic);
        sb_puts(out, "{\"subscribed\":true}");
        rc = 0;
    }
    pthread_mutex_unlock(&g_relay_lock);
    free(topic);
    return rc;
}

static int rpc_relay_unsubscribe(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *topic = json_str_dup(params, "topic");
    int i, n = 0;
    (void)err; (void)errsz;
    pthread_mutex_lock(&g_relay_lock);
    for (i = 0; i < RELAY_MAX_SUBS; i++)
        if (g_relay[i].used && relay_same(&g_relay[i], rq) && (!topic || strcmp(g_relay[i].topic, topic) == 0)) {
            memset(&g_relay[i], 0, sizeof(g_relay[i]));
            n++;
        }
    pthread_mutex_unlock(&g_relay_lock);
    free(topic);
    sb_printf(out, "{\"removed\":%d}", n);
    return 0;
}

static int rpc_relay_topics(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char names[64][49];
    int counts[64], nt = 0, i, k;
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_relay_lock);
    for (i = 0; i < RELAY_MAX_SUBS; i++) {
        if (!g_relay[i].used) continue;
        for (k = 0; k < nt; k++) if (strcmp(names[k], g_relay[i].topic) == 0) break;
        if (k == nt) { if (nt >= 64) continue; memcpy(names[nt], g_relay[i].topic, 49); counts[nt++] = 0; }
        counts[k]++;
    }
    pthread_mutex_unlock(&g_relay_lock);
    sb_puts(out, "{\"topics\":[");
    for (k = 0; k < nt; k++) {
        sb_printf(out, "%s{\"topic\":", k ? "," : "");
        sb_json_str(out, names[k]);
        sb_printf(out, ",\"subscribers\":%d}", counts[k]);
    }
    sb_puts(out, "]}");
    return 0;
}

static int rpc_relay_publish(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *topic = json_str_dup(params, "topic"), *data = json_raw_dup(params, "data");
    char who[40];
    sb_t env;
    relay_sub_t *tg = NULL;
    int ntg = 0, i, delivered = 0, echo = json_bool_arg(params, "echo", 0), rc = -1;
    uint64_t seq;
    if (!relay_topic_ok(topic)) { snprintf(err, errsz, "topic must be 1-48 characters of [A-Za-z0-9_.:/-]"); goto done; }
    if (!data) { snprintf(err, errsz, "data required"); goto done; }
    if (strlen(data) > RELAY_MAX_DATA) { snprintf(err, errsz, "data larger than %d bytes", RELAY_MAX_DATA); goto done; }
    caller_label(rq, who, sizeof(who));
    tg = (relay_sub_t *)malloc(sizeof(relay_sub_t) * RELAY_MAX_SUBS);
    if (!tg) { snprintf(err, errsz, "out of memory"); goto done; }
    pthread_mutex_lock(&g_relay_lock);
    seq = ++g_relay_seq;
    for (i = 0; i < RELAY_MAX_SUBS; i++) {
        if (!g_relay[i].used || strcmp(g_relay[i].topic, topic) != 0) continue;
        if (!echo && relay_same(&g_relay[i], rq)) continue;       /* not back to the publisher */
        tg[ntg++] = g_relay[i];
    }
    pthread_mutex_unlock(&g_relay_lock);
    sb_init(&env);
    sb_puts(&env, "{\"spp\":\"relay\",\"topic\":");
    sb_json_str(&env, topic);
    sb_printf(&env, ",\"from\":\"%s\",\"seq\":%" PRIu64 ",\"data\":", who, seq);
    sb_puts(&env, data);
    sb_putn(&env, "}", 1);
    if (env.err) { sb_free(&env); snprintf(err, errsz, "out of memory"); goto done; }
    for (i = 0; i < ntg; i++) {
        int r = tg[i].is_bridge ? bridge_send_text(env.p, env.len)
                                : spp_peer_send(tg[i].ref, SPP_DATA, (const uint8_t *)env.p, (uint32_t)env.len);
        if (r >= 0) { delivered++; continue; }
        pthread_mutex_lock(&g_relay_lock);                         /* dead subscriber: forget it */
        { int k; for (k = 0; k < RELAY_MAX_SUBS; k++)
              if (g_relay[k].used && g_relay[k].is_bridge == tg[i].is_bridge && g_relay[k].ref.conn == tg[i].ref.conn
                  && strcmp(g_relay[k].topic, topic) == 0) { memset(&g_relay[k], 0, sizeof(g_relay[k])); break; } }
        pthread_mutex_unlock(&g_relay_lock);
    }
    sb_free(&env);
    sb_printf(out, "{\"delivered\":%d,\"seq\":%" PRIu64 "}", delivered, seq);
    rc = 0;
done:
    free(topic); free(data); free(tg);
    return rc;
}

/* ---- cron.*: in-memory jobs (nothing is written to disk) ---- */
#define CRON_MAX     32
#define CRON_SRC_MAX 4096
typedef struct { uint64_t min; uint32_t hour, dom; uint16_t mon; uint8_t dow; int dom_star, dow_star; uint32_t every_s; } cron_spec_t;
typedef struct {
    int used, run_now, last_ok;
    char name[40], sched[64];
    cron_spec_t spec;
    char *src;
    uint8_t caps;
    uint64_t owner, next_ms, last_key, runs, fails, last_ms;
} cron_job_t;
static cron_job_t g_cron[CRON_MAX];
static pthread_mutex_t g_cron_lock = PTHREAD_MUTEX_INITIALIZER;

static int cron_field(const char *f, int lo, int hi, uint64_t *mask, int *star) {
    char buf[64], *item, *save = NULL;
    *mask = 0;
    *star = strcmp(f, "*") == 0;
    snprintf(buf, sizeof(buf), "%s", f);
    for (item = strtok_r(buf, ",", &save); item; item = strtok_r(NULL, ",", &save)) {
        int a = lo, b = hi, step = 1, v;
        char *slash = strchr(item, '/'), *dash, *end;
        if (slash) { *slash = '\0'; step = (int)strtol(slash + 1, &end, 10); if (*end || step < 1) return -1; }
        if (strcmp(item, "*") == 0) { /* full range */ }
        else if ((dash = strchr(item, '-')) != NULL) {
            *dash = '\0';
            a = (int)strtol(item, &end, 10); if (*end || end == item) return -1;
            b = (int)strtol(dash + 1, &end, 10); if (*end || end == dash + 1) return -1;
        } else {
            a = (int)strtol(item, &end, 10); if (*end || end == item) return -1;
            b = slash ? hi : a;
        }
        if (a < lo || b > hi || a > b) return -1;
        for (v = a; v <= b; v += step) *mask |= 1ull << v;
    }
    return *mask ? 0 : -1;
}

static int cron_parse(const char *expr, cron_spec_t *sp) {
    char buf[64], *tok[6], *save = NULL, *t;
    int n = 0, st;
    uint64_t m;
    memset(sp, 0, sizeof(*sp));
    if (strncmp(expr, "@every ", 7) == 0) {
        char *end;
        long v = strtol(expr + 7, &end, 10);
        if (end == expr + 7 || (*end != 's' && *end != 'm' && *end != 'h') || end[1] || v < 1) return -1;
        v *= *end == 'h' ? 3600 : (*end == 'm' ? 60 : 1);
        if (v > 86400) return -1;
        sp->every_s = (uint32_t)v;
        return 0;
    }
    snprintf(buf, sizeof(buf), "%s", expr);
    for (t = strtok_r(buf, " \t", &save); t && n < 6; t = strtok_r(NULL, " \t", &save)) tok[n++] = t;
    if (n != 5) return -1;
    if (cron_field(tok[0], 0, 59, &m, &st) < 0) return -1;
    sp->min = m;
    if (cron_field(tok[1], 0, 23, &m, &st) < 0) return -1;
    sp->hour = (uint32_t)m;
    if (cron_field(tok[2], 1, 31, &m, &sp->dom_star) < 0) return -1;
    sp->dom = (uint32_t)m;
    if (cron_field(tok[3], 1, 12, &m, &st) < 0) return -1;
    sp->mon = (uint16_t)m;
    if (cron_field(tok[4], 0, 7, &m, &sp->dow_star) < 0) return -1;
    if (m & (1u << 7)) m |= 1u;                              /* 7 = Sunday too */
    sp->dow = (uint8_t)(m & 0x7f);
    return 0;
}

static int cron_match(const cron_spec_t *c, const struct tm *tm) {
    int dm = (c->dom >> tm->tm_mday) & 1, dw = (c->dow >> tm->tm_wday) & 1, day;
    if (!((c->min >> tm->tm_min) & 1) || !((c->hour >> tm->tm_hour) & 1) || !((c->mon >> (tm->tm_mon + 1)) & 1)) return 0;
    if (!c->dom_star && !c->dow_star) day = dm || dw;        /* classic cron: either one */
    else day = dm && dw;
    return day;
}

static void cron_tick(void) {
    int i;
    for (i = 0; i < CRON_MAX && SP_IS_RUNNING(); i++) {
        char name[40], *src = NULL;
        uint8_t caps = 0;
        int due = 0;
        uint64_t now = sp_now_ms();
        pthread_mutex_lock(&g_cron_lock);
        if (g_cron[i].used) {
            cron_job_t *j = &g_cron[i];
            if (j->run_now) { due = 1; j->run_now = 0; }
            else if (j->spec.every_s) { if (now >= j->next_ms) due = 1; }
            else {
                time_t t = (time_t)(now / 1000);
                struct tm tm;
                uint64_t key = (uint64_t)t / 60;
                localtime_r(&t, &tm);
                if (key != j->last_key && cron_match(&j->spec, &tm)) { due = 1; j->last_key = key; }
            }
            if (due) {
                if (j->spec.every_s) j->next_ms = now + (uint64_t)j->spec.every_s * 1000u;
                snprintf(name, sizeof(name), "%s", j->name);
                src = strdup(j->src);
                caps = j->caps;
            }
        }
        pthread_mutex_unlock(&g_cron_lock);
        if (due && src) {
            char label[64];
            int r;
            snprintf(label, sizeof(label), "<cron:%s>", name);
            r = spc_run_caps(src, label, caps);
            pthread_mutex_lock(&g_cron_lock);
            if (g_cron[i].used && strcmp(g_cron[i].name, name) == 0) {
                g_cron[i].runs++;
                if (r != 0) g_cron[i].fails++;
                g_cron[i].last_ok = r == 0;
                g_cron[i].last_ms = sp_now_ms();
            }
            pthread_mutex_unlock(&g_cron_lock);
        }
        free(src);
    }
}

static int rpc_cron_add(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name"), *sched = json_str_dup(params, "schedule"), *script = json_str_dup(params, "script");
    cron_spec_t spec;
    uint8_t caps = 0;
    int i, slot = -1, rc = -1;
    if (!name || !drv_name_ok(name)) { snprintf(err, errsz, "name must be 1-39 characters of [A-Za-z0-9_-]"); goto done; }
    if (!sched || strlen(sched) > 63 || cron_parse(sched, &spec) < 0) { snprintf(err, errsz, "bad schedule (5 cron fields, or \"@every 30s|5m|1h\")"); goto done; }
    if (!script || !script[0] || strlen(script) > CRON_SRC_MAX) { snprintf(err, errsz, "script required, max %d bytes", CRON_SRC_MAX); goto done; }
    if (json_find(params, "caps") && parse_caps(params, &caps) < 0) { snprintf(err, errsz, "bad caps"); goto done; }
    if (caps & ~rq->caller.caps) { snprintf(err, errsz, "a job cannot hold capabilities its creator lacks"); goto done; }
    pthread_mutex_lock(&g_cron_lock);
    for (i = 0; i < CRON_MAX; i++) {
        if (g_cron[i].used && strcmp(g_cron[i].name, name) == 0) { snprintf(err, errsz, "job exists: remove it first"); goto locked_done; }
        if (!g_cron[i].used && slot < 0) slot = i;
    }
    if (slot < 0) { snprintf(err, errsz, "too many jobs (max %d)", CRON_MAX); goto locked_done; }
    memset(&g_cron[slot], 0, sizeof(g_cron[slot]));
    g_cron[slot].used = 1;
    snprintf(g_cron[slot].name, sizeof(g_cron[slot].name), "%s", name);
    snprintf(g_cron[slot].sched, sizeof(g_cron[slot].sched), "%s", sched);
    g_cron[slot].spec = spec;
    g_cron[slot].src = script; script = NULL;
    g_cron[slot].caps = caps;
    g_cron[slot].owner = rq->caller.kind == CALLER_PEER ? rq->caller.ref.conn : 0;
    g_cron[slot].next_ms = sp_now_ms() + (uint64_t)spec.every_s * 1000u;
    g_cron[slot].last_ok = 1;
    sb_printf(out, "{\"name\":\"%s\",\"schedule\":", name);
    sb_json_str(out, sched);
    sb_putn(out, "}", 1);
    rc = 0;
locked_done:
    pthread_mutex_unlock(&g_cron_lock);
done:
    free(name); free(sched); free(script);
    return rc;
}

static int rpc_cron_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i, first = 1;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"jobs\":[");
    pthread_mutex_lock(&g_cron_lock);
    for (i = 0; i < CRON_MAX; i++) {
        const cron_job_t *j = &g_cron[i];
        if (!j->used) continue;
        sb_printf(out, "%s{\"name\":\"%s\",\"schedule\":", first ? "" : ",", j->name);
        sb_json_str(out, j->sched);
        sb_printf(out, ",\"caps\":%u,\"runs\":%" PRIu64 ",\"failures\":%" PRIu64 ",\"last_ms\":%" PRIu64 ",\"last_ok\":%s,\"owner\":%" PRIu64 "}",
                  (unsigned)j->caps, j->runs, j->fails, j->last_ms, j->last_ok ? "true" : "false", j->owner);
        first = 0;
    }
    pthread_mutex_unlock(&g_cron_lock);
    sb_puts(out, "]}");
    return 0;
}

static int cron_find_owned_locked(const rpc_req_t *rq, const char *name, char *err, size_t errsz) {
    int i;
    for (i = 0; i < CRON_MAX; i++) if (g_cron[i].used && strcmp(g_cron[i].name, name) == 0) break;
    if (i == CRON_MAX) { snprintf(err, errsz, "no such job"); return -1; }
    if (rq->caller.kind == CALLER_PEER && g_cron[i].owner != rq->caller.ref.conn && !(rq->caller.caps & SPCAP_POLICY)) {
        snprintf(err, errsz, "denied: job belongs to another caller (or needs cap policy)");
        return -1;
    }
    return i;
}

static int rpc_cron_remove(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    int i;
    if (!name) RPC_ERR("name required");
    pthread_mutex_lock(&g_cron_lock);
    i = cron_find_owned_locked(rq, name, err, errsz);
    if (i >= 0) { free(g_cron[i].src); memset(&g_cron[i], 0, sizeof(g_cron[i])); sb_puts(out, "{\"removed\":true}"); }
    pthread_mutex_unlock(&g_cron_lock);
    free(name);
    return i >= 0 ? 0 : -1;
}

static int rpc_cron_run(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    char *name = json_str_dup(params, "name");
    int i;
    if (!name) RPC_ERR("name required");
    pthread_mutex_lock(&g_cron_lock);
    i = cron_find_owned_locked(rq, name, err, errsz);
    if (i >= 0) { g_cron[i].run_now = 1; sb_puts(out, "{\"queued\":true}"); }
    pthread_mutex_unlock(&g_cron_lock);
    free(name);
    return i >= 0 ? 0 : -1;
}

/* One background thread: cron ticks (500 ms) and the browser watchdog (1 s). */
static void *sched_thread(void *arg) {
    unsigned n = 0;
    (void)arg;
    while (SP_IS_RUNNING()) {
        usleep(500000);
        cron_tick();
        if ((++n & 1) == 0) browser_watchdog_tick();
    }
    return NULL;
}
#endif /* SP_PLATFORM_UNIX */

/* ── browser console log (spp.log) ────────────────────────────────────────────
 * The JS layer hooks console.* / window.onerror in the headless browser and sends every line as
 * {"spp":"log","level":"warn","text":"...","ts":N}. We keep the last SP_BLOG_N lines in a ring and
 * print errors and warnings (everything with --verbose). Lines are cut to SP_BLOG_TEXT bytes, control
 * characters become spaces (no terminal escape injection), the bridge token is redacted, and more than
 * BLOG_RATE lines per second are dropped (with one "dropped" line). Read with log.tail (cap op),
 * clear with log.clear (cap policy). */
#ifdef SP_PLATFORM_UNIX
#define SP_BLOG_N     1024
#define SP_BLOG_TEXT  1024
#define BLOG_RATE     200
typedef struct { uint64_t seq, ts; uint8_t level; char text[SP_BLOG_TEXT]; } blog_t;
static blog_t g_blog[SP_BLOG_N];
static uint64_t g_blog_seq, g_blog_win;
static unsigned g_blog_win_n, g_blog_dropped;
static pthread_mutex_t g_blog_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *const g_blog_names[] = { "debug", "info", "warn", "error" };

static int blog_level(const char *s) {
    int i;
    if (!s) return 1;
    if (strcmp(s, "log") == 0) return 1;
    for (i = 0; i < 4; i++) if (strcmp(s, g_blog_names[i]) == 0) return i;
    return -1;
}

static void blog_store_locked(int lvl, const char *text, uint64_t ts) {
    blog_t *e = &g_blog[g_blog_seq % SP_BLOG_N];
    g_blog_seq++;
    e->seq = g_blog_seq;
    e->ts = ts;
    e->level = (uint8_t)lvl;
    snprintf(e->text, sizeof(e->text), "%s", text);
}

static void blog_add(const char *level, const char *text, uint64_t ts) {
    char tmp[SP_BLOG_TEXT];
    char tok[33];
    size_t i = 0, tl;
    uint64_t now = sp_now_ms();
    int lvl = blog_level(level), dropped_note = 0;
    unsigned dropped = 0;
    char *hit;

    token_copy(tok);
    tl = tok[0] ? strlen(tok) : 0;
    if (lvl < 0) lvl = 1;
    for (; text[i] && i < sizeof(tmp) - 1; i++) {
        unsigned char c = (unsigned char)text[i];
        tmp[i] = (c < 0x20 && c != '\t') || c == 0x7f ? ' ' : (char)c;
    }
    tmp[i] = '\0';
    while (tl >= 16 && (hit = strstr(tmp, tok)) != NULL) {      /* redact the secret */
        static const char red[] = "[bridge-token]";
        memmove(hit + sizeof(red) - 1, hit + tl, strlen(hit + tl) + 1);
        memcpy(hit, red, sizeof(red) - 1);
    }

    pthread_mutex_lock(&g_blog_lock);
    if (now - g_blog_win >= 1000) {
        g_blog_win = now;
        g_blog_win_n = 0;
        if (g_blog_dropped) { dropped = g_blog_dropped; g_blog_dropped = 0; dropped_note = 1; }
    }
    if (dropped_note) {
        char note[96];
        snprintf(note, sizeof(note), "[%u browser log lines dropped: rate limit]", dropped);
        blog_store_locked(2, note, now);
    }
    if (g_blog_win_n >= BLOG_RATE) {
        g_blog_dropped++;
        pthread_mutex_unlock(&g_blog_lock);
        return;
    }
    g_blog_win_n++;
    blog_store_locked(lvl, tmp, ts ? ts : now);
    pthread_mutex_unlock(&g_blog_lock);

    if (lvl >= 2 || g_sp.verbose) sp_log(lvl == 3 ? "ERROR" : (lvl == 2 ? "WARN" : "DBG"), "[browser] %s", tmp);
}

static void bridge_log_msg(const char *text) {
    char *level = json_str_dup(text, "level"), *msg = json_str_dup(text, "text");
    uint64_t ts = 0;
    json_get_u64(text, "ts", &ts);
    if (msg) blog_add(level, msg, ts);
    free(level);
    free(msg);
}

static int rpc_log_tail(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int64_t n = 50, since = 0;
    int minl = 0, cnt = 0, i;
    uint64_t sel[500], seq, last, lowest;
    size_t budget = 0;
    char *lv = json_str_dup(params, "level");
    (void)rq;
    json_get_i64(params, "n", &n);
    json_get_i64(params, "since", &since);
    if (n < 1) n = 1;
    if (n > 500) n = 500;
    if (since < 0) since = 0;
    if (lv) { minl = blog_level(lv); free(lv); if (minl < 0) RPC_ERR("level must be debug, info, warn or error"); }

    pthread_mutex_lock(&g_blog_lock);
    last = g_blog_seq;
    lowest = last > SP_BLOG_N ? last - SP_BLOG_N + 1 : 1;
    for (seq = last; seq >= lowest && seq >= 1 && cnt < n; seq--) {      /* newest first */
        const blog_t *e = &g_blog[(seq - 1) % SP_BLOG_N];
        if (e->seq != seq || seq <= (uint64_t)since) { if (seq <= (uint64_t)since) break; continue; }
        if (e->level < minl) continue;
        budget += strlen(e->text) * 2 + 96;
        if (budget > SPP_MAX_PAYLOAD - 2048) break;
        sel[cnt++] = seq;
    }
    sb_puts(out, "{\"entries\":[");
    for (i = cnt - 1; i >= 0; i--) {                                      /* oldest first */
        const blog_t *e = &g_blog[(sel[i] - 1) % SP_BLOG_N];
        sb_printf(out, "%s{\"seq\":%" PRIu64 ",\"ts\":%" PRIu64 ",\"level\":\"%s\",\"text\":", i == cnt - 1 ? "" : ",", e->seq, e->ts, g_blog_names[e->level]);
        sb_json_str(out, e->text);
        sb_putn(out, "}", 1);
    }
    sb_printf(out, "],\"last_seq\":%" PRIu64 "}", last);
    pthread_mutex_unlock(&g_blog_lock);
    return 0;
}

static int rpc_log_clear(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    (void)rq; (void)params; (void)err; (void)errsz;
    pthread_mutex_lock(&g_blog_lock);
    memset(g_blog, 0, sizeof(g_blog));            /* the counter is kept so "since" cursors stay valid */
    pthread_mutex_unlock(&g_blog_lock);
    sb_puts(out, "{\"cleared\":true}");
    return 0;
}
#endif /* SP_PLATFORM_UNIX */

/* ── method table + dispatcher ──────────────────────────────────────────────── */
typedef int (*rpc_fn)(const rpc_req_t *, const char *, sb_t *, char *, size_t);
typedef struct { const char *name; rpc_fn fn; uint8_t need; uint8_t terminal_only; } rpc_method_t;

static int rpc_methods_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz);

static const rpc_method_t g_rpc_methods[] = {
    { "identity",       rpc_identity,       0,           0 },
    { "rpc.methods",    rpc_methods_list,   0,           0 },
    { "peer.list",      rpc_peer_list,      0,           0 },
    { "peer.status",    rpc_peer_status,    0,           0 },
    { "peer.kick",      rpc_peer_kick,      SPCAP_UID,   0 },
    { "peer.caps",      rpc_policy_get,     0,           0 },
    { "daemon.list",    rpc_daemon_list,    0,           0 },
    { "daemon.status",  rpc_daemon_status,  0,           0 },
    { "daemon.start",   rpc_daemon_start,   SPCAP_PID,   0 },
    { "daemon.stop",    rpc_daemon_stop,    SPCAP_PID,   0 },
    { "daemon.restart", rpc_daemon_restart, SPCAP_PID,   0 },
    { "bridge.status",  rpc_bridge_status,  0,           0 },
    { "bridge.latency", rpc_bridge_latency, 0,           0 },
    { "spc.run",        rpc_spc_run,        SPCAP_OP,    0 },
    { "spc.runFile",    rpc_spc_runfile,    SPCAP_OP,    1 },
    { "mem.alloc",      rpc_mem_alloc,      SPCAP_OP,    0 },
    { "mem.free",       rpc_mem_free,       SPCAP_OP,    0 },
    { "mem.read",       rpc_mem_read,       SPCAP_OP,    0 },
    { "mem.write",      rpc_mem_write,      SPCAP_OP,    0 },
    { "mem.info",       rpc_mem_info,       SPCAP_OP,    0 },
    { "mem.list",       rpc_mem_list,       SPCAP_OP,    0 },
    { "policy.get",     rpc_policy_get,     0,           0 },
    { "policy.check",   rpc_policy_check,   0,           0 },
    { "policy.grant",   rpc_policy_grant,   SPCAP_POLICY, 0 },
    { "policy.revoke",  rpc_policy_revoke,  SPCAP_POLICY, 0 },
    { "trace.tail",     rpc_trace_tail,     SPCAP_OP,    0 },
    { "trace.stats",    rpc_trace_stats,    SPCAP_OP,    0 },
    { "trace.clear",    rpc_trace_clear,    SPCAP_POLICY, 0 },
    { "trace.enable",   rpc_trace_enable,   SPCAP_POLICY, 0 },
    { "config.get",     rpc_config_get,     0,           0 },
    { "config.set",     rpc_config_set,     SPCAP_POLICY, 0 },
    { "browser.status", rpc_browser_status, 0,           0 },
    { "browser.restart",rpc_browser_restart,SPCAP_PID,   0 },
    { "browser.reload", rpc_browser_reload, SPCAP_OP,    0 },
    { "token.rotate",   rpc_token_rotate,   SPCAP_POLICY, 0 },
    { "token.status",   rpc_token_status,   SPCAP_OP,    0 },
    { "cron.add",       rpc_cron_add,       SPCAP_OP,    0 },
    { "cron.list",      rpc_cron_list,      SPCAP_OP,    0 },
    { "cron.remove",    rpc_cron_remove,    SPCAP_OP,    0 },
    { "cron.run",       rpc_cron_run,       SPCAP_OP,    0 },
    { "peer.send",      rpc_peer_send,      SPCAP_OP,    0 },
    { "peer.broadcast", rpc_peer_broadcast, SPCAP_OP,    0 },
    { "relay.subscribe",   rpc_relay_subscribe,   SPCAP_OP, 0 },
    { "relay.unsubscribe", rpc_relay_unsubscribe, SPCAP_OP, 0 },
    { "relay.publish",     rpc_relay_publish,     SPCAP_OP, 0 },
    { "relay.topics",      rpc_relay_topics,      SPCAP_OP, 0 },
    { "log.tail",       rpc_log_tail,       SPCAP_OP,    0 },
    { "log.clear",      rpc_log_clear,      SPCAP_POLICY, 0 },
    { "driver.list",    rpc_driver_list,    SPCAP_OP,    0 },
    { "driver.call",    rpc_driver_call,    SPCAP_OP,    0 },
    { "driver.install", rpc_driver_install, SPCAP_OP,    1 },
    { "driver.approve", rpc_driver_approve, SPCAP_OP,    1 },
    { "driver.load",    rpc_driver_load,    SPCAP_OP,    1 },
    { "driver.unload",  rpc_driver_unload,  SPCAP_OP,    1 },
    { "driver.remove",  rpc_driver_remove,  SPCAP_OP,    1 },
};

/* Methods answered by the JS layer (the browser's SP). Only names listed here can be forwarded;
 * "jsdriver.*" is deliberately absent: only the driver.* methods above may use it.
 * SPMemory is C -> JS only: nothing in the JS layer can ask C for memory. */
typedef struct { const char *name; uint8_t need; } js_method_t;
#define JSM_FS  SPCAP_FS
#define JSM_JS  SPCAP_JS
#define JSM_MEM (SPCAP_JS | SPCAP_OP)
static const js_method_t g_js_methods[] = {
    { "fs.newfile", JSM_FS }, { "fs.editfile", JSM_FS }, { "fs.cat", JSM_FS }, { "fs.newfolder", JSM_FS },
    { "fs.editfolder", JSM_FS }, { "fs.lsfolder", JSM_FS }, { "fs.delfile", JSM_FS }, { "fs.delfolder", JSM_FS },
    { "fs.cpfile", JSM_FS }, { "fs.cpfolder", JSM_FS }, { "fs.cdfile", JSM_FS }, { "fs.cdfolder", JSM_FS },
    { "fs.expose", JSM_FS }, { "fs.restrict", JSM_FS }, { "fs.bigWrite", JSM_FS }, { "fs.bigRead", JSM_FS },
    { "spmem.alloc", JSM_MEM }, { "spmem.read", JSM_MEM }, { "spmem.write", JSM_MEM }, { "spmem.free", JSM_MEM },
    { "spmem.list", JSM_MEM }, { "spmem.stat", JSM_MEM }, { "spmem.flush", JSM_MEM }, { "spmem.flushAll", JSM_MEM },
    { "audit.log", JSM_JS }, { "audit.enable", JSM_JS | SPCAP_POLICY }, { "audit.disable", JSM_JS | SPCAP_POLICY },
    { "time.now", JSM_JS }, { "time.toUTC", JSM_JS }, { "time.fromUTC", JSM_JS },
    { "compress.str", JSM_JS }, { "compress.unstr", JSM_JS }, { "compress.ratio", JSM_JS },
    { "registry.get", JSM_JS }, { "registry.has", JSM_JS }, { "registry.list", JSM_JS },
    { "mesh.list", JSM_JS }, { "mesh.count", JSM_JS }, { "mesh.get", JSM_JS },
    { "alias.mine", JSM_JS }, { "alias.resolve", JSM_JS }, { "alias.all", JSM_JS },
    { "presence.list", JSM_JS }, { "presence.get", JSM_JS },
    { "presence.set", JSM_JS | SPCAP_OP }, { "presence.clear", JSM_JS | SPCAP_OP },
};
#define N_JS_METHODS ((int)(sizeof(g_js_methods) / sizeof(g_js_methods[0])))
#define N_RPC_METHODS ((int)(sizeof(g_rpc_methods) / sizeof(g_rpc_methods[0])))

static int rpc_methods_list(const rpc_req_t *rq, const char *params, sb_t *out, char *err, size_t errsz) {
    int i;
    (void)rq; (void)params; (void)err; (void)errsz;
    sb_puts(out, "{\"methods\":[");
    for (i = 0; i < N_RPC_METHODS; i++) {
        const rpc_method_t *m = &g_rpc_methods[i];
        sb_printf(out, "%s{\"name\":\"%s\",\"needs\":\"%s\",\"terminal_only\":%s}", i ? "," : "", m->name,
                  m->need ? capname(m->need) : "", m->terminal_only ? "true" : "false");
    }
    for (i = 0; i < N_JS_METHODS; i++) {
        char nb[48];
        sb_printf(out, ",{\"name\":\"%s\",\"needs\":\"%s\",\"terminal_only\":false,\"served_by\":\"js\"}",
                  g_js_methods[i].name, need_str(g_js_methods[i].need, nb, sizeof(nb)));
    }
    sb_puts(out, "]}");
    return 0;
}

/* 0 = ok (result in out), -1 = error (message in err), 1 = async (reply comes later) */
static int rpc_execute(const rpc_req_t *rq, const char *method, const char *params,
                       sb_t *out, char *err, size_t errsz) {
    int i;
    if (strncmp(method, "sp.", 3) == 0) method += 3;
    if (*json_skip_ws(params) != '{') RPC_ERR("params must be an object");

    for (i = 0; i < N_JS_METHODS; i++) {
        const js_method_t *j = &g_js_methods[i];
        char nb[48];
        if (strcmp(j->name, method) != 0) continue;
        if ((rq->caller.caps & j->need) != j->need) RPC_ERR("denied: needs cap %s", need_str(j->need, nb, sizeof(nb)));
        return rpc_forward_js(rq, method, params, out, err, errsz);
    }
    if (strncmp(method, "fs.", 3) == 0) RPC_ERR("unknown fs method: %.64s", method);
    for (i = 0; i < N_RPC_METHODS; i++) {
        const rpc_method_t *m = &g_rpc_methods[i];
        if (strcmp(m->name, method) != 0) continue;
        if (m->terminal_only && rq->caller.kind != CALLER_TERMINAL) RPC_ERR("denied: terminal only");
        if ((rq->caller.caps & m->need) != m->need) { char nb[48]; RPC_ERR("denied: needs cap %s", need_str(m->need, nb, sizeof(nb))); }
        return m->fn(rq, params, out, err, errsz);
    }
    RPC_ERR("unknown method: %.64s", method);
}

/* Entry point for SPP_RPC (peers) and {"spp":"rpc"} (bridge). text is NUL-terminated JSON. */
static void rpc_handle_text(const sp_caller_t *base, const char *text) {
    rpc_req_t rq;
    char *method, *params, err[200] = "";
    sb_t out;
    int rc;
    uint64_t id = 0;

    memset(&rq, 0, sizeof(rq));
    rq.caller = *base;
    rq.has_id = json_get_u64(text, "id", &id) == 0;
    rq.id = id;
    rq.t0_us = sp_now_us();

    if (rq.caller.kind == CALLER_PEER) {        /* caps are read now so revokes take effect immediately */
        spp_peer_t *p;
        pthread_mutex_lock(&g_sp.peers_lock);
        p = peer_by_ref(rq.caller.ref);
        rq.caller.caps = p ? sp_caps_get(p) : 0;
        pthread_mutex_unlock(&g_sp.peers_lock);
    } else if (rq.caller.kind == CALLER_BRIDGE) {
        rq.caller.caps = __atomic_load_n(&g_sp.bridge_caps, __ATOMIC_RELAXED);
    }

    method = json_str_dup(text, "method");
    params = json_raw_dup(text, "params");
    sb_init(&out);
    if (method) snprintf(rq.mname, sizeof(rq.mname), "%s", strncmp(method, "sp.", 3) == 0 ? method + 3 : method);
    if (!method) { snprintf(err, sizeof(err), "method required"); rc = -1; }
    else rc = rpc_execute(&rq, method, params ? params : "{}", &out, err, sizeof(err));

    if (rc <= 0 && (rq.has_id || rq.caller.kind == CALLER_TERMINAL)) {
        if (rc == 0 && out.err) { rc = -1; snprintf(err, sizeof(err), "out of memory"); }
        rpc_reply(&rq.caller, rq.has_id, rq.id, rc == 0, rc == 0 ? out.p : err);
    }
    if (rc <= 0) trace_record(rq.caller.kind, rq.caller.ref.conn, rq.mname[0] ? rq.mname : "(none)", rc == 0, rc == 0 ? NULL : err, rq.t0_us);
    sb_free(&out);
    free(method);
    free(params);
}

/* Terminal command: runs a method with full privileges and blocks for fs.* answers. */
static int rpc_call_terminal(const char *method, const char *params, sb_t *out, char *err, size_t errsz) {
    rpc_req_t rq;
    memset(&rq, 0, sizeof(rq));
    int rc;
    rq.caller.kind = CALLER_TERMINAL;
    rq.caller.caps = SPCAP_ALL;
    rq.t0_us = sp_now_us();
    snprintf(rq.mname, sizeof(rq.mname), "%s", strncmp(method, "sp.", 3) == 0 ? method + 3 : method);
    rc = rpc_execute(&rq, method, params, out, err, errsz);
    if (rc <= 0) trace_record(CALLER_TERMINAL, 0, rq.mname, rc == 0, rc == 0 ? NULL : err, rq.t0_us);
    return rc;
}

/* Messages from the JS layer that use the "spp" envelope. Returns 1 if consumed. */
static int bridge_dispatch_text(const char *text, size_t len) {
    char *kind;
    int handled = 0;
    if (len == 0 || text[0] != '{') return 0;
    kind = json_str_dup(text, "spp");
    if (!kind) return 0;
    if (strcmp(kind, "rpc") == 0) {
        sp_caller_t c;
        memset(&c, 0, sizeof(c));
        c.kind = CALLER_BRIDGE;
        rpc_handle_text(&c, text);
        handled = 1;
    } else if (strcmp(kind, "rpc_result") == 0) {
        bridge_rpc_result(text);
        handled = 1;
    } else if (strcmp(kind, "log") == 0) {
        bridge_log_msg(text);
        handled = 1;
    }
    free(kind);
    return handled;
}

#endif /* SP_PLATFORM_UNIX */

/* ── Peer message handler ──────────────────────────────────────────────────── */
/* Runs on the IO thread with no locks held. Returns -1 to have the peer dropped.
 * Never touch `peer` after a send: the send itself may have dropped it. */
#ifdef SP_PLATFORM_UNIX
static int spp_handle_message(spp_peer_t *peer, uint16_t msg_type,
                              uint8_t *payload, uint32_t payload_len) {
    peer_ref_t ref;
    uint8_t    caps = sp_caps_get(peer);

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

    case SPP_DATA:
    case SPP_IO_INPUT:
        /* Forwarding into the browser reaches SP's terminal handlers, so it needs cap op. */
        if (!(caps & SPCAP_OP)) { spp_peer_error(ref, "denied: needs cap op"); break; }
        SP_DBG("%s from %s: %.200s", msg_type == SPP_DATA ? "SPP_DATA" : "IO_INPUT",
               peer->spmention, (char *)payload);
        bridge_send_op(0x2, payload, payload_len);
        break;

    case SPP_SPC_RUN:
        if (!(caps & SPCAP_OP)) { spp_peer_error(ref, "denied: needs cap op"); break; }
        SP_LOG("SPC_RUN: executing script (%u bytes)", payload_len);
        {
            int ret = spc_run_caps((char *)payload, "<remote>", caps);
            char result[64];
            snprintf(result, sizeof(result), "{\"ok\":%s}", ret == 0 ? "true" : "false");
            spp_peer_send(ref, SPP_SPC_RESULT, (uint8_t *)result, (uint32_t)strlen(result));
        }
        break;

    case SPP_DAEMON_START:
    case SPP_DAEMON_STOP:
        if (!(caps & SPCAP_PID)) { spp_peer_error(ref, "denied: needs cap pid"); break; }
        if (payload_len >= 1) {
            uint8_t did = payload[0];
            if (msg_type == SPP_DAEMON_START) sp_daemon_handle_msg(did, payload + 1, payload_len - 1);
            else if (did >= 1 && did <= SP_DAEMON_MAX) SP_ST(g_sp.daemons[did-1].running, 0);
        }
        break;

    case SPP_RPC:
        {
            sp_caller_t c;
            memset(&c, 0, sizeof(c));
            c.kind = CALLER_PEER;
            c.ref  = ref;
            rpc_handle_text(&c, (const char *)payload);
        }
        break;

    case SPP_CLOSE:
        SP_DBG("peer %s sent CLOSE", peer->spmention);
        return -1;

    default:
        SP_WARN("unknown msg_type 0x%04x from %s", msg_type, peer->spmention);
        break;
    }
    return 0;
}
#endif

/* ── Server thread ─────────────────────────────────────────────────────────── */
#ifdef SP_PLATFORM_UNIX
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
    sb_puts(&ack, ",\"accepted_caps\":[\"host\",\"daemon\",\"spc\",\"rpc\"]}");
    if (!ack.err) spp_peer_send(ref, SPP_CONNECT_ACK, (const uint8_t *)ack.p, (uint32_t)ack.len);
    sb_free(&ack);
    SP_DBG("handshake: accepted peer %s session=%s", mention, session);
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
    static uint64_t last_bridge_ping;
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

    pending_fail("timeout waiting for the JS layer", 1);
    if (now - last_bridge_ping > 5000) { last_bridge_ping = now; bridge_ping(); }
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

/* After the WebSocket upgrade the browser must prove it was launched by us: its first
 * frame has to be {"type":"sp:ready","token":"<bridge token>"}. Origin alone is not
 * enough ("null" is also what sandboxed iframes and data: pages send). */
static int bridge_authenticate(sp_socket_t client) {
    uint8_t *buf = (uint8_t *)malloc(SPP_MAX_PAYLOAD + 1);
    size_t   len = 0;
    int      ok  = 0;

    if (!buf) return -1;
    bridge_set_timeouts(client, 5000, 2000);
    if (bridge_ws_recv(client, buf, &len) >= 0 && len > 0 && len < 1024) {
        char *type, *tok;
        buf[len] = '\0';
        type = json_str_dup((const char *)buf, "type");
        tok  = json_str_dup((const char *)buf, "token");
        char cur[33];
        token_copy(cur);
        ok = type && tok && cur[0] &&
             strcmp(type, "sp:ready") == 0 && sp_ct_streq(tok, cur);
        free(type);
        free(tok);
    }
    free(buf);
    bridge_set_timeouts(client, 0, 2000);
    if (!ok) SP_WARN("bridge: rejected client (missing or wrong token)");
    return ok ? 0 : -1;
}

static void *bridge_server_thread(void *arg) {
    (void)arg;
    struct sockaddr_in addr = {0};
    sp_socket_t srv;
    int opt = 1;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == SP_INVALID_SOCKET) { SP_ERR("bridge socket: %s", strerror(errno)); return NULL; }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 only */
    addr.sin_port        = htons((uint16_t)g_sp.bridge_port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        SP_ERR("bridge bind: %s", strerror(errno)); sp_close_socket(srv); return NULL;
    }
    listen(srv, 1);
    SP_LOG("bridge WebSocket server on 127.0.0.1:%d", g_sp.bridge_port);

    while (SP_IS_RUNNING()) {
        sp_socket_t client = accept(srv, NULL, NULL);
        if (client == SP_INVALID_SOCKET) break;
        SP_LOG("bridge: browser connected");

        if (bridge_ws_handshake(client) < 0 || bridge_authenticate(client) < 0) {
            sp_close_socket(client); continue;
        }

        BRIDGE_LOCK();
        g_sp.bridge_sock = client;
        BRIDGE_UNLOCK();
        g_sp.bridge_rtt_ms = UINT32_MAX;
        bridge_ping();

        /* Relay loop: {"spp":...} envelopes are RPC; everything else is browser
         * output and goes to the ready peers as before. */
        {
            uint8_t buf[SPP_MAX_PAYLOAD + 1];
            size_t  len;
            while (SP_IS_RUNNING()) {
                len = 0;
                if (bridge_ws_recv(client, buf, &len) < 0) break;
                buf[len] = '\0';
                SP_DBG("bridge→SPP: %zu bytes", len);
                if (bridge_dispatch_text((const char *)buf, len)) continue;
                spp_broadcast_ready(SPP_IO_OUTPUT, buf, (uint32_t)len);
            }
        }

        BRIDGE_LOCK();
        g_sp.bridge_sock = SP_INVALID_SOCKET;
        BRIDGE_UNLOCK();
        g_sp.bridge_rtt_ms = UINT32_MAX;
        pending_fail("bridge disconnected", 0);
        sp_close_socket(client);
        SP_LOG("bridge: browser disconnected");
    }

    sp_close_socket(srv);
    return NULL;
}
#endif

/* ── Terminal I/O loop ─────────────────────────────────────────────────────── */
static void sp_terminal_loop(void) {
    char line[1024];
    SP_LOG("SharedProtocol terminal ready. Type 'help' for commands.");
    printf("\n\033[1;36msharedprotocol>\033[0m ");
    fflush(stdout);

    while (SP_IS_RUNNING() && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  help              — this message\n");
            printf("  status            — show SPP, bridge and peer status\n");
            printf("  peers             — list connected peers (first 50)\n");
            printf("  daemons           — list daemon status\n");
            printf("  rpc <method> [json] — call an SP API, e.g. rpc identity | rpc rpc.methods\n");
            printf("                        rpc policy.grant {\"target\":\"bridge\",\"caps\":\"op\"}\n");
            printf("                        rpc fs.cat {\"path\":\"/a.txt\"}   (served by the JS layer)\n");
            printf("  spc <file>        — run a .spc file on host\n");
            printf("  stop              — stop sharedprotocol\n");
            printf("  <any SPCode>      — run inline SPCode on host\n");

        } else if (strcmp(line, "status") == 0) {
            printf("SPP port:    %d\n", g_sp.port);
            printf("Bridge port: %d\n", g_sp.bridge_port);
            printf("Mention:     %s\n", g_sp.spmention);
            printf("Browser:     %s\n", g_sp.no_browser ? "disabled" : g_sp.chromium_bin);
#ifdef SP_PLATFORM_UNIX
            {
                size_t ready;
                pthread_mutex_lock(&g_sp.peers_lock);
                ready = g_sp.ready_count;
                pthread_mutex_unlock(&g_sp.peers_lock);
                printf("Peers:       %zu ready / %zu max   (default caps 0x%02x)\n", ready, g_sp.max_peers, g_sp.default_caps);
            }
            printf("Bridge:      %s   caps 0x%02x   rtt %d ms\n",
                   bridge_connected() ? "connected" : "offline",
                   __atomic_load_n(&g_sp.bridge_caps, __ATOMIC_RELAXED),
                   bridge_connected() && g_sp.bridge_rtt_ms != UINT32_MAX ? (int)g_sp.bridge_rtt_ms : -1);
#endif

        } else if (strcmp(line, "peers") == 0) {
            size_t shown = 0, total = 0;
#ifdef SP_PLATFORM_UNIX
            size_t i;
            pthread_mutex_lock(&g_sp.peers_lock);
            total = g_sp.ready_count;
            for (i = 0; i < g_sp.peer_hi && shown < 50; i++) {
                spp_peer_t *p = &g_sp.peers[i];
                if (!p->active) continue;
                printf("  [%zu] conn=%" PRIu64 " %s  session=%s  caps=0x%02x  rtt=%ums\n",
                       i, p->conn_id, p->spmention, p->session_id, sp_caps_get(p), p->rtt_ms);
                shown++;
            }
            pthread_mutex_unlock(&g_sp.peers_lock);
#endif
            if (!total) printf("  no peers connected\n");
            else if (total > shown) printf("  ... and %zu more (rpc peer.list pages through all of them)\n", total - shown);

        } else if (strcmp(line, "daemons") == 0) {
            for (int i = 0; i < SP_DAEMON_MAX; i++) {
                printf("  [%d] %-12s  %s\n",
                       g_sp.daemons[i].id,
                       g_sp.daemons[i].name,
                       SP_LD(g_sp.daemons[i].running) ? "\033[32mrunning\033[0m" : "\033[31mstopped\033[0m");
            }

        } else if (strncmp(line, "rpc", 3) == 0 && (line[3] == ' ' || line[3] == '\0')) {
#ifdef SP_PLATFORM_UNIX
            char *m = line + 3, *params;
            while (*m == ' ') m++;
            params = m;
            while (*params && *params != ' ') params++;
            if (*params) { *params++ = '\0'; while (*params == ' ') params++; }
            if (!*m) {
                printf("usage: rpc <method> [json-params]   (try: rpc rpc.methods)\n");
            } else {
                sb_t out;
                char err[200] = "";
                int rc;
                sb_init(&out);
                rc = rpc_call_terminal(m, *params ? params : "{}", &out, err, sizeof(err));
                if (rc == 0) printf("%s\n", out.p ? out.p : "null");
                else         printf("\033[31merror:\033[0m %s\n", err);
                sb_free(&out);
            }
#else
            printf("rpc is not available on this platform\n");
#endif

        } else if (strncmp(line, "spc ", 4) == 0) {
            spc_run_file(line + 4);

        } else if (strcmp(line, "stop") == 0) {
            SP_ST(g_sp.running, 0);
            break;

        } else if (strlen(line) > 0) {
            /* Treat as inline SPCode */
            spc_run(line, "<stdin>");
        }

        printf("\n\033[1;36msharedprotocol>\033[0m ");
        fflush(stdout);
    }
}

/* ── SP-side additions (SPTerminal in sharedprotocol.js) ──────────────────────
 *
 * sharedprotocol.js already ships SPTerminal (sp.terminal). This adds the RPC
 * envelope that SPP_RPC uses on the bridge:
 *
 *   C  -> JS   {"spp":"rpc","id":N,"method":"fs.cat","params":{...}}
 *   JS -> C    {"spp":"rpc_result","id":N,"ok":true,"result":...}   (or "ok":false,"error":"...")
 *   JS -> C    {"spp":"rpc","id":N,"method":"peer.list","params":{}}  (answered by C)
 *
 * The existing sp:vfs / sp:mem / sp:memory "blocked" cases stay exactly as they are.
 * fs.* from C is a separate, jailed path: every path is resolved under /terminal in the
 * VFS ("/a.txt" -> "/terminal/a.txt", ".." is rejected) and only a small flag set is
 * allowed, so the terminal never reaches the rest of the VFS and SPMemory stays blocked.
 *
 *   // 1) constructor: add
 *   this._rid = 0; this._calls = new Map();
 *
 *   // 2) _dispatch(raw): after the JSON.parse line, before `switch (msg.type)`, add
 *   if (msg && msg.spp === "rpc")        { this._onRpc(msg);       return; }
 *   if (msg && msg.spp === "rpc_result") { this._onRpcResult(msg); return; }
 *
 *   // 3) new methods on SPTerminal
 *   // call a C-side API: sp.terminal.call("peer.list", {limit: 10})
 *   call(method, params = {}, timeoutMs = 10000) {
 *     return new Promise((resolve, reject) => {
 *       if (!this.connected) return reject(new Error("bridge not connected"));
 *       const id = ++this._rid;
 *       const t = setTimeout(() => { this._calls.delete(id); reject(new Error("rpc timeout")); }, timeoutMs);
 *       this._calls.set(id, { resolve, reject, t });
 *       this.send({ spp: "rpc", id, method, params });
 *     });
 *   }
 *   _onRpcResult(m) {
 *     const c = this._calls.get(m.id);
 *     if (!c) return;
 *     this._calls.delete(m.id); clearTimeout(c.t);
 *     if (m.ok) c.resolve(m.result); else c.reject(new Error(m.error || "rpc error"));
 *   }
 *   async _onRpc(m) {
 *     const reply = (ok, v) => this.send({ spp: "rpc_result", id: m.id, ok,
 *       ...(ok ? { result: v } : { error: String((v && v.message) || v) }) });
 *     try {
 *       if (typeof m.method !== "string" || !m.method.startsWith("fs."))
 *         throw new Error("only fs.* is served by the JS layer");
 *       reply(true, await this._fsCall(m.method, m.params || {}));
 *     } catch (e) { reply(false, e); }
 *   }
 *   _jail(p) {
 *     if (typeof p !== "string") throw new Error("path must be a string");
 *     const parts = p.split("/").filter(Boolean);
 *     if (parts.some(s => s === ".." || s === "." || s.includes("\\"))) throw new Error("bad path");
 *     return "/terminal" + (parts.length ? "/" + parts.join("/") : "");
 *   }
 *   _bigName(n) {
 *     if (typeof n !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(n) || n === "." || n === "..")
 *       throw new Error("bad name");
 *     return "terminal-" + n;
 *   }
 *   async _ensureRoot() {
 *     if (this._rootReady) return;
 *     try { await this._sp.newfolder("/terminal"); } catch (e) { }   // already exists
 *     this._rootReady = true;
 *   }
 *   async _fsCall(method, p) {
 *     const sp = this._sp, op = method.slice(3), J = (x) => this._jail(x);
 *     const OK = new Set(["--stayforever", "--sensitive", "--noexec", "--lock"]);
 *     const flags = Array.isArray(p.flags) ? p.flags.filter(f => OK.has(f)) : [];
 *     await this._ensureRoot();
 *     switch (op) {
 *       case "newfile":    return { path: await sp.newfile(J(p.path), String(p.content ?? ""), ...flags) };
 *       case "editfile":   await sp.editfile(J(p.path), String(p.content ?? "")); return { ok: true };
 *       case "cat":        return { content: await sp.cat(J(p.path)) };
 *       case "newfolder":  return { path: await sp.newfolder(J(p.path), ...flags) };
 *       case "editfolder": {
 *         if (typeof p.newName !== "string" || p.newName.includes("/")) throw new Error("bad name");
 *         return { result: await sp.editfolder(J(p.path), p.newName) };
 *       }
 *       case "lsfolder":   return { entries: sp.lsfolder(J(p.path || "/")) };
 *       case "delfile":    return { result: await sp.delfile(J(p.path)) };
 *       case "delfolder": {
 *         const t = J(p.path);
 *         if (t === "/terminal") throw new Error("cannot delete the jail root");
 *         return { result: await sp.delfolder(t) };
 *       }
 *       case "cpfile": case "cpfolder": case "cdfile": case "cdfolder":
 *         return { result: sp[op](J(p.src), J(p.dest)) };
 *       case "expose": case "restrict": sp[op](J(p.path)); return { ok: true };
 *       case "bigWrite": {      // data is base64; limited by the 64 KB bridge frame
 *         const bin = Uint8Array.from(atob(String(p.data || "")), c => c.charCodeAt(0));
 *         return { result: await sp.bigWrite(this._bigName(p.name), new Blob([bin])) };
 *       }
 *       case "bigRead": {
 *         const b = await sp.bigRead(this._bigName(p.name));
 *         const buf = new Uint8Array(b instanceof Blob ? await b.arrayBuffer() : b);
 *         if (buf.length > 45000) throw new Error("too large for one bridge frame (" + buf.length + " bytes)");
 *         let s = ""; for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
 *         return { data: btoa(s), size: buf.length };
 *       }
 *       default: throw new Error("unknown fs method: " + method);
 *     }
 *   }
 *
 * Privileges: peers connect with --default-caps (default 0) and the bridge starts with
 * caps 0, so out of the box only read-only methods (identity, peer.*, daemon.status,
 * bridge.*) work. Grant more from the terminal, e.g.
 *   rpc policy.grant {"target":"bridge","caps":"op"}
 *   rpc policy.grant {"conn":1,"caps":"fs,op"}
 * ─────────────────────────────────────────────────────────────────────────── */

/* ── Main ──────────────────────────────────────────────────────────────────── */
static void sp_print_banner(void) {
    printf("\033[1;35m");
    printf("  ____  _                    _ ____            _                  _  \n");
    printf(" / ___|| |__   __ _ _ __ ___| |  _ \\ _ __ ___ | |_ ___   ___ ___ | | \n");
    printf(" \\___ \\| '_ \\ / _` | '__/ _ \\ | |_) | '__/ _ \\| __/ _ \\ / __/ _ \\| | \n");
    printf("  ___) | | | | (_| | | |  __/ |  __/| | | (_) | || (_) | (_| (_) | | \n");
    printf(" |____/|_| |_|\\__,_|_|  \\___|_|_|   |_|  \\___/ \\__\\___/ \\___\\___/|_| \n");
    printf("\033[0m");
    printf("  SharedProtocol Terminal v1.1.0  |  SPP v1.1  |  SPCode host runner\n\n");
}

static void sp_usage(void) {
    printf("Usage: sharedprotocol [options]\n\n");
    printf("Options:\n");
    printf("  --port <n>       SPP listen port (default: %d)\n", SPP_DEFAULT_PORT);
    printf("  --bridge <n>     Bridge WebSocket port (default: %d)\n", SPP_BRIDGE_PORT);
    printf("  --no-browser     Disable headless browser launch\n");
    printf("  --spc <file>     Run a .spc file on host and exit\n");
    printf("  --max-peers <n>  Peer table size (default: %d, needs ulimit -n above n)\n", SPP_MAX_PEERS);
    printf("  --default-caps <mask>  Capabilities new peers start with (default: 0)\n");
    printf("  --bridge-origin <o>    Extra web origin allowed to use the bridge\n");
    printf("  --bridge-token <t>     Fixed bridge token (default: random per run; needed with --no-browser)\n");
    printf("  --chromium-no-sandbox  Pass --no-sandbox to Chromium (added automatically when run as root)\n");
    printf("  --drivers-dir <dir>    Where SPP drivers are installed (default: ./sp_drivers)\n");
    printf("  --browser-used <b>     Browser to launch: chromium (default), chrome, firefox or brave\n");
    printf("  --site-used <site>     Open this site (https:// optional) instead of the built-in page; only it may use the bridge\n");
    printf("  --verbose        Enable debug logging\n");
    printf("  --help           Show this help\n\n");
}

int main(int argc, char *argv[]) {
    int i;

    /* Defaults */
    g_sp.port        = SPP_DEFAULT_PORT;
    g_sp.bridge_port = SPP_BRIDGE_PORT;
    g_sp.running     = 1;
    g_sp.bridge_sock = SP_INVALID_SOCKET;
    g_sp.browser_pid = -1;
    g_sp.max_peers   = SPP_MAX_PEERS;
    g_sp.epfd        = -1;
    g_sp.bridge_rtt_ms = UINT32_MAX;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i+1 < argc) {
            g_sp.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bridge") == 0 && i+1 < argc) {
            g_sp.bridge_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-browser") == 0) {
            g_sp.no_browser = 1;
        } else if (strcmp(argv[i], "--spc") == 0 && i+1 < argc) {
            strncpy(g_sp.spc_file, argv[++i], sizeof(g_sp.spc_file)-1);
            g_sp.spc_mode = 1;
        } else if (strcmp(argv[i], "--max-peers") == 0 && i+1 < argc) {
            long v = atol(argv[++i]);
            if (v < 1) v = 1;
            if (v > SPP_MAX_PEERS_HARD) v = SPP_MAX_PEERS_HARD;
            g_sp.max_peers = (size_t)v;
        } else if (strcmp(argv[i], "--default-caps") == 0 && i+1 < argc) {
            g_sp.default_caps = (uint8_t)(strtoul(argv[++i], NULL, 0) & SPCAP_ALL);
        } else if (strcmp(argv[i], "--bridge-origin") == 0 && i+1 < argc) {
            strncpy(g_sp.bridge_origin, argv[++i], sizeof(g_sp.bridge_origin) - 1);
        } else if (strcmp(argv[i], "--bridge-token") == 0 && i+1 < argc) {
            const char *t = argv[++i];
            size_t k, tl = strlen(t);
            if (tl < 16 || tl > 32) { fprintf(stderr, "--bridge-token must be 16..32 characters\n"); return 1; }
            for (k = 0; k < tl; k++)
                if (!isalnum((unsigned char)t[k]) && t[k] != '-' && t[k] != '_') { fprintf(stderr, "--bridge-token: only letters, digits, - and _\n"); return 1; }
            memcpy(g_sp.bridge_token, t, tl); g_sp.bridge_token[tl] = '\0';
        } else if (strcmp(argv[i], "--browser-used") == 0 && i+1 < argc) {
            char b[16];
            size_t k, bl = strlen(argv[i + 1]);
            if (bl >= sizeof(b)) bl = sizeof(b) - 1;
            for (k = 0; k < bl; k++) b[k] = (char)tolower((unsigned char)argv[i + 1][k]);
            b[bl] = '\0';
            i++;
            if (strcmp(b, "chromium") && strcmp(b, "chrome") && strcmp(b, "firefox") && strcmp(b, "brave")) {
                fprintf(stderr, "--browser-used must be chromium, chrome, firefox or brave\n");
                return 1;
            }
            snprintf(g_sp.browser_kind, sizeof(g_sp.browser_kind), "%s", b);
        } else if (strcmp(argv[i], "--site-used") == 0 && i+1 < argc) {
            char why[96];
            if (sp_parse_site(argv[++i], g_sp.site_url, sizeof(g_sp.site_url), g_sp.site_origin, sizeof(g_sp.site_origin), why, sizeof(why)) < 0) {
                fprintf(stderr, "--site-used: %s\n", why);
                return 1;
            }
            if (strncmp(g_sp.site_origin, "http://", 7) == 0 && strncmp(g_sp.site_origin + 7, "localhost", 9) && strncmp(g_sp.site_origin + 7, "127.", 4))
                fprintf(stderr, "warning: --site-used %s is plain http: anything on the path to it can read the bridge token\n", g_sp.site_origin);
        } else if (strcmp(argv[i], "--drivers-dir") == 0 && i+1 < argc) {
            snprintf(g_sp.drivers_dir, sizeof(g_sp.drivers_dir), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--chromium-no-sandbox") == 0) {
            g_sp.chromium_no_sandbox = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_sp.verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            sp_usage(); return 0;
        }
    }

    sp_print_banner();

#ifdef SP_PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        SP_ERR("WSAStartup failed"); return 1;
    }
#endif

    /* Generate SPMention */
    sp_gen_mention(g_sp.spmention, sizeof(g_sp.spmention));
    if (g_sp.bridge_token[0] == '\0' && sp_random_hex(g_sp.bridge_token, 16) < 0) {
        SP_ERR("no secure random source: the browser bridge will reject every client");
        g_sp.bridge_token[0] = '\0';
    }
    SP_LOG("SPMention: %s", g_sp.spmention);

    /* SPCode init */
    spc_init_quickjs();

    /* --spc mode: just run the file and exit */
    if (g_sp.spc_mode) {
        int ret = spc_run_file(g_sp.spc_file);
        return ret == 0 ? 0 : 1;
    }

    /* Init daemons */
    sp_daemon_init();

#ifdef SP_PLATFORM_UNIX
    {   /* SPP v1.1 engine: fd limit, peer table, epoll */
        struct rlimit rl;
        size_t k;
        spp_crc32_build_table();            /* once, before any thread uses it */
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rlim_t want = (rlim_t)g_sp.max_peers + 64;   /* + listener, bridge, epoll, logs, browser pipes */
            if (rl.rlim_cur < want) {
                rl.rlim_cur = (want > rl.rlim_max) ? rl.rlim_max : want;
                setrlimit(RLIMIT_NOFILE, &rl);
                getrlimit(RLIMIT_NOFILE, &rl);
            }
            if ((rlim_t)g_sp.max_peers + 64 > rl.rlim_cur) {
                size_t cap = rl.rlim_cur > 64 ? (size_t)rl.rlim_cur - 64 : 1;
                SP_WARN("RLIMIT_NOFILE is %llu: capping max peers %zu -> %zu (raise it with ulimit -n)",
                        (unsigned long long)rl.rlim_cur, g_sp.max_peers, cap);
                g_sp.max_peers = cap;
            }
        }
        g_sp.peers      = (spp_peer_t *)calloc(g_sp.max_peers, sizeof(spp_peer_t));
        g_sp.free_slots = (uint32_t *)malloc(g_sp.max_peers * sizeof(uint32_t));
        if (!g_sp.peers || !g_sp.free_slots) { SP_ERR("out of memory for %zu peer slots", g_sp.max_peers); return 1; }
        for (k = 0; k < g_sp.max_peers; k++) g_sp.free_slots[k] = (uint32_t)(g_sp.max_peers - 1 - k);
        g_sp.free_top = g_sp.max_peers;
        sp_rpc_init();
        g_sp.epfd = epoll_create1(EPOLL_CLOEXEC);
        if (g_sp.epfd < 0) { SP_ERR("epoll_create1: %s", strerror(errno)); return 1; }
        SP_LOG("peer table: %zu slots", g_sp.max_peers);
    }
#endif

    /* Create SPP server socket */
    {
        struct sockaddr_in addr = {0};
        int opt = 1;

        g_sp.server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (g_sp.server_sock == SP_INVALID_SOCKET) {
            SP_ERR("socket: %s", strerror(errno)); return 1;
        }

        setsockopt(g_sp.server_sock, SOL_SOCKET, SO_REUSEADDR,
                   (const char *)&opt, sizeof(opt));

        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons((uint16_t)g_sp.port);

        if (bind(g_sp.server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            SP_ERR("bind: %s", strerror(errno)); return 1;
        }
        if (listen(g_sp.server_sock, 4096) < 0) {
            SP_ERR("listen: %s", strerror(errno)); return 1;
        }
#ifdef SP_PLATFORM_UNIX
        {
            struct epoll_event ev;
            fcntl(g_sp.server_sock, F_SETFL, fcntl(g_sp.server_sock, F_GETFL, 0) | O_NONBLOCK);
            ev.events   = EPOLLIN;
            ev.data.u64 = UINT64_MAX;       /* marks the listener */
            epoll_ctl(g_sp.epfd, EPOLL_CTL_ADD, g_sp.server_sock, &ev);
        }
#endif
    }

#ifdef SP_PLATFORM_UNIX
    pthread_mutex_init(&g_sp.peers_lock, NULL);
    pthread_mutex_init(&g_sp.bridge_tx_lock, NULL);

    /* Start SPP server thread */
    pthread_create(&g_sp.server_thread, NULL, spp_server_thread, NULL);

    /* Start bridge thread */
    pthread_create(&g_sp.bridge_thread, NULL, bridge_server_thread, NULL);

    /* Start daemons */
    sp_daemons_start();

    /* Launch headless browser */
    if (!g_sp.no_browser) {
        pthread_mutex_lock(&g_browser_lock);
        if (browser_start_locked() < 0)
            SP_WARN("continuing without browser layer");
        pthread_mutex_unlock(&g_browser_lock);
    }
    { pthread_t st; pthread_create(&st, NULL, sched_thread, NULL); pthread_detach(st); }
#else
    SP_WARN("threaded server not implemented for this platform yet");
#endif

    /* Terminal I/O loop */
    sp_terminal_loop();

    /* Shutdown */
    SP_ST(g_sp.running, 0);
    SP_LOG("shutting down...");

    sp_close_socket(g_sp.server_sock);
    if (g_sp.bridge_sock != SP_INVALID_SOCKET)
        sp_close_socket(g_sp.bridge_sock);

#ifdef SP_PLATFORM_UNIX
    if (g_sp.browser_pid > 0) {
        kill(g_sp.browser_pid, SIGTERM);
        usleep(300000);
        SP_LOG("browser process terminated");
    }
    sp_rm_profile();
    pthread_mutex_destroy(&g_sp.peers_lock);
#endif

#ifdef SP_PLATFORM_WINDOWS
    WSACleanup();
#endif

    SP_LOG("goodbye");
    return 0;
}
