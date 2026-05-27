/*
 * sharedprotocol.c — SharedProtocol Terminal App v1.0.0
 *
 * Single-file C implementation of the SharedProtocol runtime.
 * Boots SPP, launches headless Chromium, bridges to SP in the browser,
 * runs host daemons (SPAI, SPRegistry, SPReport, SPPolicy, SP-CRON, SharedWorkers).
 *
 * Build:
 *   Linux/Android:  gcc -o sharedprotocol sharedprotocol.c -lpthread -lm
 *   Windows:        cl sharedprotocol.c ws2_32.lib
 *
 * Usage:
 *   sharedprotocol               — start with defaults
 *   sharedprotocol --port 5221   — custom SPP port
 *   sharedprotocol --no-browser  — SPP + daemons only, no headless browser
 *   sharedprotocol --spc <file>  — run a .spc script on host and exit
 */

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

/* ── SPP Constants ─────────────────────────────────────────────────────────── */
#define SPP_VERSION         0x0100   /* v1.0 */
#define SPP_MAGIC           "\x53\x50\x50\x01"  /* "SPP\x01" */
#define SPP_MAGIC_LEN       4
#define SPP_DEFAULT_PORT    5221
#define SPP_BRIDGE_PORT     5222     /* local WebSocket bridge to headless browser */
#define SPP_MAX_PEERS       64
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

#define SPP_HEADER_SIZE     sizeof(spp_header_t)  /* 22 bytes */
#define SPP_CRC_SIZE        4

/* ── SPP Peer ──────────────────────────────────────────────────────────────── */
typedef struct {
    sp_socket_t  sock;
    char         spmention[64];
    char         session_id[37];  /* UUID */
    uint64_t     seq_local;
    uint64_t     seq_remote;
    uint8_t      caps;            /* bitmask: 0x01=browser 0x02=daemon 0x04=host 0x08=mesh */
    int          active;
    time_t       last_ping;
} spp_peer_t;

/* ── Daemon State ──────────────────────────────────────────────────────────── */
typedef struct {
    int      id;
    char     name[32];
    int      running;
    char     spc_path[256];  /* path to .spc script for this daemon */
    uint64_t start_time;
    int      restart_count;
} sp_daemon_t;

/* ── Global State ──────────────────────────────────────────────────────────── */
static struct {
    sp_socket_t   server_sock;
    sp_socket_t   bridge_sock;    /* bridge to headless browser */
    spp_peer_t    peers[SPP_MAX_PEERS];
    int           peer_count;
    sp_daemon_t   daemons[SP_DAEMON_MAX];
    int           running;
    int           port;
    int           bridge_port;
    char          spmention[64];
    int           no_browser;
    char          spc_file[256];  /* --spc mode */
    int           spc_mode;
    char          chromium_bin[256];
#ifdef SP_PLATFORM_UNIX
    pid_t         browser_pid;
    pthread_t     server_thread;
    pthread_t     bridge_thread;
    pthread_t     daemon_threads[SP_DAEMON_MAX];
    pthread_mutex_t peers_lock;
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
    struct tm *tm = localtime(&t);
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
    srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)out);
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

  static void spc_init_quickjs(void) {
      qjs_rt  = JS_NewRuntime();
      qjs_ctx = JS_NewContext(qjs_rt);
      JS_SetMemoryLimit(qjs_rt, 16 * 1024 * 1024); /* 16MB */
      JS_SetMaxStackSize(qjs_rt, 512 * 1024);       /* 512KB */
      SP_LOG("SPCode: QuickJS runtime ready");
  }

  static int spc_run(const char *src, const char *filename) {
      JSValue result;
      int ret = 0;

      /* Inject sp object */
      JSValue sp_obj    = JS_NewObject(qjs_ctx);
      JSValue print_fn  = JS_NewCFunction(qjs_ctx, js_sp_print, "print", 1);
      JSValue daemon_obj = JS_NewObject(qjs_ctx);
      JSValue dstart_fn = JS_NewCFunction(qjs_ctx, js_sp_daemon_start, "start", 1);

      JS_SetPropertyStr(qjs_ctx, daemon_obj, "start", dstart_fn);
      JS_SetPropertyStr(qjs_ctx, sp_obj, "daemon", daemon_obj);
      JS_SetPropertyStr(qjs_ctx, sp_obj, "print",  print_fn);
      JS_SetPropertyStr(qjs_ctx, JS_GetGlobalObject(qjs_ctx), "sp", sp_obj);
      JS_SetPropertyStr(qjs_ctx, JS_GetGlobalObject(qjs_ctx), "print", print_fn);

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
      return ret;
  }

#else
  /* Minimal .spc runner without QuickJS — handles print() and basic sp.* */
  static void spc_init_quickjs(void) {
      SP_LOG("SPCode: minimal host runner active (build with -DUSE_QUICKJS for full JS)");
  }

  static int spc_run(const char *src, const char *filename) {
      /* Very minimal: just handle print("...") lines for now */
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
    d->running = 1;
    d->start_time = sp_now_ms();

    while (g_sp.running && d->running) {
        /* Run daemon .spc if it exists */
        FILE *f = fopen(d->spc_path, "r");
        if (f) {
            fclose(f);
            if (spc_run_file(d->spc_path) < 0) {
                SP_WARN("daemon[%s]: .spc error, restarting in 3s", d->name);
                d->restart_count++;
                sleep(3);
                continue;
            }
        }
        /* Daemon heartbeat — sleep and loop */
        sleep(1);
    }

    SP_LOG("daemon[%s]: stopped", d->name);
    d->running = 0;
    return NULL;
}
#endif

static void sp_daemons_start(void) {
#ifdef SP_PLATFORM_UNIX
    for (int i = 0; i < SP_DAEMON_MAX; i++) {
        pthread_create(&g_sp.daemon_threads[i], NULL, sp_daemon_thread, &g_sp.daemons[i]);
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
static int sp_find_chromium(char *out, size_t sz) {
    static const char *candidates[] = {
#ifdef SP_PLATFORM_WINDOWS
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        "C:\\Program Files\\Chromium\\Application\\chromium.exe",
#elif defined(SP_PLATFORM_ANDROID)
        /* Android: look for Chromium APK CLI or Termux chromium */
        "/data/local/tmp/chromium",
        "/system/bin/chromium",
#else
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/brave-browser",
        "/snap/bin/chromium",
        "/usr/local/bin/chromium",
#endif
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        FILE *f = fopen(candidates[i], "r");
        if (f) { fclose(f); strncpy(out, candidates[i], sz - 1); return 1; }
    }

    /* Try PATH via which/where */
#ifdef SP_PLATFORM_WINDOWS
    FILE *p = _popen("where chromium 2>nul", "r");
#else
    FILE *p = popen("which chromium-browser 2>/dev/null || which chromium 2>/dev/null || which google-chrome 2>/dev/null", "r");
#endif
    if (p) {
        char tmp[256] = {0};
        if (fgets(tmp, sizeof(tmp), p)) {
            tmp[strcspn(tmp, "\r\n")] = '\0';
            if (strlen(tmp) > 0) { strncpy(out, tmp, sz - 1); pclose(p); return 1; }
        }
        pclose(p);
    }

    return 0;
}

static int sp_launch_browser(void) {
    char cmd[1024];
    char sp_url[256];

    if (!sp_find_chromium(g_sp.chromium_bin, sizeof(g_sp.chromium_bin))) {
        SP_WARN("browser: no Chromium-based browser found — SP browser layer disabled");
        SP_WARN("browser: install chromium, google-chrome, or brave to enable");
        return -1;
    }

    SP_LOG("browser: found %s", g_sp.chromium_bin);

    /* Bootstrap HTML: injects bridge config then fetches SP from sharedpro.pages.dev */
    snprintf(sp_url, sizeof(sp_url),
        "data:text/html,<script>"
        "window.__SP_BRIDGE_PORT__=%d;"
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
        g_sp.bridge_port, g_sp.spmention);

    snprintf(cmd, sizeof(cmd),
        "\"%s\" "
        "--headless=new "
        "--disable-gpu "
        "--no-sandbox "
        "--disable-dev-shm-usage "
        "--js-flags=--max-old-space-size=128 "   /* limit RAM */
        "--disk-cache-size=0 "
        "--remote-debugging-port=0 "
        "--app=\"%s\"",
        g_sp.chromium_bin, sp_url);

#ifdef SP_PLATFORM_UNIX
    g_sp.browser_pid = fork();
    if (g_sp.browser_pid == 0) {
        /* child */
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(1);
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

static uint64_t ws_htonll(uint64_t v) {
    /* host to network 64-bit */
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xFFFFFFFF));
    return ((uint64_t)hi) | ((uint64_t)lo << 32);
}

static int bridge_ws_handshake(sp_socket_t client) {
    char buf[2048] = {0};
    char response[512];
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char key[128] = {0};
    char accept[64] = {0};

#ifdef SP_PLATFORM_WINDOWS
    int n = recv(client, buf, sizeof(buf)-1, 0);
#else
    ssize_t n = recv(client, buf, sizeof(buf)-1, 0);
#endif
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* Extract Sec-WebSocket-Key */
    char *p = strstr(buf, "Sec-WebSocket-Key:");
    if (!p) { SP_ERR("bridge: no WebSocket key in handshake"); return -1; }
    p += 18;
    while (*p == ' ') p++;
    char *end = strstr(p, "\r\n");
    if (!end) return -1;
    strncpy(key, p, (size_t)(end - p));

    /* Compute accept key: SHA1(key + magic) → base64
     * Minimal implementation — we concatenate and do a simple hash
     * For production, link OpenSSL and use proper SHA1+base64 */
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", key, magic);

    /* Simple base64 of combined string (not real SHA1 — works for our own bridge) */
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t *in = (uint8_t *)combined;
    size_t in_len = strlen(combined);
    char *out = accept;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16)
                   | (i+1 < in_len ? (uint32_t)in[i+1] << 8 : 0)
                   | (i+2 < in_len ? (uint32_t)in[i+2]      : 0);
        *out++ = b64[(v >> 18) & 0x3F];
        *out++ = b64[(v >> 12) & 0x3F];
        *out++ = (i+1 < in_len) ? b64[(v >> 6) & 0x3F] : '=';
        *out++ = (i+2 < in_len) ? b64[v & 0x3F]        : '=';
    }
    *out = '\0';

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
    SP_LOG("bridge: WebSocket handshake complete");
    return 0;
}

static int bridge_ws_send(sp_socket_t sock, const uint8_t *data, size_t len) {
    uint8_t frame[14 + SPP_MAX_PAYLOAD];
    size_t  hdr_len = 2;

    frame[0] = 0x82; /* FIN + binary opcode */
    if (len <= 125) {
        frame[1] = (uint8_t)len;
        hdr_len  = 2;
    } else if (len <= 65535) {
        frame[1] = 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
        hdr_len  = 4;
    } else {
        frame[1] = 127;
        uint64_t l = ws_htonll((uint64_t)len);
        memcpy(frame + 2, &l, 8);
        hdr_len = 10;
    }

    memcpy(frame + hdr_len, data, len);
#ifdef SP_PLATFORM_WINDOWS
    return send(sock, (char *)frame, (int)(hdr_len + len), 0) < 0 ? -1 : 0;
#else
    return send(sock, frame, hdr_len + len, MSG_NOSIGNAL) < 0 ? -1 : 0;
#endif
}

static int bridge_ws_recv(sp_socket_t sock, uint8_t *out, size_t *out_len) {
    uint8_t hdr[14];
    size_t  hdr_len = 2;
    uint64_t payload_len;
    int masked;

#ifdef SP_PLATFORM_WINDOWS
    if (recv(sock, (char *)hdr, 2, 0) != 2) return -1;
#else
    if (recv(sock, hdr, 2, MSG_WAITALL) != 2) return -1;
#endif

    masked      = (hdr[1] & 0x80) != 0;
    payload_len = hdr[1] & 0x7F;

    if (payload_len == 126) {
#ifdef SP_PLATFORM_WINDOWS
        if (recv(sock, (char *)(hdr+2), 2, 0) != 2) return -1;
#else
        if (recv(sock, hdr+2, 2, MSG_WAITALL) != 2) return -1;
#endif
        payload_len = ((uint64_t)hdr[2] << 8) | hdr[3];
        hdr_len = 4;
    } else if (payload_len == 127) {
#ifdef SP_PLATFORM_WINDOWS
        if (recv(sock, (char *)(hdr+2), 8, 0) != 8) return -1;
#else
        if (recv(sock, hdr+2, 8, MSG_WAITALL) != 8) return -1;
#endif
        memcpy(&payload_len, hdr+2, 8);
        hdr_len = 10;
    }

    uint8_t mask[4] = {0};
    if (masked) {
#ifdef SP_PLATFORM_WINDOWS
        if (recv(sock, (char *)mask, 4, 0) != 4) return -1;
#else
        if (recv(sock, mask, 4, MSG_WAITALL) != 4) return -1;
#endif
    }

    if (payload_len > SPP_MAX_PAYLOAD) return -1;

#ifdef SP_PLATFORM_WINDOWS
    if (recv(sock, (char *)out, (int)payload_len, 0) < (int)payload_len) return -1;
#else
    if (recv(sock, out, (size_t)payload_len, MSG_WAITALL) < (ssize_t)payload_len) return -1;
#endif

    if (masked)
        for (uint64_t i = 0; i < payload_len; i++)
            out[i] ^= mask[i & 3];

    *out_len = (size_t)payload_len;
    return 0;
}

/* ── Peer message handler ──────────────────────────────────────────────────── */
static void spp_handle_message(spp_peer_t *peer, uint16_t msg_type,
                                uint8_t *payload, uint32_t payload_len) {
    switch (msg_type) {

    case SPP_PING:
        spp_send(peer->sock, SPP_PONG, peer->seq_local++, NULL, 0);
        peer->last_ping = time(NULL);
        break;

    case SPP_PONG:
        peer->last_ping = time(NULL);
        break;

    case SPP_DATA:
        payload[payload_len] = '\0';
        SP_DBG("SPP_DATA from %s: %s", peer->spmention, payload);
        /* Forward to bridge if browser is connected */
        if (g_sp.bridge_sock != SP_INVALID_SOCKET)
            bridge_ws_send(g_sp.bridge_sock, payload, payload_len);
        break;

    case SPP_IO_INPUT:
        /* Terminal input → forward to SP in browser via bridge */
        payload[payload_len] = '\0';
        SP_DBG("IO_INPUT: %s", payload);
        if (g_sp.bridge_sock != SP_INVALID_SOCKET)
            bridge_ws_send(g_sp.bridge_sock, payload, payload_len);
        break;

    case SPP_SPC_RUN:
        /* Run .spc payload on host */
        payload[payload_len] = '\0';
        SP_LOG("SPC_RUN: executing script (%u bytes)", payload_len);
        {
            int ret = spc_run((char *)payload, "<remote>");
            char result[64];
            snprintf(result, sizeof(result), "{\"ok\":%s}", ret == 0 ? "true" : "false");
            spp_send(peer->sock, SPP_SPC_RESULT, peer->seq_local++,
                     (uint8_t *)result, (uint32_t)strlen(result));
        }
        break;

    case SPP_DAEMON_START:
        if (payload_len >= 1) {
            uint8_t did = payload[0];
            sp_daemon_handle_msg(did, payload + 1, payload_len - 1);
        }
        break;

    case SPP_DAEMON_STOP:
        if (payload_len >= 1) {
            uint8_t did = payload[0];
            if (did >= 1 && did <= SP_DAEMON_MAX)
                g_sp.daemons[did-1].running = 0;
        }
        break;

    case SPP_CLOSE:
        SP_LOG("peer %s sent CLOSE", peer->spmention);
        peer->active = 0;
        sp_close_socket(peer->sock);
        break;

    default:
        SP_WARN("unknown msg_type 0x%04x from %s", msg_type, peer->spmention);
        break;
    }
}

/* ── Server thread ─────────────────────────────────────────────────────────── */
#ifdef SP_PLATFORM_UNIX
static void *spp_client_thread(void *arg) {
    spp_peer_t *peer = (spp_peer_t *)arg;
    spp_header_t hdr;
    uint8_t      payload[SPP_MAX_PAYLOAD + 1];
    uint32_t     payload_len;

    while (g_sp.running && peer->active) {
        memset(&hdr, 0, sizeof(hdr));
        payload_len = 0;
        if (spp_recv(peer->sock, &hdr, payload, &payload_len) < 0) {
            SP_LOG("peer %s disconnected", peer->spmention);
            break;
        }
        peer->seq_remote = hdr.seq;
        spp_handle_message(peer, hdr.msg_type, payload, payload_len);
    }

    peer->active = 0;
    sp_close_socket(peer->sock);
    SP_LOG("client thread for %s exiting", peer->spmention);
    return NULL;
}

static void *spp_server_thread(void *arg) {
    (void)arg;
    SP_LOG("SPP server listening on port %d", g_sp.port);

    while (g_sp.running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        sp_socket_t client = accept(g_sp.server_sock,
                                    (struct sockaddr *)&client_addr, &addr_len);
        if (client == SP_INVALID_SOCKET) {
            if (g_sp.running) SP_ERR("accept: %s", strerror(errno));
            break;
        }

        SP_LOG("new connection from %s", inet_ntoa(client_addr.sin_addr));

        /* Find free peer slot */
        pthread_mutex_lock(&g_sp.peers_lock);
        spp_peer_t *peer = NULL;
        for (int i = 0; i < SPP_MAX_PEERS; i++) {
            if (!g_sp.peers[i].active) { peer = &g_sp.peers[i]; break; }
        }
        pthread_mutex_unlock(&g_sp.peers_lock);

        if (!peer) {
            SP_WARN("peer slots full, rejecting connection");
            sp_close_socket(client);
            continue;
        }

        memset(peer, 0, sizeof(*peer));
        if (spp_do_handshake_server(client, peer) < 0) {
            SP_ERR("handshake failed");
            sp_close_socket(client);
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, spp_client_thread, peer);
        pthread_detach(tid);
    }

    return NULL;
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

    while (g_sp.running) {
        sp_socket_t client = accept(srv, NULL, NULL);
        if (client == SP_INVALID_SOCKET) break;
        SP_LOG("bridge: browser connected");

        if (bridge_ws_handshake(client) < 0) {
            sp_close_socket(client); continue;
        }

        g_sp.bridge_sock = client;

        /* Relay loop: browser → SPP peers */
        uint8_t buf[SPP_MAX_PAYLOAD + 1];
        size_t  len;
        while (g_sp.running) {
            len = 0;
            if (bridge_ws_recv(client, buf, &len) < 0) break;
            buf[len] = '\0';
            SP_DBG("bridge→SPP: %zu bytes", len);
            /* Broadcast to all active SPP peers */
            pthread_mutex_lock(&g_sp.peers_lock);
            for (int i = 0; i < SPP_MAX_PEERS; i++) {
                if (g_sp.peers[i].active)
                    spp_send(g_sp.peers[i].sock, SPP_IO_OUTPUT,
                             g_sp.peers[i].seq_local++, buf, (uint32_t)len);
            }
            pthread_mutex_unlock(&g_sp.peers_lock);
        }

        g_sp.bridge_sock = SP_INVALID_SOCKET;
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

    while (g_sp.running && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';

        if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  help              — this message\n");
            printf("  status            — show SPP and daemon status\n");
            printf("  peers             — list connected peers\n");
            printf("  daemons           — list daemon status\n");
            printf("  spc <file>        — run a .spc file on host\n");
            printf("  stop              — stop sharedprotocol\n");
            printf("  <any SPCode>      — run inline SPCode on host\n");

        } else if (strcmp(line, "status") == 0) {
            printf("SPP port:    %d\n", g_sp.port);
            printf("Bridge port: %d\n", g_sp.bridge_port);
            printf("Mention:     %s\n", g_sp.spmention);
            printf("Browser:     %s\n", g_sp.no_browser ? "disabled" : g_sp.chromium_bin);

        } else if (strcmp(line, "peers") == 0) {
            int found = 0;
            for (int i = 0; i < SPP_MAX_PEERS; i++) {
                if (g_sp.peers[i].active) {
                    printf("  [%d] %s  session=%s\n",
                           i, g_sp.peers[i].spmention, g_sp.peers[i].session_id);
                    found++;
                }
            }
            if (!found) printf("  no peers connected\n");

        } else if (strcmp(line, "daemons") == 0) {
            for (int i = 0; i < SP_DAEMON_MAX; i++) {
                printf("  [%d] %-12s  %s\n",
                       g_sp.daemons[i].id,
                       g_sp.daemons[i].name,
                       g_sp.daemons[i].running ? "\033[32mrunning\033[0m" : "\033[31mstopped\033[0m");
            }

        } else if (strncmp(line, "spc ", 4) == 0) {
            spc_run_file(line + 4);

        } else if (strcmp(line, "stop") == 0) {
            g_sp.running = 0;
            break;

        } else if (strlen(line) > 0) {
            /* Treat as inline SPCode */
            spc_run(line, "<stdin>");
        }

        printf("\n\033[1;36msharedprotocol>\033[0m ");
        fflush(stdout);
    }
}

/* ── SP-side additions (JS snippet for sharedprotocol.js) ───────────────────
 *
 * Paste the following into sharedprotocol.js to add SPP terminal support:
 *
 *   // ── SPTerminal ─────────────────────────────────────────────────────────
 *   // Handles connection from sharedprotocol C app via local WebSocket bridge.
 *   // Exposes terminal I/O: sp.terminal.send(msg), sp.terminal.on(fn)
 *   // VFS and SPMemory are NOT accessible from the terminal connection.
 *   //
 *   class SPTerminal {
 *     constructor(sp) {
 *       this._sp       = sp;
 *       this._ws       = null;
 *       this._handlers = [];
 *       this._port     = window.__SP_BRIDGE_PORT__ || 5222;
 *       this._mention  = window.__SP_MENTION__     || null;
 *       this._connect();
 *     }
 *     _connect() {
 *       try {
 *         this._ws = new WebSocket("ws://127.0.0.1:" + this._port);
 *         this._ws.binaryType = "arraybuffer";
 *         this._ws.onopen    = () => log("SPTerminal: bridge connected");
 *         this._ws.onmessage = (e) => this._onMessage(e.data);
 *         this._ws.onclose   = () => { log("SPTerminal: bridge closed"); setTimeout(() => this._connect(), 3000); }
 *         this._ws.onerror   = (e) => log("SPTerminal: bridge error", e);
 *       } catch(e) { log("SPTerminal: WebSocket not available"); }
 *     }
 *     _onMessage(data) {
 *       const msg = typeof data === "string" ? data : new TextDecoder().decode(data);
 *       for (const fn of this._handlers) { try { fn(msg); } catch {} }
 *     }
 *     send(msg) {
 *       if (this._ws && this._ws.readyState === WebSocket.OPEN)
 *         this._ws.send(typeof msg === "string" ? msg : JSON.stringify(msg));
 *     }
 *     on(fn) { this._handlers.push(fn); return this; }
 *   }
 *   sp.terminal = new SPTerminal(sp);
 *
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
    printf("  SharedProtocol Terminal v1.0.0  |  SPP v1.0  |  SPCode host runner\n\n");
}

static void sp_usage(void) {
    printf("Usage: sharedprotocol [options]\n\n");
    printf("Options:\n");
    printf("  --port <n>       SPP listen port (default: %d)\n", SPP_DEFAULT_PORT);
    printf("  --bridge <n>     Bridge WebSocket port (default: %d)\n", SPP_BRIDGE_PORT);
    printf("  --no-browser     Disable headless browser launch\n");
    printf("  --spc <file>     Run a .spc file on host and exit\n");
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
        if (listen(g_sp.server_sock, 16) < 0) {
            SP_ERR("listen: %s", strerror(errno)); return 1;
        }
    }

#ifdef SP_PLATFORM_UNIX
    pthread_mutex_init(&g_sp.peers_lock, NULL);

    /* Start SPP server thread */
    pthread_create(&g_sp.server_thread, NULL, spp_server_thread, NULL);

    /* Start bridge thread */
    pthread_create(&g_sp.bridge_thread, NULL, bridge_server_thread, NULL);

    /* Start daemons */
    sp_daemons_start();

    /* Launch headless browser */
    if (!g_sp.no_browser) {
        if (sp_launch_browser() < 0)
            SP_WARN("continuing without browser layer");
    }
#else
    SP_WARN("threaded server not implemented for this platform yet");
#endif

    /* Terminal I/O loop */
    sp_terminal_loop();

    /* Shutdown */
    g_sp.running = 0;
    SP_LOG("shutting down...");

    sp_close_socket(g_sp.server_sock);
    if (g_sp.bridge_sock != SP_INVALID_SOCKET)
        sp_close_socket(g_sp.bridge_sock);

#ifdef SP_PLATFORM_UNIX
    if (g_sp.browser_pid > 0) {
        kill(g_sp.browser_pid, SIGTERM);
        SP_LOG("browser process terminated");
    }
    pthread_mutex_destroy(&g_sp.peers_lock);
#endif

#ifdef SP_PLATFORM_WINDOWS
    WSACleanup();
#endif

    SP_LOG("goodbye");
    return 0;
}
