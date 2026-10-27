# LocalEnterprise (LE) 1.0.0

Spin-off of `sharedprotocol.c`. One C file, Linux only:
`gcc -O2 -Wall -Wextra -o localenterprise localenterprise.c -lpthread`

Kept from SP: the SPP v1.1 epoll engine (128k-peer design), SPP_RPC, the capability byte.
Removed: browser + bridge, SPCode, daemons, drivers, cron, relay, trace, SPMemory, JS forwarding.

## Quick start
    ./localenterprise --fse-root /srv/enterprise --state-dir /var/lib/le
    localenterprise> rpc server.token.add {"name":"alice","caps":"fsr,fsw","role":"dev"}     # secret shown once
    localenterprise> rpc policy.rule.add {"effect":"allow","who":"role:dev","action":"fse.*","resource":"/projects/**"}
    curl -H "Authorization: Bearer le_..." http://127.0.0.1:5223/files/projects/readme.txt

Default is deny: with no rules, no token or peer can do anything except identity / auth / own caps.
The terminal is the administrator and is never policy-checked. Use `--no-terminal` to run as a daemon.

## Capabilities (one byte, per token / SPP peer)
srv 0x01 routes+settings · kick 0x02 peers · tok 0x04 tokens · exec 0x08 fse.exec (+fsr) · logr 0x10 audit log + metrics ·
policy 0x20 rules/roles/grant · fsw 0x40 write ops · fsr 0x80 read ops.
Caps say which kinds of calls are possible; policy rules say which concrete calls are allowed. Both must pass.

## SPPLogE
`<state-dir>/audit.log`, mode 0600, one JSON line per action, hash-chained (`prev`, `hash` = SHA-256).
Logged: connection open/handshake/close, every non-ping SPP frame, every RPC (caller, method, redacted params,
ok/error, duration), every policy decision, auth ok/fail, token/rule/route/config changes, every HTTP request,
FSE operations (as RPC / http entries), start/stop. Params with token/secret/pass/key/content/data/auth/cookie/cred
keys are replaced with `***`; file contents are never logged.
Rotation at `--log-max-mb` keeps the chain across files. If the log cannot be written, all non-terminal calls are
denied (fail-closed; `--log-fail-open` to disable) and `/health` returns 503.
Verify: `rpc log.verify`, terminal `logverify`, or offline `localenterprise --verify-log f [--expect-head <hash>]`.
Editing, deleting or reordering lines is detected. Truncating the END is only detected against a head hash you saved
elsewhere (`loghead` / `rpc log.head`).

## SPPPolicyE
Rule = effect · who · action · resource · hours · days. who: `*`, `kind:peer|http`, `name:`, `role:`, `mention:`,
`ip:a.b.c.d/n`, `conn:N` joined with `&`. action globs over `rpc.<method>`, `fse.<op>`, `http.<METHOD>`;
resource globs over the FSE or HTTP path (`*` = one segment, `**` = anything, `/dir/**` also covers `/dir`).
Deny overrides allow; no match = `--policy-default` (deny). `hours` like 09:00-18:00 (wraps midnight), `days` like mon-fri.
Modes: `enforce` / `audit` (log would-be denials, allow). `policy.set {"lockdown":true}` denies all non-terminal calls.
Roles per connection: `policy.role.set`. `policy.eval` simulates a decision. Rules persist in `policy.db`.

## FSE (jailed to `--fse-root`)
fse.stat ls read hash · write touch mkdir rm mv cp chmod · exec · info. Paths are walked with openat(O_NOFOLLOW):
no symlink is ever followed, `..` is rejected, no existence is revealed before the policy check passes.
The FSE root must not contain (or be inside) the state/log directory. Reads ≤ 32 KB and writes ≤ 48 KB per SPP call
(use offset / append / patch; HTTP streams whole files). chmod refuses setuid/setgid/sticky.
`fse.exec` is OFF unless `--fse-exec`: runs a regular, executable file from the jail via fexecve with a clean env,
cwd = root, no stdin, merged output capped at 32 KB, timeout (default 10 s, max 60 s), rlimits (CPU, memory, file size,
fds), no_new_privs, own process group killed at the end, max 8 at once. It is NOT a sandbox: the program runs as the
LE user and can touch anything that user can. Run LE as an unprivileged user.

## SPPServer (HTTP/1.1, default 127.0.0.1:5223, no TLS: put a TLS proxy in front)
Pipeline: request id → conn/IP limits → rate limit → CORS → Bearer auth → route → policy → handler → audit log.
Built in: `GET /health` (public) · `GET /metrics` (logr) · `POST /rpc` {"method","params"} · `GET|HEAD|PUT|DELETE /files/<path>`
(Range, directory listing with a trailing `/`, `?mode=append|create`, `?parents=1`, `?recursive=1`).
User routes: `server.route.add {method,pattern,type:text|json|file|rpc,target,public?,status?,content_type?}`;
patterns support `:param` and a trailing `/*`; file routes can mount a directory. Non-public routes need a token and
pass policy as `http.<METHOD>`. `server.config {rate,max_body,cors}`. Request smuggling guards: chunked bodies,
duplicate Content-Length, obsolete folding, oversized headers are rejected.

## SPP
Same framing as SP (26-byte header, CRC32). Only SPP_RPC is served. `auth.login {token}` gives the connection the
token's caps/name/role (five failures drop it); revoking or expiring a token cuts live sessions.

## License
MIT, Copyright (c) 2026 Sekid; see `LICENSE`. Provided as is, without warranty. Meeting any regulatory or compliance requirement is the responsibility of whoever deploys it.
