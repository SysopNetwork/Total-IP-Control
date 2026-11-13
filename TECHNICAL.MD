# Total IP Control — Technical Reference

## Architecture Overview

`SNTIPCTL` is a single-source-file Major BBS v10 module (`SNTIPCTL.C`) compiled
as a 32-bit Win32 DLL. It registers with the BBS module system and installs two
hooks into the TCP/IP layer at startup:

1. **`hdlcon` hook** — Intercepts every new connection, on every registered
   daemon, to mark the socket for PROXY header processing, to apply
   connection-limit checks at connect time, and to enforce the "require trusted
   proxy" policy before login. The accepting daemon is identified by its
   `svrinf` name, and each protocol's policy is applied independently.

2. **`recv()` IAT patch** — Replaces the `recv()` entry in the Import Address
   Table of whichever module reads the socket, so the PROXY header is consumed
   before any application data is seen, without polling or sleeping. Two modules
   are patched: `GALTNTD.DLL` for telnet, and `ssh.dll` — the libssh library the
   SSH Server module (`SNSSH`) hands its accepted sockets to — for SSH.

It also starts a **background worker thread** and a once-per-second `rtkick()`
routine for GeoIP location lookups (see *GeoIP Location* below), so blocking
network I/O never runs on the main scheduler thread.

All features share one configuration record and one lifecycle.

---

## Module Initialization

`init__sntipctl()` runs when `SNTIPCTL.DLL` loads. The sequence is:

1. `register_module(&SNTIPCTL)` — registers the module interface block and
   stores the returned state number in `cfgstt` (used by the online editor and
   the per-module gateway).
2. Initialize the audit-log `CRITICAL_SECTION` and clear the per-channel
   pending-socket table.
3. `opnmsg("SNTIPCTL.MCV")` — open the compiled message file.
4. Apply built-in defaults (all features off), then `cfg_load()` to read the
   saved settings record from `SNTIPCTL.DAT`.
5. (Log folders under `TOTALIPCONTROL\` are not created here: the log writer
   creates a file's folders the first time it opens it.)
7. Resolve `_tcpipinf` at runtime from `GALTCPIP.DLL` via `GetProcAddress`
   (avoids link-time ordinal dependencies).
8. Save and replace `hdlcon`.
9. Patch `recv()` in `GALTNTD.DLL`'s IAT (falls back to `GALTCPIP.DLL` if
   GALTNTD is unavailable, and to a single non-blocking check if no patch slot
   is found), then patch `recv()` in `ssh.dll`'s IAT if that module is loaded.
   The two patches are tracked independently: either can fail without affecting
   the other.
10. `geoip_start()` — create the GeoIP worker thread and its signalling events,
    and arm the once-per-second result-drain `rtkick()`.
11. Register the `/MYIP`, `/WHOSON` and `/TIP` global command handler (`globalcmd`).

If `hdlcon` is NULL at init (because `GALTNTD` has not yet loaded), proxy
detection cannot be installed and a fatal warning is logged.

---

## IAT Patching

`find_iat_recv()` walks the PE import directory of the target module to find the
IAT slot for `recv()` from `WS2_32.dll` or `wsock32.dll`. It handles both named
and ordinal imports (matching the current slot value against the known
`WS2_32!recv` address).

`patch_iat_recv()` makes the IAT page writable with `VirtualProtect`, overwrites
the slot with `prx_recv_hook`, and restores the original protection. Each patched
slot is recorded in `iat_patches[]` alongside its original address, so
`sntipctl_fin()` can restore every one of them at shutdown; a slot that is
already hooked is never re-recorded, which keeps a repeat call from saving
`prx_recv_hook` as the "original". `SNTIPCTL`'s own `recv()` calls go through its
own unpatched IAT, so there is no recursion.

`ssh.dll` imports `recv` **by ordinal** (WS2_32 ordinal 16), which is why
`find_iat_recv()` must resolve ordinal imports by comparing the bound slot value
against `WS2_32!recv` rather than by name. Because `ssh.dll` is a static import
of `SNSSH.DLL`, it is already in the process by the time `SNTIPCTL` initializes,
provided `SNSSH` precedes `SNTIPCTL` in `wgserv.cfg`.

Two booleans, `tnt_recv_hooked` and `ssh_recv_hooked`, record which patches
succeeded. They are tracked separately rather than inferred from `real_recv`:
telnet must fall back to its `FIONREAD` path when only `ssh.dll` was hooked, and
SSH header processing must stay off when only the telnet module was.

---

## Connection Handling (`sntipctl_hdlcon`)

`hdlcon` is the BBS "handle connect" vector, reached for every new connection on
every registered daemon. GALTNTD calls it for telnet; `SNSSH` reaches it through
the `bbscon()` call in its `incall` routine. The accepting daemon is identified
from `(*tcpipinf)[usrnum].server->name` (`"Telnet"` / `"SSH"`), and everything
below is keyed off that. Rlogin, FTP and any other daemon are never blocked here.

In order:

1. **Require-trusted-proxy enforcement** (if enabled for the connecting
   protocol): the raw TCP peer IP — the proxy's address for a relayed
   connection, or the client's own address for a direct one — is checked against
   that protocol's trusted-proxy list. Loopback (`127.0.0.0/8`) and whitelisted
   addresses are always exempt, and an empty trusted-proxy list disables blocking.
   Refusal differs by protocol; see below.
2. Record `(*tcpipinf)[usrnum].socket` in `pending_skt[usrnum]`, and the protocol
   in `pending_proto[usrnum]`, so the recv hook can process the PROXY header on
   first read. SSH is only registered when the Sysop enabled header processing
   **and** `ssh.dll` was hooked.
3. **Connection-limit check** — telnet only, and only for connections whose real
   IP is already known at connect time (no pending PROXY header). If the per-IP
   limit is reached, the `CLIMIT` message is sent and the connection is closed
   before the login prompt. SSH and every other protocol are limited at logon
   instead, via the `byenow()` path in `sntipctl_logon`.
4. Call through to the original `hdlcon` (`hcsave`).

### Refusing a connection

The two protocols must be refused differently, because of **when** `hdlcon` runs
relative to the daemon taking ownership of the socket.

**Telnet** — refused at the door. `PRXBLK` is written straight to the socket,
`closesocket()` is called, and `hdlcon` returns **without** calling `hcsave()`,
so GALTNTD never activates the channel. Skipping `hcsave()` is essential: if
GALTNTD claimed the channel first and the socket were then closed, both GALTNTD
and GALTCPIP would still hold the now-closed handle and would try to flush the
login banner to it on the next scheduler cycle — the cause of the audit-trail
`TCP/IP ERROR ... SEND error 10038 (Socket operation on non-socket)` and the
garbled bytes after the refusal message.

**SSH** — refused with `shutdown(skt, SD_BOTH)`, and `hcsave()` **is** called.
By the time `hdlcon` runs for an SSH channel, `SNSSH` has already passed the
socket to libssh via `ssh_bind_accept_fd()`; `hdlcon` is reached from the
`bbscon()` call that follows it. From that moment libssh owns the descriptor and
closes it itself in `ssh_free()`. Calling `closesocket()` here — the telnet
technique — would leave libssh to close a descriptor the OS may already have
reused for an unrelated connection. `shutdown()` instead tears down the
*connection* while leaving the descriptor valid and owned by libssh: the next
read returns EOF, `SNSSH`'s key-exchange pump fails the session, and its normal
teardown (`snssh_drop` → reap → `ssh_free` + `bbsdsc`) releases the channel and
the socket exactly once. The channel must therefore be allowed to finish
connecting, which is why `hcsave()` is still called.

No refusal text is sent on SSH. Nothing has been negotiated at that point, so
plaintext written now would land in the middle of the SSH version exchange and
the client would report a protocol error rather than display it. The refusal is
recorded in `DENIED CONNECTIONS` instead.

---

## PROXY Protocol v1 Parsing

The recv hook (`prx_recv_hook`) fires on every `recv()` made by a patched module
— GALTNTD for telnet, libssh (`ssh.dll`) for SSH:

- Peek reads (`MSG_PEEK`) are passed straight through.
- A socket that `sntipctl_hdlcon` never registered is passed straight through.
  This is what makes the hook inert when SSH header processing is switched off.
- For a non-peek read on a pending socket, `prx_consume_header()` is called.
  It returns one of three results, and the hook acts accordingly:
  - **consumed** — a complete header was read (and applied, or discarded if the
    source is untrusted); the pending flag is cleared and the read passes
    through.
  - **not a PROXY stream** — the pending flag is cleared and the read passes
    through untouched.
  - **incomplete** — the header is still arriving; the hook returns
    `WSAEWOULDBLOCK` and leaves the pending flag set, so the daemon's
    non-blocking event loop retries on the next readable event. No partial data
    is delivered. GALTNTD retries directly; libssh turns the `WSAEWOULDBLOCK`
    into `SSH_AGAIN`, which `SNSSH`'s key-exchange pump already treats as "need
    more data" and re-drives on the next socket notification.

This guarantees the entire header is consumed before the daemon reads any
application data, even when the header is split across TCP segments — preventing
a half-consumed header from corrupting the input stream (for telnet, garbled ANSI
and dead arrow keys; for SSH, a broken version exchange).

The socket is mapped back to its channel by `pending_unum_for()`, which matches
**only** against the current channel (`pending_skt[usrnum] == s`). That is always
correct here: `hdlsock()` calls `curusr(usrnum)` before invoking any socket event
handler, and every libssh read is driven from `SNSSH`'s `sktnfy()` callback, which
was registered with that same `usrnum`.

This must not be "hardened" into a scan of `pending_skt[]` for the socket. A stale
entry whose handle the OS has since recycled would then match a *different*
channel, and the hook would consume bytes from a live session's stream and rewrite
the wrong channel's IP. A missed match merely passes the read through untouched; a
wrong match corrupts a connection.

`prx_consume_header()` distinguishes "no data yet" from "connection gone": a peek
returning 0 (EOF), or failing with anything other than `WSAEWOULDBLOCK`, reports
*not a PROXY stream* so the daemon reads the EOF/error and tears the channel down.
Reporting "wait" there would spin, since `select()` keeps calling a closed socket
readable.

`prx_consume_header()` logic:

1. `recv(..., MSG_PEEK)` reads up to 127 bytes without consuming them.
2. Leading `\r`/`\n` bytes are skipped.
3. The available bytes are compared against the `"PROXY "` prefix. Bytes that
   already diverge mean "not a PROXY stream" (returned immediately, so ordinary
   telnet clients are never delayed); a partial prefix means "incomplete".
4. Once the full `"PROXY "` prefix and the `\r\n` terminator are present, the
   exact header bytes are consumed with a non-peeking `recv()`.
5. If trusted-proxy enforcement is on and the source is not trusted, the header
   is consumed but **not** applied (the event is logged).
6. Otherwise `sscanf` parses
   `"PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n"` and the source IP
   (`inet_addr`) is written into `(*tcpipinf)[unum].inaddr`.

Which trusted list and enforcement flag apply is chosen from
`pending_proto[unum]`, so the telnet and SSH policies never share a list.

When a connect-time Audit Trail line is emitted here, `conn_ip_logged[unum]` is
set so `sntipctl_logon` does not write a second, redundant line for the same
session. (Telnet is skipped from the logon trail line unconditionally, as it
always has been; a *direct* SSH login — no header, nothing logged at connect —
still produces its trail line.)

Only `TCP4` (IPv4) headers are applied; other protocols pass through unchanged.
If the telnet IAT patch was unavailable, `sntipctl_hdlcon` performs a single
non-blocking `FIONREAD` check as a best-effort fallback. That fallback is never
run for SSH: with no hook there is no SSH header support to fall back to, and a
destructive read there would steal bytes from libssh.

---

## Trusted Proxy Enforcement

Up to ten trusted proxy entries per protocol are stored as `struct snt_cidr`
(network address + mask, both in network byte order; IPv4 only, since the BBS
listens on IPv4 and the proxy's hop to it is always IPv4). A bare IP is treated as `/32`; an all-zero
entry is unused. `cidr_list_match()` does the work; `is_trusted_proxy(ip)` and
`is_ssh_trusted_proxy(ip)` apply it to the telnet and SSH lists respectively.

Two independent switches use each list:

- **Trusted proxy enforcement** — when on, PROXY headers are applied only when
  the connecting IP is trusted (anti-spoofing). The connection is still allowed.
- **Require trusted proxy** — when on, connections not from a trusted proxy are
  refused at connect time (see Connection Handling). Both switches are no-ops
  when the trusted list is empty.

### SSH policy

The SSH policy is a parallel, fully independent copy of the telnet one: its own
enable flags and its own trusted proxy CIDR list. The two protocols may be
fronted by different proxies, and trusting a relay to assert client IPs for
telnet must not implicitly trust it for SSH.

| Variable | Meaning |
|---|---|
| `ssh_manage_enabled` | Master gate. Off ⇒ no SSH-specific policy at all |
| `ssh_hdr_enabled` | Consume a PROXY v1 header on SSH and rewrite the channel IP |
| `ssh_trust_enabled` | Only apply a consumed header from a trusted SSH proxy |
| `ssh_block_enabled` | Refuse SSH not relayed by a trusted SSH proxy |
| `ssh_proxy_cidrs[]` | The SSH trusted list (`ssh_proxy_count` non-empty entries) |

`ssh_hdr_enabled` has no telnet counterpart because telnet header processing is
unconditional. For SSH it must be opted into: the interception it requires
reaches into libssh, and it only makes sense when the front end actually sends
the header on the SSH port.

Every SSH setting takes effect on the next connection, since all of them are read
in `hdlcon`. The one exception is `ssh_hdr_enabled`, which additionally needs
`ssh.dll` to have been hooked at init — `cfg_ssh_done()` logs a message telling
the Sysop to restart if it is turned on while `ssh_recv_hooked` is false.

---

## Connection Limiting

`count_active_ip(ip)` iterates channels up to `hichp1`, skipping the current
channel and any not in `ACTUSR` (fully logged-on) state, and returns the count
of other logged-on sessions with a matching IP.

Enforcement occurs at two points:

- **Connect time** (`sntipctl_hdlcon`) — for connections whose IP is already
  known. The `CLIMIT` message is written directly to the socket and the socket
  is closed before the login prompt.
- **Login** (`sntipctl_logon`, the `lonrou` supplement) — by login the real IP
  is resolved. If the limit is exceeded, the user is logged off with `byenow()`,
  which formats the `CLIMIT` message (naming the other sessions from the same
  IP), flushes output in order, and tears the channel down cleanly.

Exemptions, checked before the count: whitelisted IPs (`is_whitelisted`), the
`SYSOP`/`MASTER` keys, and the configured bypass key (`has_bypass_key`).

The denial message (`CLIMIT`) includes the list of other user IDs currently
connected from the same IP, built by `build_active_ip_users()` using
`uacoff()` to read each channel's account record.

---

## Per-Module IP Gateway

When a BBS menu item routes into `SNTIPCTL` (entered with `substt == 0`),
`sntipctl_gateway()` runs. It parses `MODULE=`, `MAXIP=`, and `BYPASS=` from the
menu command string (two-pass, to support module names containing spaces),
then:

1. Resolves the target module with `findmod()`.
2. Grants immediately (`entmdl`) if the user holds a bypass key, or if the IP
   layer is unavailable (fail-open).
3. Counts matching in-module sessions for the user's IP (`count_ip_in_mod`).
4. If under `MAXIP`, forwards with `entmdl()`; otherwise denies with `IPGDNY`,
   which lists the other user IDs from the same IP already in that module
   (`build_ip_in_mod_users`).

`BYPASS=` defaults to `SYSOP` when omitted.

---

## User Profile IP Recording

When enabled, `write_ip_to_profile()` runs from `sntipctl_logon()` for sessions
that pass the connection-limit check:

1. The IP is formatted as dotted-decimal.
2. The configured field in `usaptr` is overwritten with `stzcpy()`.
3. `updacc()` persists the account record to the user database.

| Field | `usracc` member | Capacity |
|---|---|---|
| 1 | `usrad1` | 30 bytes (`NADSIZ`) |
| 2 | `usrad2` | 30 bytes (`NADSIZ`) |
| 3 | `usrad3` | 30 bytes (`NADSIZ`) |
| 4 | `usrad4` | 30 bytes (`NADSIZ`) |
| 5 | `usrpho` | 16 bytes (`PHOSIZ`) |

A dotted-decimal IPv4 address is at most 15 characters and fits any of these.

---

## GeoIP Location

GeoIP resolves a caller's approximate City / State / Country from their IP
address and stores it in one or two configurable profile fields (see *Write
modes* below). Because the BBS runs a single cooperative scheduler thread, an
HTTP request (which can take seconds) must never run on that thread. The
subsystem is therefore split across a background worker and the main thread.

### Threading model

```
  main thread (logon)            worker thread              main thread (rtkick, 1/sec)
  ------------------             -------------              ---------------------------
  geoip_enqueue()                geoip_worker()             geoip_drain()
    skip private IP                pop request               pop result
    cache hit -> apply             WinHttp GET (blocking)    geo_cache_store()
    else snapshot req  --queue-->  parse JSON       --queue--> geoip_apply()
        SetEvent(work)             push result                  updaccu(uacoff(ch))
```

- **`geoip_enqueue()` (main thread, from `sntipctl_logon`)** — Skips private,
  loopback, and reserved IPs. On a cache hit it applies the stored location
  immediately. Otherwise it builds a **self-contained request snapshot**
  (`struct geo_req`: channel, IP, userid, host, path, HTTPS flag, timeout,
  provider, retries), pushes it onto a `CRITICAL_SECTION`-guarded queue, and
  signals the worker. It returns instantly — login is never delayed.

- **`geoip_worker()` (background thread)** — Waits on the work/stop events, pops
  a request, performs one blocking WinHTTP GET (`geoip_http_get`) with optional
  retries, parses the response into location **components** (`geoip_parse_body`
  fills a `struct geo_loc`: city, region, country, country code), and pushes a
  `struct geo_res` back. Formatting is deliberately *not* done here — it happens
  on the main thread at apply time, so the current write-mode / format settings
  always apply. **The worker calls no Major BBS SDK function** — it
  reads only the inert request snapshot, never a live BBS global (`usrnum`,
  `usaptr`, `tcpipinf`, …), which the engine reuses the instant a channel hangs
  up. Its only outward action is file logging via `geoip_log()`, which is
  CRT/`fopen`-based and guarded by the shared `log_cs`.

- **`geoip_drain()` (main thread, `rtkick` once per second)** — The only place a
  result re-enters the BBS. It pops results, updates the per-IP cache, and calls
  `geoip_apply()`, which formats the components (`geo_format`) and writes them to
  the profile field(s) per the write mode (`geo_set_field`), then persists once
  with `updaccu(uacoff(channel))` if anything changed — after re-checking the
  channel still holds the **same userid** that requested the lookup, so a
  recycled channel is never written to the wrong user. `updaccu()` persists a
  record keyed by its userid
  and touches no per-user globals, which is required here because a `rtkick`
  routine runs with no current-user context. The drain re-arms itself each
  second unless shutdown has cleared `geo_started`.

### HTTP client

`geoip_http_get()` uses WinHTTP (`winhttp.lib`). Every leg (resolve / connect /
send / receive) is bounded by the configured timeout via `WinHttpSetTimeouts`,
and the read loop bails out if the stop event is signalled, so the worker (and
shutdown) can never block indefinitely. The HTTP status code is read so that
`429` (rate limiting) and other errors are logged distinctly. HTTPS is used
unless disabled; WinHTTP performs TLS transparently.

### Caching

`geo_cache_lookup()` / `geo_cache_store()` maintain a fixed table of
`{ IP, expiry, location components }` entries (the raw `struct geo_loc`, not a
formatted string, so a write-mode change needs no re-lookup), accessed **only
from the main thread**
(enqueue and drain), so no lock is needed. Entries are reused by IP, then by
empty/expired slot, then round-robin.

The **cache mode** (`geoip_cache_on` + `geoip_cache_bytime`) selects expiry:

- **TIME** — `expiry = GetTickCount64() + duration`; a lookup past that time
  misses and re-queries. The historical behavior and the default.
- **IP** — `expiry = (ULONGLONG)-1` (never expires), so a known IP is never
  re-queried while the BBS is up; only an unseen IP triggers a lookup. The
  duration is ignored.
- **OFF** — caching is skipped entirely (`geoip_cache_on == FALSE`).

### Provider abstraction

Two functions form the provider seam:

- `geoip_build_url(provider, ip, …)` — builds the host and request path.
- `geoip_parse_body(provider, body, struct geo_loc *out)` — validates the
  provider's success indicator and extracts city / region / country / country
  code into `out`, choosing the US two-letter state code (or the full
  subdivision name elsewhere) for the region. It does **not** format — the
  main-thread `geo_format()` does that at apply time.

Adding a provider is a matter of adding a `case` to each. Three are wired up:
**ipwho.is** (`GEOPRV_IPWHOIS`, the default), **ip-api.com** (`GEOPRV_IPAPI`),
and **ipapi.co** (`GEOPRV_IPAPICO`). ipwho.is's keyless free tier returns a
dedicated two-letter `region_code`, `country_code`, and a `success` flag over
HTTPS. ip-api.com's free tier is HTTP-only, so `geoip_use_https` is forced off
for it unless a paid key is set.

### Format template

The stored string is assembled from a template with `{city}`, `{region}`,
`{country}`, and `{cc}` tokens (default `{city}, {region}, {country}`).
`{region}` resolves to the US two-letter state code when the country is `US`,
otherwise the full subdivision name. Empty pieces are removed (`geo_join_clean`)
so the result never contains stray separators.

### Write modes

`geoip_apply()` honours a write mode (`geoip_split`):

- **SPLIT (default)** — `geo_format(fmt, L, inc_country=FALSE, …)` renders the
  city/state (the `{country}`/`{cc}` tokens expand to empty) into `geoip_field`,
  and the country — full name or two-letter code per `geoip_cty_fmt` — goes into
  `geoip_cty_field`. Defaults: city/state → Address 3, country → Address 4. If
  the two field numbers collide, the country write is skipped so it cannot
  clobber the city/state value.
- **COMBINED** — `geo_format(fmt, L, inc_country=TRUE, …)` renders the whole
  location (country included per the template) into the single `geoip_field`.

Each field is written through `geo_set_field()`, which copies only when the
stored value actually differs and reports whether it changed; a single
`updaccu()` then persists the record if any field changed.

### Shutdown

`geoip_stop()` (called first in `finrou`) clears `geo_started` (stopping the
drain re-arm), signals the stop event, **joins the worker thread**
(`WaitForSingleObject`) so the DLL is never unloaded while the thread runs, then
closes the events and deletes the critical section.

---

## Audit Logging

When enabled, daily log files are written under `TOTALIPCONTROL\`, split into
three folders:

| Folder | Contents |
|---|---|
| `PROXCLIP LOGS\` | Proxy header processing, untrusted-source rejections, profile IP writes |
| `DENIED CONNECTIONS\` | Per-IP connection-limit refusals (connect time and login) |
| `DENIED MODULE ACCESS\` | Per-module gateway denials |
| `GEOIP LOGS\` | GeoIP lookups, cache activity, API errors, rate limiting, profile updates |

The first three folders follow the global **Audit logging** flag. `GEOIP LOGS\`
is governed independently by the GeoIP **Log level** (OFF / ERRORS / NORMAL /
VERBOSE); `geoip_log()` writes it directly (also under `log_cs`) so worker-thread
and main-thread GeoIP events are serialized safely.

Paths are relative to the BBS root (the process working directory). Files are
named `YYYY-MM-DD.LOG`. Each entry is one line:

```
YYYY-MM-DD HH:MM:SS  <userid padded to 20>  <ip padded to 15>  <event text>
```

`build_log_path(subdir, ...)` and `sntipctl_log_event(subdir, userid, ip, event)`
take the folder name as a parameter. All file I/O is serialized through a
`CRITICAL_SECTION` (`log_cs`), so concurrent channels can log safely.

---

## Online Configuration Editor

The editor opens with `/TIP` from anywhere on the BBS, or from a menu item that
runs the module with the command line `MENU=SYSOPMENU`; both need the `MASTER`
flag (`ed_allowed`). It has two levels, like the Globals `=gset` menu: a list of
six sections with their setting counts, then the chosen section's settings,
numbered from 1.

`sntipctl_gbl()` (for `/TIP`) and `sntipctl_gateway()` (for a menu item whose
command line has `MENU=SYSOPMENU`) both call `ed_open()`, which sets
`usrptr->state = cfgstt` / `substt = ST_TOP`, turns page pausing off with
`btuxnf(usrnum, 0, 19)`, and draws the section list. `sntipctl_stt()` (the
`sttrou`) runs the menu entry when `substt == 0` and hands every other
sub-state to `ed_entry()`:

- `ST_TOP` — the section list: a number opens that section; `H` is the quick
  start; `X`/`Q` leaves (restoring the user's own paging with `rstrxf()` and
  returning 0 via `condex()`).
- `ST_SECT` — one section: a setting number opens it; `H n` is the help for
  setting *n*; `X` goes back to the section list.
- `ST_VALUE` — a new value for a free-form setting (blank keeps it, `?` helps).
- `ST_CHOICE` — a list setting: a choice number or its name.

`MENU=` is parsed with the gateway's other keywords and takes precedence over
`MODULE=`. Only `SYSOPMENU` is defined; any other value is refused with an
Audit Trail warning, so the keyword can name more screens later.

**The settings table.** `fields[]` holds all 150 settings in display order. It
is built once at startup by `ed_build()`: each section's single settings come
from a template (`gen_tmpl`, `tel_tmpl`, `geo_tmpl`, `ssh_tmpl`), and
`ed_add_list()` adds one row per entry of an address list (10 trusted proxies
per protocol, 50 + 50 whitelist entries). Each entry binds a label to the
**live variable** it edits (`&conn_limit_enabled`,
`&whitelist_cidrs[3]`, ...), with a type (`FT_YN`, `FT_NUM`, `FT_KEY`, `FT_STR`,
`FT_SECRET`, `FT_CIDR`, `FT_CIDR6`, `FT_LIST`, `FT_CACHE`), a range or choice
list, a hint, and its help message. A setting's number is its position in the
table, grouped by section; `sections[]` gives each section's title, range and
rows per page (the whitelists show 10 at a time, `N`/`P`), and a row's number
is its position within its section. Yes/no and list settings may
be bound to a `GBOOL` (a `short`) or an `INT`; `ed_getint`/`ed_setint` pick the
width from the entry's `size` so neither is ever written as the other.

**Applying a change** (`ed_applyvalue`): parse and store (`ed_setfield`, which
changes nothing if the value is refused), recompute derived state
(`cfg_after_change`: proxy and whitelist counts, the two logging sinks, the
GeoIP host/HTTPS rules), save (`cfg_save`, or `cfg6_save` for an IPv6 whitelist
entry), and write an Audit Trail line `<userid> changed <section>: <setting>`.

**Screen text** is all in `SNTIPCTL.MSG` (header, rows, prompts, a help message
per setting), with the values supplied through text variables (`N!SNTSTATUS`,
`N!SNTROWNAME`, `N!SNTROWVAL`, `N!SNTHINT`, ...). `ed_rownote()` adds a remark
to a row whose setting cannot take effect right now, such as a block with no
trusted proxy listed.

**Spurious input absorption** (`absorb_count`) swallows the empty/`/` input the
BBS delivers immediately after a global command returns 1, so the first screen
is not drawn twice and no real keystroke is lost.

`TESTS\RUNTESTS.CMD` builds `EDTEST.EXE`, which compiles the editor's table and
value logic straight out of `SNTIPCTL.C` and checks every setting type against
the variable it is bound to — no BBS needed.

---

## Configuration Storage

### `SNTIPCTL.DAT` (Btrieve)

Settings are stored in `SNTIPCTL.DAT`, a Btrieve file of fixed 512-byte
records, each found by its 16-byte `recid` key:

| Record | Holds |
|---|---|
| `SNTIPCTL` | Every single setting, plus the first 2 trusted proxies per protocol and the first 10 IPv4 whitelist entries |
| `SNTPROXY` | The telnet and SSH trusted proxy lists, 10 each |
| `SNTWL4` | The IPv4 whitelist, 50 entries |
| `SNTIPV6WL` | The IPv6 whitelist, entries 1–25 (earlier builds wrote 10 here, at the same offset) |
| `SNTIPV6W2` | The IPv6 whitelist, entries 26–50 |

The list records let the lists grow without changing the main record. The main
record still carries the leading entries it always had, written on every save,
so an earlier build reading the file keeps them; on upgrade, a missing list
record means the lists start from those entries and the record is written on
the first save. Every record is asserted at compile time to be 512 bytes.

The main record (`"SNTIPCTL"`) is created automatically on first run via `dfaCreateSpec` (guarded by a
file-existence check to avoid a spurious create error on restart). The record
carries a layout-version byte (currently **13**). A compile-time assertion keeps
`sizeof(struct sntipctlcfg)` pinned at 512 bytes as fields are added.

The record holds: trusted-proxy enable flag and two CIDRs, require-trusted-proxy
flag, connection-limit enable flag and maximum, audit-logging mode, profile-IP
enable flag and field number, bypass key name, ten whitelist CIDRs, the GeoIP
block (enable flag, city/state field number, provider, HTTPS flag, timeout,
cache flag and duration, retry count, log level, host, key, and format
template), the version-9 write-mode block (split flag, country field number,
country format), the state/region format byte, and the version-11 SSH block
(manage, header, trust and block flags plus two SSH trusted proxy CIDRs).

Each block was appended after the previous version's fields (carved from the old
spare area), so an older record is a byte-compatible prefix of the current
layout. Versions **9, 10 and 11 load directly**: bytes a record predates read as
zero, and `cfg_struct_to_live()` maps them to the behavior that version had (a
v9 `'Y'`/`'N'` audit byte migrates to `LOGM_BOTH`/`LOGM_OFF`; a zeroed v9/v10 SSH
block reads as "SSH unmanaged"). A version **7 or 8** record is migrated in place
**with all existing settings preserved** — it is loaded, defaults are applied only
for the blocks that record lacked (the whole GeoIP block for v7; the write-mode
block for both; the SSH block for both), and it is rewritten as version 11. A
record from an incompatible older version is replaced with defaults. `cfg_save()`
writes the record each time the editor changes a setting; changes are live immediately and
persist across restarts.

### `SNTIPCTL.MCV` (read-only at runtime)

Compiled from `SNTIPCTL.MSG` by the BBS itself at startup. All messages sit in
one `LEVEL6` block — the caller messages, `/MYIP` and `/WHOSON`, and every
screen of the settings editor — so the Sysop can reword any of them in the
BBS's message editor. It holds no settings values. Dynamic values are named text
variables (`N!SNT...`), never positional `printf` arguments.

`SRC\SNTIPCTL.MSG` is the deployable file itself: binary CP437 with real ESC
bytes and CRLF line endings (`.gitattributes` keeps git from converting it).

---

## Shutdown

`sntipctl_fin()` (the `finrou`) runs at BBS shutdown:

1. `geoip_stop()` — stops the result drain, signals and **joins** the GeoIP
   worker thread, and frees its events and critical section (done first, so the
   thread cannot run while the DLL unloads).
2. Restores the original `recv()` address in **every** patched IAT slot
   (`iat_patches[]` — the telnet module and `ssh.dll`).
3. Restores the original `hdlcon` pointer.
4. Deletes the audit-log critical section.
5. Closes the settings file and the message file.

---

## Source Files

| File | Purpose |
|---|---|
| `SRC\SNTIPCTL.C` | All module logic |
| `SRC\SNTIPCTL.H` | Message numbers and setting value constants |
| `SRC\SNTVER.H` | The version number (used by the C code and the `.RC`) |
| `SRC\SNTIPCTL.MSG` | Message file (deployable as-is: ESC bytes, CRLF) |
| `SRC\SNTIPCTL.MDF` | Module descriptor |
| `SRC\SNTIPCTL_EXP.DEF` | Export definition for the `init__sntipctl` entry alias |
| `SRC\SNTIPCTL.RC` | Windows version resource |
| `SRC\SNTIPCTL.vcxproj` | Visual Studio 2022 project |
| `TESTS\RUNTESTS.CMD` | Builds and runs the host-side settings-editor test |

`SNTIPCTL.DAT` is created at runtime and is not part of the source tree.

---

## Credits

- **Developer:** Mark Laudenbach
- **R&D / Testing:** Gregory McGill

Maintained by Sysop Network. Released under the MIT License.
