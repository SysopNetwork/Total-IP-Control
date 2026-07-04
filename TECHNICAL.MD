# Total IP Control — Technical Reference

## Architecture Overview

`SNTIPCTL` is a single-source-file Major BBS v10 module (`SNTIPCTL.C`) compiled
as a 32-bit Win32 DLL. It registers with the BBS module system and installs two
hooks into the TCP/IP layer at startup:

1. **`hdlcon` hook** — Intercepts every new telnet connection to mark the socket
   for PROXY header processing, to apply connection-limit checks at connect
   time, and to enforce the "require trusted proxy" policy before login.

2. **`recv()` IAT patch** — Replaces the `recv()` entry in `GALTNTD.DLL`'s
   Import Address Table so the PROXY header is consumed before GALTNTD reads
   any application data, without polling or sleeping.

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
4. Size the full-screen editor forms (`fsdroom`) and reserve per-user VDA space
   (`dclvda`).
5. Apply built-in defaults (all features off), then `cfg_load()` to read the
   saved settings record from `SNTIPCTL.DAT`.
6. Create the audit-log directory tree if logging is enabled, and the
   `GEOIP LOGS\` folder if GeoIP logging is enabled.
7. Resolve `_tcpipinf` at runtime from `GALTCPIP.DLL` via `GetProcAddress`
   (avoids link-time ordinal dependencies).
8. Save and replace `hdlcon`.
9. Patch `recv()` in `GALTNTD.DLL`'s IAT (falls back to `GALTCPIP.DLL` if
   GALTNTD is unavailable, and to a single non-blocking check if no patch slot
   is found).
10. `geoip_start()` — create the GeoIP worker thread and its signalling events,
    and arm the once-per-second result-drain `rtkick()`.
11. Register the `/TOTALIP` global command handler (`globalcmd`).

If `hdlcon` is NULL at init (because `GALTNTD` has not yet loaded), proxy
detection cannot be installed and a fatal warning is logged.

---

## IAT Patching

`find_iat_recv()` walks the PE import directory of the target module to find the
IAT slot for `recv()` from `WS2_32.dll` or `wsock32.dll`. It handles both named
and ordinal imports (matching the current slot value against the known
`WS2_32!recv` address).

`patch_iat_recv()` makes the IAT page writable with `VirtualProtect`, overwrites
the slot with `prx_recv_hook`, and restores the original protection. The
original address is saved in `real_recv` for pass-through and shutdown
restoration. `SNTIPCTL`'s own `recv()` calls go through its own unpatched IAT,
so there is no recursion.

---

## Connection Handling (`sntipctl_hdlcon`)

Called by GALTNTD for every new connection. In order:

1. Record `(*tcpipinf)[usrnum].socket` in `pending_skt[usrnum]` so the recv hook
   can process the PROXY header on first read.
2. Call through to the original `hdlcon` (`hcsave`).
3. **Require-trusted-proxy enforcement** (if enabled): the raw TCP peer IP — the
   proxy's address for a relayed connection, or the client's own address for a
   direct one — is checked against the trusted-proxy list. A connection that is
   not from a trusted proxy is refused before login: the `PRXBLK` message is
   written to the socket, the socket is closed, and the channel is released.
   Loopback (`127.0.0.0/8`) and whitelisted addresses are always exempt, and an
   empty trusted-proxy list disables blocking.
4. **Connection-limit check** (non-proxy connections, where the real IP is
   already known): if the per-IP limit is reached, the `CLIMIT` message is sent
   and the connection is closed before the login prompt.

---

## PROXY Protocol v1 Parsing

The recv hook (`prx_recv_hook`) fires on every `recv()` GALTNTD makes:

- Peek reads (`MSG_PEEK`) are passed straight through.
- For a non-peek read on a pending socket, `prx_consume_header()` is called.
  It returns one of three results, and the hook acts accordingly:
  - **consumed** — a complete header was read (and applied, or discarded if the
    source is untrusted); the pending flag is cleared and the read passes
    through.
  - **not a PROXY stream** — the pending flag is cleared and the read passes
    through untouched.
  - **incomplete** — the header is still arriving; the hook returns
    `WSAEWOULDBLOCK` and leaves the pending flag set, so GALTNTD's non-blocking
    event loop retries on the next readable event. No partial data is delivered.

This guarantees the entire header is consumed before GALTNTD reads any
application data, even when the header is split across TCP segments — preventing
a half-consumed header from corrupting the input stream.

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

Only `TCP4` (IPv4) headers are applied; other protocols pass through unchanged.
If the IAT patch was unavailable, `sntipctl_hdlcon` performs a single
non-blocking `FIONREAD` check as a best-effort fallback.

---

## Trusted Proxy Enforcement

Up to two trusted proxy entries are stored as `struct snt_cidr` (network address
+ mask, both in network byte order). A bare IP is treated as `/32`; an all-zero
entry is unused. `is_trusted_proxy(ip)` returns TRUE if `ip` matches any
configured entry.

Two independent switches use this list:

- **Trusted proxy enforcement** — when on, PROXY headers are applied only when
  the connecting IP is trusted (anti-spoofing). The connection is still allowed.
- **Require trusted proxy** — when on, connections not from a trusted proxy are
  refused at connect time (see Connection Handling). Both switches are no-ops
  when the trusted list is empty.

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

The editor is opened with `/TOTALIP` from anywhere on the BBS; the `MASTER` key
is required.

`sntipctl_gbl()` (a `globalcmd` handler) matches the command, verifies access,
sets `usrptr->state = cfgstt` / `substt = CFGSTT_MENU`, suppresses the output
pager for the whole session, and displays the top menu.

`sntipctl_stt()` (the `sttrou` state-input routine) drives the editor:

- `substt == 0` — entered from a BBS menu item; runs the per-module gateway.
- `CFGSTT_MENU` — top-level menu. `1`/`2`/`3`/`4` launch full-screen (FSE) forms;
  `X`/`Q` restores the pager and exits via `condex()`.

The four FSE forms are **General Settings**, **Trusted Proxy IP/CIDRs**
(2 entries), **Connection Limit Whitelist** (10 entries), and **GeoIP Location**.
All four share a uniform layout — the same header, the same `Action:` / error
footer, and field markers aligned to a common column. Each form's done callback
applies its fields to the live variables and persists them with `cfg_save()`.

Three interaction details:

- **Pager suppression.** The editor sets `scnbrk` to the continuous-output
  sentinel `CTNUOS` for the whole session (on `/TOTALIP` entry) and restores the
  user's real screen length only on exit. Channel output is transmitted
  asynchronously by the poll loop, so `cfg_show_topmenu()` — which draws the
  header/banner/menu — keeps `scnbrk` pinned to `CTNUOS` while the editor owns
  the pager (rather than restoring a value the FSD teardown may have left paged),
  which is what prevents a `(N)onstop,Q,C?` prompt when the menu redraws after a
  form closes.
- **Menu redraw on form close.** Each form's done callback (`cfg_finish_form`)
  redraws the top menu immediately, optionally with a one-line "settings saved"
  banner printed *after* the screen-clearing header so it is not wiped (and does
  not flash on a separate screen).
- **Spurious input absorption** (`absorb_count`) swallows the empty/`/` input
  the BBS delivers immediately after a global command or a full-screen form
  closes, so a real keystroke is never lost and the menu is not redrawn twice.

---

## Configuration Storage

### `SNTIPCTL.DAT` (Btrieve)

Settings are stored in a single 512-byte Btrieve record keyed by `"SNTIPCTL"`,
created automatically on first run via `dfaCreateSpec` (guarded by a
file-existence check to avoid a spurious create error on restart). The record
carries a layout-version byte (currently **9**). A compile-time assertion keeps
`sizeof(struct sntipctlcfg)` pinned at 512 bytes as fields are added.

The record holds: trusted-proxy enable flag and two CIDRs, require-trusted-proxy
flag, connection-limit enable flag and maximum, audit-logging flag, profile-IP
enable flag and field number, bypass key name, ten whitelist CIDRs, the GeoIP
block (enable flag, city/state field number, provider, HTTPS flag, timeout,
cache flag and duration, retry count, log level, host, key, and format
template), and the version-9 write-mode block (split flag, country field number,
country format).

Each block was appended after the previous version's fields (carved from the old
spare area), so an older record is a byte-compatible prefix of the current
layout. `cfg_load()` therefore **migrates a version 7 or 8 record in place with
all existing settings preserved** — it loads them, applies defaults only for the
blocks that record lacked (the whole GeoIP block for v7; the write-mode block for
both v7 and v8), and rewrites the record as version 9. A record from an
incompatible older version is replaced with defaults. `cfg_save()` writes the
record when an editor form is saved; changes are live immediately and persist
across restarts.

### `SNTIPCTL.MCV` (read-only at runtime)

Compiled from `SNTIPCTL.MSG` by the BBS message compiler (GCNF). It contains the
display messages (`LEVEL6`) and the full-screen editor templates (`LEVEL99`),
read via `opnmsg`/`rawmsg`/`prfmsg`. It holds no settings values.

The message **source** uses bare `[` for ANSI sequences (so it is safe to edit
and render in design tools); the actual escape byte (`0x1B`) is injected at
packaging time. See `BUILDING.MD`.

---

## Shutdown

`sntipctl_fin()` (the `finrou`) runs at BBS shutdown:

1. `geoip_stop()` — stops the result drain, signals and **joins** the GeoIP
   worker thread, and frees its events and critical section (done first, so the
   thread cannot run while the DLL unloads).
2. Restores the original `recv()` address in the patched IAT slot.
3. Restores the original `hdlcon` pointer.
4. Deletes the audit-log critical section.
5. Closes the settings file and the message file.

---

## Source Files

| File | Purpose |
|---|---|
| `SRC\SNTIPCTL.C` | All module logic |
| `SRC\SNTIPCTL.H` | Message slot numbers, FSE field numbers, editor sub-state constants |
| `SRC\DIST\SNTIPCTL.MSG` | Message source (display messages + FSE templates; bare `[`) |
| `SRC\DIST\SNTIPCTL.MDF` | Module descriptor |
| `SRC\SNTIPCTL_EXP.DEF` | Export definition for the `init__sntipctl` entry alias |
| `SRC\SNTIPCTL.RC` | Windows version resource |
| `SRC\SNTIPCTL.vcxproj` | Visual Studio 2022 project |

`SNTIPCTL.DAT` is created at runtime and is not part of the source tree.

---

## Credits

- **Developer:** Mark Laudenbach
- **R&D / Testing:** Gregory McGill

Maintained by Sysop Network. Released under the MIT License.
