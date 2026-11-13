# CHANGELOG

All notable changes to Total IP Control are documented here.

## [2.0.0] — 2026-11-12

**Upgrading from 1.x:** install `SNTIPCTL.DLL`, `SNTIPCTL.MSG`, `SNTIPCTL.MDF`
and `SNTIPCTL.RLN` together. Every message renumbers, so if you reworded any
Total IP Control message in the message editor, note your text first and redo
it afterwards. Existing settings in `SNTIPCTL.DAT` are read and upgraded
automatically with **all settings preserved**.

### Added — Settings menu

- **`/TIP` replaces `/TOTALIP`** and the six full-screen forms. It opens on six
  sections — General Settings, Telnet Trusted Proxies, IPv4 Whitelist, IPv6
  Whitelist, GeoIP Location, SSH Settings — each listing its settings with
  their current values, numbered from 1. Type a number, see what is allowed,
  type the new value. `X` goes back one step.
- **Changes apply and save at once.** There is no Save step, and every change
  writes an Audit Trail line naming the Sysop, the section and the setting.
- **Help everywhere.** `?` at any prompt explains that setting, `H n` in a
  section explains setting *n*, and `H` alone is a quick-start guide.
- **The menu says when a setting cannot work yet**, for example
  `Block direct connections  YES (inactive: no proxy listed)`, in red beside
  its value. Values are coloured by state, and list sections show how many
  entries are in use.
- **Menu item.** A BBS menu item that runs the module with the command line
  `MENU=SYSOPMENU` opens the same menu (MASTER access, as for `/TIP`).
- A `0.0.0.0/0` proxy or whitelist entry is refused instead of being stored as
  empty.

### Added — Longer lists

- **10 trusted proxies each for telnet and SSH** (was 2).
- **50-entry IPv4 whitelist** (was 10), shown 10 to a page; `N`/`P` turn the
  page and any entry's number works from any page.

### Added — IPv6

- **IPv6 callers behind a proxy are fully supported.** A `PROXY TCP6` header is
  parsed and the caller's real IPv6 address is used everywhere the real IPv4
  address is: `/myip`, `/whoson`, the Audit Trail and `LOGINS` log, GeoIP
  lookups, and the per-IP connection limit (two IPv6 users are two people, not
  one proxy address). IPv4-mapped addresses (`::ffff:1.2.3.4`) are treated as
  IPv4.
- **User-profile IP recording for IPv6.** The profile field receives the full
  address, or its `/64` prefix when the full address does not fit the field's
  29 characters — never a truncated address.
- **50-entry IPv6 whitelist** (address or CIDR, e.g. `2001:db8::/32`). An IPv6
  caller whose real address matches is never subject to the connection limit.
- Trusted proxy lists remain IPv4. The BBS listens on IPv4 only, so the hop from
  the proxy to the BBS is always IPv4; the caller behind the proxy can be either.

### Added — SSH

- **The trusted-proxy policy is available for SSH, configured separately** on
  the SSH Settings section: **Manage SSH connections** (the master switch, off
  by default), **Require trusted proxy (block direct)**, **Trusted proxy
  enforcement**, and **its own trusted proxy list**. Trusting a relay for telnet
  does not trust it for SSH.
- **PROXY protocol support for SSH.** With **Process PROXY protocol header** on,
  the caller's real IP replaces the proxy's on SSH connections, exactly as for
  telnet. Requires the SSH Server module (`SNSSH`) to load before `SNTIPCTL` in
  `wgserv.cfg` (the default alphabetical order does).
- **`prx_ssh_ready()` export.** A cooperating SSH server calls it to wait until
  a PROXY header has fully arrived before reading, so a header split across
  packets cannot break the SSH handshake.

### Added — Users and staff

- **`/myip`** — any user can see their own real (post-proxy) IP address.
- **`/whoson`** — a staff who's-online table: user, connection type (`Telnet` /
  `SSH`), real IP, current module and time on line. Callers still in the
  post-login sequence (bulletins, ads) or new-account signup are included.
  Access is set by the **Staff view key** (default `SYSOP`); SYSOP and MASTER
  always have access.
- **Text variables** for message text: `N!SNTIP`, `N!SNTIPSHORT` (long IPv6
  shortened to first..last hextet), `N!SNTUSERID`, `N!SNTMODULE`, `N!SNTTOL`,
  `N!SNTTIPCT` (connection type), `N!SNTVER` (running version), and
  `N!SNTUSERS` / `N!SNTMAXIP` for the refusal messages. A name already taken by
  another module is reported in the Audit Trail at startup.
- **Debug trace log** (General Settings) writes a detailed trace to
  `TOTALIPCONTROL\DEBUG\`, stamped with the running version on its first line.
  It never records users' keystrokes.

### Changed

- **One message file block.** All text, including the whole settings menu, is
  in one `LEVEL6` block of `SNTIPCTL.MSG` and can be reworded in the BBS's
  message editor. `CLIMIT` and `IPGDNY` use `N!SNTUSERS` and `N!SNTMAXIP` in
  place of `%s` and `%d`.
- The MDF's `Online user manual:` names `SNTIPCTL.RLN`.
- A missing `recv()` hook (usually `SNTIPCTL` loaded before `GALTNTD`) raises a
  prominent startup warning naming the fix. A connect-time fallback keeps real-IP
  detection working meanwhile, tagged `(fallback)` in the log.
- The settings record is now version 13. The longer lists live in new records of
  `SNTIPCTL.DAT`; the first 2 proxies per protocol and first 10 IPv4 entries are
  also kept in the main record, so an earlier version still finds them.

### Fixed

- **Board crash (`OVERSIZED SPR() CALL`)** when the per-module gateway refused a
  user while several users were active from the same IP. Every Audit Trail line
  the module writes is now length-bounded, and runtime text is never used as a
  format string.
- **Real IP lost while WorldLink was connected.** The telnet server could read
  and consume the PROXY header before the module's connect handler ran; the busier
  the board, the more often. The header is now captured at that first read and
  applied as soon as the channel is known.
- **SSH connections through a PROXY-protocol front end failing intermittently**
  (as often as eleven tries in twelve).
- **Refusing a connection paused the whole board for half a second**, on every
  refused connection — with block-direct on, that is every port scanner. The
  refusal message is now also delivered reliably instead of being lost to a
  connection reset.
- **Log writing stalled the board** (an open/close per line, slowed further by
  on-access virus scanners). Log files are now held open.
- A client that disconnected while a PROXY header was expected could leave the
  reading daemon spinning.
- `/myip` and `/whoson` could show a stale address from an earlier connection on
  the same channel.
- A PROXY header captured for a connection that never completed could be applied
  to a later connection that reused the same socket handle.

## [1.1.2] — 2026-07-08

### Added — GeoIP provider

- **ipinfo.io is now a selectable GeoIP provider.** Choose `IPINFO.IO` in the
  **Provider** field of the GeoIP Location screen. Unlike the existing
  providers, ipinfo derives its city/region data from its own network probing
  rather than reselling a shared free database, so it is typically more accurate
  at the city level. In testing, IPs that the other providers mislocated by
  hundreds of miles resolved correctly with ipinfo.
- ipinfo requires a free API token (each sysop supplies their own). Sign up for
  a free account at `https://ipinfo.io/signup`, copy the token from the account
  dashboard, and paste it into the existing **Key** field on the GeoIP Location
  screen. The free tier allows 50,000 lookups per month — far more than a BBS
  needs.

### Added — State format option

- **New "State format" setting on the GeoIP Location screen: `CODE` or `FULL`.**
  `CODE` shows the two-letter state code (`Minnesota` → `MN`), `FULL` shows the
  full name. It mirrors the existing Country format option and defaults to
  `CODE`, preserving the previous behavior. Non-US regions always show their
  full name regardless of this setting (there is no universal short code for
  foreign subdivisions). The choice is applied at write time, so it takes effect
  on the next lookup without touching stored records.

### Changed — GeoIP API host field

- **The API Host field is now optional and defaults to the selected provider.**
  Leave it blank and the correct host is used automatically for whichever
  provider is chosen (`ipwho.is`, `ip-api.com`, `ipapi.co`, or `ipinfo.io`).
  Only fill it in to point a provider at a custom or self-hosted endpoint. This
  also fixes a latent issue where a default host left in the field after
  switching providers could route requests to the wrong host.

### Notes

- ipinfo returns state/region as the full name; it is mapped to the two-letter
  code for US results (via the new State format option) so it renders like the
  other providers by default. Non-US regions keep their full name (e.g.
  `London, England, GB`).
- ipinfo returns the country as a two-letter code only. Total IP Control now maps
  the code to a full country name (via a built-in ISO 3166 table), so the Country
  format FULL/CODE option works with ipinfo just like the other providers.
- No settings-file change: the new provider and State format settings are stored
  in spare space within the existing version 10 record. Upgrading is drop-in and
  preserves all settings.

## [1.1.1] — 2026-07-08

### Fixed

- **Rejected connections no longer log a `SEND error 10038 (Socket operation on
  non-socket)` in the BBS audit trail.** When a connection was refused by
  *Require trusted proxy* (or the pre-login connection limit), the socket was
  closed *after* the connection had already been handed to the telnet daemon,
  so the BBS still tried to flush the login banner to the now-closed socket on
  the next scheduler cycle. The refusal is now performed *before* the
  connection is handed off, so the channel is never activated and nothing is
  ever written to the closed socket. This also removes stray trailing bytes
  that could appear after the "connection refused" message.

### Changed — Audit logging

- **"Audit logging" is now a four-way choice cycled with the space bar:
  `NO` / `AUDIT` / `LOG` / `BOTH`.** The setting controls two independent
  sinks — the BBS **Audit Trail** (the live sysop log) and the daily **log
  files** under `TOTALIPCONTROL\`. `AUDIT` writes only the Audit Trail, `LOG`
  writes only the files, `BOTH` writes both, and `NO` writes neither.
  Previously this was a Yes/No switch that wrote files but also emitted a
  per-connection IP line to the Audit Trail regardless of the setting; with
  `NO` selected nothing is logged now.
- **New login access log** — a dedicated `TOTALIPCONTROL\LOGINS\` daily file
  records **who connected and from where**: one line per successful login for
  **every** protocol (telnet, SSH, and others) with the timestamp, user ID, real
  IP, and protocol. Written whenever file logging is on (`LOG` or `BOTH`).
- **Every login's real IP is recorded** according to the selected mode. In the
  Audit Trail, telnet real IPs appear at connect time (when the PROXY header is
  processed) and SSH and other daemons at login; the `LOGINS\` file records all
  protocols uniformly at login. Connection and gateway denials are routed to the
  selected sink(s).
- The settings record advanced to version 10 (the audit-logging byte was
  repurposed from `Y`/`N` to the new mode). Existing settings files are read and
  upgraded automatically with **all settings preserved** — a prior "Yes" maps to
  `BOTH` (files + trail), matching the previous behavior.

### Changed — SSH Server module compatibility

- **"Require trusted proxy (block direct)" now applies to telnet only.** The
  block is identified against the accepting server, so SSH, Rlogin, and any
  other registered daemon are no longer refused by it. SSH connections are
  direct and already end-to-end encrypted, so the trusted-proxy requirement —
  which exists to force plaintext telnet through an authorized proxy — does not
  apply to them. Per-IP connection limiting, audit logging, GeoIP location, and
  user-profile IP recording continue to apply to SSH and every other protocol.

## [1.1.0] — 2026-07-04

### Added

- **GeoIP Location** — Looks up each caller's approximate City / State / Country
  from their IP address at login and stores it in configurable user-profile
  field(s).  US states are stored as the standard two-letter abbreviation;
  locations elsewhere use the most appropriate subdivision plus country.

  - **Write modes** — *Split* (default) stores the city/state and the country in
    two separate fields (city/state → Address 3, country → Address 4 by default);
    *Combined* stores the whole location in one field.  A **country format**
    option renders the country as its full name (`United States`) or two-letter
    code (`US`).

  - **Non-blocking by design.** Lookups run on a dedicated background worker
    thread and results are applied on the main thread by a once-per-second
    `rtkick()` drain, so login is never delayed and a failed, slow, or
    unreachable provider can never prevent a user from logging in.
  - **Per-IP caching** with selectable **cache mode** — *TIME* (re-look-up after
    a configurable duration, default 24 hours), *IP* (a known IP is never looked
    up again while the BBS is up; minimizes API calls), or *OFF*.  Private,
    loopback, and reserved IP ranges are never looked up.
  - **Provider abstraction** — Ships with **ipwho.is** as the default provider
    (keyless free tier, HTTPS, dedicated two-letter US state field); the request
    builder and response parser are structured so further providers can be added
    without reworking the module.
  - **Configurable** via a new **GeoIP Location** form in the `/TOTALIP` editor:
    enable/disable, write mode, city/state field, country field, country format,
    provider, API host, API key, HTTPS, timeout, cache mode and duration, retry
    count, log level, and a location format template (`{city}`, `{region}`,
    `{country}`, `{cc}` tokens).  The provider is selected by cycling with the
    space bar, and HTTPS is adjusted automatically for providers whose free tier
    is HTTP-only.
  - **Logging** — A dedicated `TOTALIPCONTROL\GEOIP LOGS\` folder with its own
    OFF / ERRORS / NORMAL / VERBOSE verbosity control records successful lookups,
    failures, API errors, rate limiting, and cache activity.

### Changed

- Settings record format advanced to version 9 to hold the GeoIP configuration.
  A version 7 settings file (from 1.0.0) is migrated automatically on first
  start with **all existing settings preserved** — the GeoIP options are added
  with default values and the feature starts disabled.
- The `/TOTALIP` editor now presents four forms (GeoIP Location added), with a
  consistent layout across every form.

## [1.0.0] — 2026-06-29

### Fixed

- **Gateway bypass-key sessions no longer count against the per-IP limit for
  other users.** When a user holding a bypass key (e.g., Sysop) entered a
  gateway-protected module first, their session was counted by the IP check
  applied to subsequent users from the same IP. This caused the limit to appear
  one slot lower than configured for non-bypass users, blocking a legitimate
  connection that should have been allowed. Bypass-key holders' sessions are now
  excluded from the count via `gen_haskey()`, matching the intent that bypass
  keys skip the limit entirely rather than just skip the check at entry time.

## [1.0.0] — 2026-06-22

### Added

- **Proxy Protocol v1** — Detects and processes `PROXY TCP4` headers prepended
  by a reverse proxy.  Real IP is restored into `tcpipinf[n].inaddr` before
  GALTNTD performs any telnet negotiation.  Implemented via IAT patching of
  `recv()` in GALTNTD.DLL for zero-sleep, event-driven detection.  Falls back
  to a single non-blocking `FIONREAD` check if the IAT patch is unavailable.

- **Trusted proxy enforcement** — Optional restriction of PROXY header
  processing to up to two configured trusted proxy IP/CIDR ranges.  Connections
  from untrusted sources pass through without IP replacement.  Prevents PROXY
  header spoofing from arbitrary callers.

- **Require trusted proxy (block direct connections)** — A separate, optional
  toggle that refuses any connection not relayed by a configured trusted proxy,
  at connect time before the login prompt.  Stops users from bypassing the
  reverse proxy by telnetting straight to the backend port.  Loopback (the
  local console) and connection-limit whitelist IPs are always exempt, and an
  empty trusted-proxy list disables blocking entirely, so a misconfigured CIDR
  cannot lock the system out.

- **Global IP connection limits** — BBS-wide cap on simultaneous active
  sessions from a single IP address.  Enforced both at connect time (before the
  login prompt) and at login.  Sessions exceeding the limit receive a message
  naming the other user(s) already connected from that IP, then are
  disconnected.  Limit is configurable; feature can be disabled independently.

- **Connection limit whitelist** — Up to ten IP/CIDR entries that are never
  subject to the connection limit.

- **Per-module IP gateway** — A BBS menu item can route users through the
  gateway (`MODULE=`, `MAXIP=`, `BYPASS=` parameters) to enforce a separate
  per-module simultaneous-connection cap per IP.  Denied users see the other
  user(s) from their IP already in that module.

- **User profile IP recording** — Writes the real caller IP to a selected
  field in the user's account record (`usrad1`–`usrad4` or `usrpho`) on every
  successful login.  Field is configurable; feature can be disabled.

- **Audit logging** — Daily log files under `TOTALIPCONTROL\`, split into three
  folders: `PROXCLIP LOGS\` (proxy events, profile writes), `DENIED CONNECTIONS\`
  (connection-limit violations), and `DENIED MODULE ACCESS\` (gateway denials,
  including the other userids from that IP).  Thread-safe via `CRITICAL_SECTION`.

- **Online configuration editor** — Master-level Sysop command `/TOTALIP` opens
  an interactive editor using full-screen data entry (FSE) forms for General
  Settings, Trusted Proxy CIDRs, and the Connection Limit Whitelist.  Changes
  take effect immediately and persist to `SNTIPCTL.DAT` (a Btrieve file) across
  restarts.

- `SNTIPCTL.MDF` module descriptor, replacing `PROXCLIP` and `IPCTRL`.
- Windows version resource (`SNTIPCTL.rc`) with product name, version, and
  copyright metadata.

### Changed (development, pre-release)

- The configuration editor now suppresses the output pager for the entire
  session, so no "(N)onstop, (Q)uit, or (C)ontinue?" prompt appears when moving
  between menus or returning from a form. (Replaces the earlier per-screen
  suppression.)
- The General Settings "Profile field" prompt now lists all five choices
  (1=Address1 … 5=Phone) instead of only the first and last.
- The startup status message for audit logging now reads "audit file logging
  enabled in TOTALIPCONTROL folder".

### Fixed (development, pre-release)

- FSE configuration form fields were offset by one row — caused by clear-screen
  / cursor-home (`ESC[2J ESC[H`) in the form templates; removed from all
  templates.
- Proxy header processing is now reliable when the `PROXY` header arrives split
  across TCP reads. A timing race could previously leave the header partially
  read, which both prevented the real client IP from being restored and left
  stray header bytes in the input stream — corrupting terminal handling, so that
  (for example) arrow keys stopped working in the configuration editor. The recv
  hook now waits for the complete header before releasing the connection to the
  BBS, and always consumes the header so the input stream stays clean.
- Connection-limit disconnect of a logged-on user is now handled by the MBBS
  `byenow()` log-off utility, fixing several problems together: the denial
  message reaches the user and renders correctly with the list of other sessions
  from their IP (no scrambling), the Main Menu no longer flashes before the
  disconnect, no paging prompt interrupts it, and the channel is freed cleanly
  (no lingering "still connected" session). The earlier approach wrote the
  message to the socket directly and called `aschup()`, which garbled the text
  (it interleaved with the BBS's own queued logon output) and did not actually
  disconnect the session. Pre-login rejections, where no BBS session exists yet,
  still write to the socket and close it directly.
- The configuration editor no longer appears to display the "Settings saved"
  confirmation twice — the spurious redraw MBBS triggers after a full-screen
  form closes is now absorbed.
