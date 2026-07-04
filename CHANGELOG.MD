# CHANGELOG

All notable changes to Total IP Control are documented here.

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
