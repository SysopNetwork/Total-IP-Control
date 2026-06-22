# CHANGELOG

All notable changes to Total IP Control are documented here.

## [1.0.0] — Unreleased

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
