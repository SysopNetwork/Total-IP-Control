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
6. Create the audit-log directory tree if logging is enabled.
7. Resolve `_tcpipinf` at runtime from `GALTCPIP.DLL` via `GetProcAddress`
   (avoids link-time ordinal dependencies).
8. Save and replace `hdlcon`.
9. Patch `recv()` in `GALTNTD.DLL`'s IAT (falls back to `GALTCPIP.DLL` if
   GALTNTD is unavailable, and to a single non-blocking check if no patch slot
   is found).
10. Register the `/TOTALIP` global command handler (`globalcmd`).

`SNTIPCTL` **must** appear after `GALTNTD` in `wgserv.cfg`. If `hdlcon` is NULL
at init, proxy detection cannot be installed and a fatal warning is logged.

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

## Audit Logging

When enabled, daily log files are written under `TOTALIPCONTROL\`, split into
three folders:

| Folder | Contents |
|---|---|
| `PROXCLIP LOGS\` | Proxy header processing, untrusted-source rejections, profile IP writes |
| `DENIED CONNECTIONS\` | Per-IP connection-limit refusals (connect time and login) |
| `DENIED MODULE ACCESS\` | Per-module gateway denials |

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
- `CFGSTT_MENU` — top-level menu. `1`/`2`/`3` launch full-screen (FSE) forms;
  `X`/`Q` restores the pager and exits via `condex()`.

The three FSE forms are **General Settings**, **Trusted Proxy IP/CIDRs**
(2 entries), and **Connection Limit Whitelist** (10 entries). Each form's done
callback applies its fields to the live variables, persists them with
`cfg_save()`, and returns to the menu.

Two interaction details:

- **Pager suppression** is applied once for the editor session (`scnbrk` set to
  the continuous-output sentinel on entry, restored on exit), rather than around
  each screen, so paging never interrupts a form or the menu.
- **Spurious input absorption** (`absorb_count`) swallows the empty/`/` input
  the BBS delivers immediately after a global command or a full-screen form
  closes, preventing duplicate redraws.

---

## Configuration Storage

### `SNTIPCTL.DAT` (Btrieve)

Settings are stored in a single 512-byte Btrieve record keyed by `"SNTIPCTL"`,
created automatically on first run via `dfaCreateSpec` (guarded by a
file-existence check to avoid a spurious create error on restart). The record
carries a layout-version byte; if a record written by an incompatible version is
found, it is deleted and re-created with defaults.

The record holds: trusted-proxy enable flag and two CIDRs, require-trusted-proxy
flag, connection-limit enable flag and maximum, audit-logging flag, profile-IP
enable flag and field number, bypass key name, and ten whitelist CIDRs.

`cfg_load()` reads the record at init; `cfg_save()` writes it when an editor form
is saved. Changes are live immediately and persist across restarts.

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

1. Restores the original `recv()` address in the patched IAT slot.
2. Restores the original `hdlcon` pointer.
3. Deletes the audit-log critical section.
4. Closes the settings file and the message file.

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
