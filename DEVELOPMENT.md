# Development Guide

Internal development notes for **Total IP Control** (`SNTIPCTL`). For build and
packaging steps see [BUILDING.MD](BUILDING.MD); for architecture and internals
see [TECHNICAL.MD](TECHNICAL.MD).

---

## Project Overview

**Total IP Control** (`SNTIPCTL`) is a The Major BBS v10 module written in C. It
consolidates and expands functionality from two earlier modules — PROXCLIP
(proxy protocol / real IP restoration) and IPControl (per-IP connection
limiting) — into a single, unified IP management system.

---

## Platform

- **Target:** The Major BBS v10 — a 32-bit Windows DLL module
- **Language:** C (Win32, built against the MBBS v10 SDK)
- **Build tool:** Visual Studio 2022 (v143 toolset), MSBuild
- **SDK:** The Major BBS v10 SDK — proprietary, obtained separately and located
  via the `MBBS_SDK_DIR` variable (see [BUILDING.MD](BUILDING.MD))

---

## Build

```powershell
# Build Release (Win32)
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" `
    SNTIPCTL.sln /p:Configuration=Release /p:Platform=Win32 /t:Build

# Output: BUILD\Release\SNTIPCTL.DLL
```

**Required compiler flags** (must match the MBBS SDK):

- `/Zp8` — 8-byte struct alignment
- `/J` — `char` is unsigned by default
- `/MT` (Release) / `/MTd` (Debug) — static CRT

**Required libraries:** `wgserver_lib.lib`, `galgsbl_lib.lib`, `ws2_32.lib`.
`galtcpip_lib.lib` is intentionally not linked; `_tcpipinf` is resolved at
runtime via `GetProcAddress` to avoid an ordinal-mismatch load failure.

---

## Architecture

MBBS v10 modules are single- or minimal-file C implementations compiled as
32-bit DLLs. Key patterns used here:

- **Entry point:** `init__sntipctl()`, called by the BBS when the module loads.
- **Gateway pattern:** intercept menu navigation to enforce per-module policy.
- **Hook-based interception:** patch `hdlcon` and the `recv()` IAT to intercept
  socket data before the BBS processes it.
- **Configuration:** a Btrieve settings record (`SNTIPCTL.DAT`), created at
  runtime and editable live; display text and editor templates live in a
  message file (`SNTIPCTL.MSG` → `SNTIPCTL.MCV`).
- **Online config:** a Sysop menu (`/TOTALIP`) for view/modify/save/apply
  without a BBS restart, implemented natively with MBBS v10 SDK patterns.

### Features

1. **Global IP connection limits** — system-wide max connections per IP,
   configurable; disconnect with a message on violation.
2. **User profile IP recording** — write the current IP to a configurable user
   profile field on each login.
3. **Proxy protocol support and audit logging** — restore real caller IPs from
   a reverse proxy; daily, thread-safe log files under
   `TOTALIPCONTROL\` with timestamp, username, IP, and event.
4. **Live online configuration** — all settings editable while the BBS is
   running.

### Design priorities (in order)

1. Reliability
2. Maintainability
3. Stability
4. Sysop usability
5. Performance

---

## Directory Structure

```
/
├── SRC/              # All source code
│   ├── SNTIPCTL.C
│   ├── SNTIPCTL.H
│   ├── SNTIPCTL.RC          # Windows version resource
│   ├── SNTIPCTL.vcxproj
│   ├── SNTIPCTL_EXP.DEF
│   └── DIST/                # Module descriptor + message source
│       ├── SNTIPCTL.MDF
│       └── SNTIPCTL.MSG
├── DIST/<version>/   # Deployable files (DLL, MDF, MSG)
├── DOCS/ADR/         # Architecture Decision Records
├── TESTS/
├── TOOLS/
├── BUILD/            # Build output (not committed)
├── README.MD
├── TECHNICAL.MD
├── CHANGELOG.MD
├── BUILDING.MD
└── LICENSE
```

All deployable filenames must be **UPPERCASE** with **UPPERCASE extensions**
(e.g. `SNTIPCTL.DLL`).

---

## Code Comments

This project favours more comments than typical. Comments should:

- Explain intent and non-obvious behaviour.
- Describe MBBS-specific functionality.
- Be clear enough for a non-programmer to follow the purpose of a section.

---

## Documentation

Keep these accurate to the actual implementation — do not document speculative
features:

- `README.MD` — public overview, features, install, config, usage, license
- `TECHNICAL.MD` — architecture, APIs, data structures, workflows, file formats
- `CHANGELOG.MD` — added/changed/fixed/breaking per release
- `BUILDING.MD` — toolchain, SDK setup, build and packaging steps
- `DEVELOPMENT.md` — this file
- `DOCS/ADR/` — one ADR per significant design decision

---

## DLL Metadata

Every DLL ships with a Windows version resource (`SNTIPCTL.RC`) carrying:

- Product name
- Version number
- Copyright: `Copyright © Sysop Network`
- Company information

---

## Repository Hygiene

Never commit to the public repository:

- Credentials, API keys, tokens, or passwords
- Internal IP addresses, server names, or local filesystem paths
- Real user data or private test data
- Generated build artifacts (`BUILD/`, object files, compiled `.MCV` files)

Use `.example` config files in place of real config files.

---

## Release Checklist

Before tagging a release: the build passes, version numbers are updated,
`CHANGELOG.MD` is updated, `DIST` contents are verified, DLL metadata is
correct, installation is tested, and the repository is audited for any of the
prohibited content listed above.

---

## Attribution

Total IP Control is developed and maintained by Mark Laudenbach at Sysop
Network. Released under the MIT License.
