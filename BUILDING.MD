# Building Total IP Control

## Requirements

- **Visual Studio 2022** (v143 toolset, Win32 workload)
- **Windows SDK 10.0**
- **The Major BBS v10 SDK** — a proprietary SDK that is **not** included in this
  repository. You must obtain it separately and tell the build where it lives.

### Pointing the build at the SDK

The project resolves all SDK include and library paths from a single
`MBBS_SDK_DIR` variable. Set it once, either way:

- **Environment variable (recommended):** set `MBBS_SDK_DIR` to the SDK root, e.g.

  ```powershell
  setx MBBS_SDK_DIR "C:\path\to\MBBS 10 SDK"
  ```

  Open a new shell (or restart Visual Studio) so the variable is picked up.

- **Or edit the default** in `SRC\SNTIPCTL.vcxproj` (the `MBBS_SDK_DIR`
  property under `UserMacros`), which defaults to `..\..\MBBS 10 SDK` relative
  to the project directory.

The SDK root is the folder containing `inc\` and `lib\`.

## Build

### Command line (Release)

```powershell
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" `
    SNTIPCTL.sln /p:Configuration=Release /p:Platform=Win32 /t:Build
```

### Visual Studio

Open `SNTIPCTL.sln`, set Configuration to **Release** and Platform to
**Win32**, then build.

## Build Output

| Configuration | Output directory |
|---|---|
| Release | `BUILD\Release\` |
| Debug | `BUILD\Debug\` |

The post-build step copies `SNTIPCTL.MSG` and `SNTIPCTL.MDF` next to the DLL,
so `BUILD\Release\` holds a matched, deployable set.

## Compiler Flags

These are set in the vcxproj and must not be changed:

| Flag | Purpose |
|---|---|
| `/Zp8` | 8-byte struct alignment (required by the BBS SDK) |
| `/J` | `char` is unsigned by default (required by the BBS SDK) |
| `/MT` | Static CRT linkage (Release) |
| `/MTd` | Static CRT linkage (Debug) |

## Preprocessor Definitions

```
WIN32;GCWINNT;GCMVC;BBSVER=1000;USE_DEF_FILE;_CRT_SECURE_NO_WARNINGS;_CRT_SECURE_NO_DEPRECATE;_CRT_NONSTDC_NO_DEPRECATE;_WINSOCK_DEPRECATED_NO_WARNINGS;__BUILDV10MODULE
```

## Required Libraries

`wgserver_lib.lib`, `galgsbl_lib.lib`, `ws2_32.lib`, `winhttp.lib`

`winhttp.lib` (a standard Windows SDK library) provides the HTTP client used by
the GeoIP location feature. `galtcpip_lib.lib` is intentionally **not** linked.
`_tcpipinf` is resolved at runtime via `GetProcAddress`, which avoids a DLL load
failure from an ordinal mismatch on production servers.

## Message File

`SRC\SNTIPCTL.MSG` is the deployable file itself: binary CP437 with real ESC
bytes (`0x1B`) before every ANSI `[`, `0x01` text-variable markers, and CRLF line
endings. There is no conversion step. Edit it with a binary-safe tool (or a
script that reads and writes bytes) and keep it in the repository as the source
of truth — the BBS's own message editor strips trailing spaces from prompts.
`.gitattributes` marks `*.MSG` binary so git never converts its line endings.

All messages are in one `LEVEL6` block, and code finds a message by its position
in the file (`SNTIPCTL.H`). **Append** a new message at the end; inserting one
renumbers every message after it. Dynamic values are named text variables
(`N!SNT...`), never `printf`-style arguments, and a literal `%` must be written
`%%`.

## Tests

```
TESTS\RUNTESTS.CMD
```

Builds and runs `BUILD\TESTS\EDTEST.EXE`: the `/TIP` settings table and its
value logic, compiled straight out of `SRC\SNTIPCTL.C`, checked against every
kind of setting (yes/no and lists stored as `GBOOL` or `INT`, numbers, key names,
text, IPv4 and IPv6 ranges). No BBS is needed. Exit code 0 = all passed.

## Release Packaging

Stage these files into `DIST\<version>\`. All filenames must be uppercase with
uppercase extensions.

| File | Source |
|---|---|
| `SNTIPCTL.DLL` | `BUILD\Release\SNTIPCTL.DLL` |
| `SNTIPCTL.MDF` | `BUILD\Release\SNTIPCTL.MDF` |
| `SNTIPCTL.MSG` | `BUILD\Release\SNTIPCTL.MSG` (a copy of `SRC\SNTIPCTL.MSG`) |
| `SNTIPCTL.RLN` | Release notes / manual for this version (the MDF's online manual) |

`SNTIPCTL.DAT` (the settings record) is created automatically by the module on
first run and is **not** shipped.

## Where the Version Number Lives

`SRC\SNTVER.H` is the only place the version lives. The C code
(`SNTIPCTL_VERSION`: the Audit Trail line at boot, the debug trace's first line,
and `N!SNTVER` on the `/TIP` screens) and `SRC\SNTIPCTL.RC` (the DLL's
FileVersion/ProductVersion in Explorer) both take it from there, so they cannot
disagree.

| Define | Example | Used for |
|---|---|---|
| `SNTVER_STR` | `2.0.0` | Shown to sysops |
| `SNTVER_DOTTED` | `2.0.0.0` | Windows FileVersion string |
| `SNTVER_NUMS` | `2,0,0,0` | Windows FILEVERSION numbers |

A version names exactly one binary: bump it for every build that leaves this
machine, never rebuild under a number already committed or shared.

**Do not type a version number into `SNTIPCTL.MSG`.** Use `N!SNTVER`; a typed
version goes stale with the first DLL-only build.

## Release Checklist

- [ ] Build passes with no errors or warnings in Release|Win32
- [ ] Version bumped in `SRC\SNTVER.H` — never reuse a version already
      committed or shared, even for a rebuild
- [ ] `TESTS\RUNTESTS.CMD` passes
- [ ] `/TIP` header verified against the new build (it should follow the DLL
      automatically via `N!SNTVER`; if it shows a literal version, someone typed
      one into the `.MSG`)
- [ ] `CHANGELOG.MD` entry written for the release version
- [ ] `DIST\<version>\` populated with DLL, MDF, MSG and RLN
- [ ] If the MSG changed, the RLN says so (installing it resets any text the
      Sysop customised in the BBS's message editor)
- [ ] DLL metadata verified (Explorer → Properties → Details)
- [ ] `README.MD` and `TECHNICAL.MD` accurate to this build
- [ ] Repository audited: no credentials, no local paths, and no internal-only
      files committed to any public repository

## BBS Installation

1. Copy the `DIST\<version>\` contents to the BBS installation directory.
2. If replacing `PROXCLIP` or `IPCTRL`, remove those module lines from
   `wgserv.cfg`.
3. `SNTIPCTL` must load **after** `GALTNTD` in `wgserv.cfg` (it chains `hdlcon`),
   and — for SSH PROXY header support — **after** the SSH Server module `SNSSH`,
   whose `ssh.dll` it patches. The default alphabetical order satisfies both.
4. Restart the BBS and confirm the startup log shows `SNTIPCTL` initializing
   with the expected feature set.

---

## Credits

- **Developer:** Mark Laudenbach
- **R&D / Testing:** Gregory McGill

Maintained by Sysop Network. Released under the MIT License.
