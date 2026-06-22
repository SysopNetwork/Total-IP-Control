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

The post-build step copies `SNTIPCTL.MDF` and the message **source**
(`SNTIPCTL.MSG`) next to the DLL in the output directory. The copied message
file still uses the bare-`[` source form and is **not** the deployable copy —
see *Message File Packaging* below.

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

`wgserver_lib.lib`, `galgsbl_lib.lib`, `ws2_32.lib`

`galtcpip_lib.lib` is intentionally **not** linked. `_tcpipinf` is resolved at
runtime via `GetProcAddress`, which avoids a DLL load failure from an ordinal
mismatch on production servers.

## Message File Packaging

The message **source** (`SRC\DIST\SNTIPCTL.MSG`) uses a bare `[` for every ANSI
sequence so it can be edited and previewed safely. The deployable message file
requires the real ANSI escape byte (`0x1B`) before each `[`, and CRLF line
endings.

When staging a release, convert the source into the deployable form rather than
copying it verbatim:

```powershell
$src = "SRC\DIST\SNTIPCTL.MSG"
$dst = "DIST\1.0.0\SNTIPCTL.MSG"
$raw = [System.IO.File]::ReadAllText($src, [System.Text.Encoding]::Latin1)
$raw = $raw -replace '(?<!\x1b)\[', "`e["            # bare [ -> ESC [ (skip any already-escaped)
$raw = $raw -replace '\r\n', "`n" -replace '\r', "`n" -replace '\n', "`r`n"   # normalize to CRLF
[System.IO.File]::WriteAllText($dst, $raw, [System.Text.Encoding]::Latin1)
```

Use the Latin1 encoding so `0x1B` and any high-bit bytes round-trip unchanged.
After conversion, the count of `0x1B` bytes should equal the count of `[` bytes,
with no doubled escapes.

## Release Packaging

Stage these files into `DIST\<version>\`. All filenames must be uppercase with
uppercase extensions.

| File | Source |
|---|---|
| `SNTIPCTL.DLL` | `BUILD\Release\SNTIPCTL.DLL` |
| `SNTIPCTL.MDF` | `BUILD\Release\SNTIPCTL.MDF` |
| `SNTIPCTL.MSG` | Converted from `SRC\DIST\SNTIPCTL.MSG` (see above) |

`SNTIPCTL.DAT` (the settings record) is created automatically by the module on
first run and is **not** shipped.

## Release Checklist

- [ ] Build passes with no errors or warnings in Release|Win32
- [ ] Version number updated in `SRC\SNTIPCTL.RC` (FileVersion, ProductVersion)
- [ ] `CHANGELOG.MD` entry written for the release version
- [ ] `DIST\<version>\` populated with DLL, MDF, and the **converted** MSG
- [ ] Deployed MSG verified: `0x1B` count equals `[` count, no doubled escapes
- [ ] DLL metadata verified (Explorer → Properties → Details)
- [ ] `README.MD` and `TECHNICAL.MD` accurate to this build
- [ ] Repository audited: no credentials, no local paths, and no internal-only
      files committed to any public repository

## BBS Installation

1. Copy the `DIST\<version>\` contents to the BBS installation directory.
2. **Run GCNF** to compile `SNTIPCTL.MSG` into `SNTIPCTL.MCV`. This is required
   on first install and after any change to the message file. If GCNF is not
   run, `/TOTALIP` cannot load its screens.
3. Add `SNTIPCTL` to `wgserv.cfg` **after** `GALTNTD`. Load order is required —
   proxy detection will not install if `SNTIPCTL` loads first.
4. If replacing `PROXCLIP` or `IPCTRL`, remove those module lines from
   `wgserv.cfg` first.
5. Restart the BBS and confirm the startup log shows `SNTIPCTL` initializing
   with the expected feature set.

---

## Credits

- **Developer:** Mark Laudenbach
- **R&D / Testing:** Gregory McGill

Maintained by Sysop Network. Released under the MIT License.
