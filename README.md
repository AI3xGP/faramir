# Faramir

> *"The younger brother, wiser and swifter."*

(VibeCoding) Faramir is the evolution of [Boromir](https://github.com/skyg4mb/Persistence_Boromir) — a forensic tool designed to extract and timeline Windows persistence artifacts from offline registry hives. Rewritten from the ground up in **Rust** at the request of [@jupyterj0nes](https://github.com/jupyterj0nes), Faramir inherits all of Boromir's detection power while delivering native-speed performance, a single self-contained binary, and memory-safe parsing of registry hives with no runtime dependencies.

If Boromir gave analysts a way to hunt persistence, Faramir gives them a faster, sharper blade.

---

## Why Rust?

| | Boromir (Python) | Faramir (Rust) |
|---|---|---|
| Runtime required | Python 3 + pip deps | None — single binary |
| Performance | Moderate | Native speed |
| Memory safety | Runtime errors possible | Guaranteed at compile time |
| Deployment | Script + virtualenv | Drop and run |

---

## What It Does

Faramir scans a mounted Windows disk image and parses raw registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, etc.) to detect known persistence techniques. Results are written to a CSV file, ready to be loaded into a timeline or SIEM.

---

## Detected Persistence Techniques

### Registry Run Keys (MITRE T1547.001)
- `get-run` — HKLM/HKCU Run key
- `get-run-once` — RunOnce key
- `get-run-ex` — RunEx key
- `get-run-once-ex` — RunOnceEx key

### DLL Injection & Hijacking
- `get-app-init-dlls` — AppInit_DLLs (MITRE T1546.010)
- `get-service-dlls` — ServiceDll hijacking via registry Parameters subkey (Hexacorn N.4)
- `get-gp-extension-dlls` — Group Policy Extension DLLs
- `get-chm-helper-dll` — CHM Helper DLL (Hexacorn N.77)
- `get-hh-ctrl-hijacking` — hhctrl.ocx COM hijack (Hexacorn N.77)
- `get-com-hijacking` — HKCU COM object hijacking via `Software\Classes\CLSID\*\InprocServer32` (MITRE T1546.015)
- `get-nldp-dll-override-path` — Natural Language Development Platform DLL override (Hexacorn N.98)

### Winlogon & Authentication
- `get-winlogon-userinit` — Winlogon Userinit property (MITRE T1547.004)
- `get-winlogon-shell` — Winlogon Shell property (MITRE T1547.004)
- `get-winlogon-mp-notify` — Winlogon MPNotify property
- `get-lsa-packages` — LSA Authentication, Security and Notification Packages (MITRE T1547.002)

### Boot & Pre-OS
- `get-boot-execute` — Session Manager BootExecute (MITRE T1542.003)

### Process & Debugger Hooks
- `get-image-file-execution-options` — IFEO Debugger value (MITRE T1546.012)
- `get-aedebug` — AeDebug custom debugger (Hexacorn N.4)
- `get-wer-fault-hangs` — WerFault Hangs debugger (Hexacorn N.116)
- `get-silent-process-exit` — SilentProcessExit MonitorProcess (Hexacorn N.116)

### Autorun & Startup
- `get-cmd-autorun` — Command Processor AutoRun key
- `get-explorer-load` — Explorer Load property
- `get-startup-programs` — Files in user Startup folders (MITRE T1547.001)
- `get-active-setup` — Active Setup StubPath (Hexacorn N.54)
- `get-screensaver` — SCRNSAVE.EXE in HKCU Control Panel\Desktop (MITRE T1546.002)

### App Paths & Certificates
- `get-app-cert-dlls` — AppCertDlls (MITRE T1546.009)
- `get-app-paths` — App Paths subkeys (Hexacorn N.3)

### Scheduled Tasks & Services
- `get-scheduled-tasks` — Registry TaskCache + XML files from `Windows\System32\Tasks\` (MITRE T1053.005)
- `get-windows-services` — Windows Services via ControlSet (MITRE T1543.003)

### Logon Scripts
- `get-user-init-mpr-script` — UserInitMprLogonScript environment variable (MITRE T1037.001)
- `get-terminal-profile-start-on-user-login` — Windows Terminal profiles with `startOnUserLogin: true`

---

## Installation

### From source

Requires [Rust](https://rustup.rs/) (stable).

```bash
git clone https://github.com/AI3xGP/faramir.git
cd faramir
cargo build --release
```

The binary will be at `target/release/faramir`.

---

## Usage

```
faramir [OPTIONS] <ACTION>
```

| Option | Description |
|---|---|
| `--source-evidence <PATH>` | Path where the Windows disk image is mounted |
| `--csv-output <PATH>` | Output CSV file path prefix |
| `<ACTION>` | Technique to run (e.g. `get-run`, `get-scheduled-tasks`, `all`) |

### Examples

Run all detections and write results to CSV:
```bash
faramir --source-evidence /mnt/windows --csv-output ./results all
```

Check only Run keys:
```bash
faramir --source-evidence /mnt/windows get-run
```

---

## Output

Results are written to a CSV file with the following columns:

| Column | Description |
|---|---|
| `timestamp` | Last write time of the registry key |
| `technique` | Name of the detection technique |
| `classification` | MITRE ATT&CK ID or Hexacorn reference |
| `path` | Full path to the hive file |
| `value` | Suspicious value found |
| `access_gained` | Likely access level obtained |
| `reference` | External reference link |

---

## Credits

- Original [Boromir](https://github.com/skyg4mb/Persistence_Boromir) concept and Rust rewrite by [@AI3xGP](https://github.com/AI3xGP) (formerly @skyg4mb)
- Co-author of Boromir: [@jupyterj0nes](https://github.com/jupyterj0nes)
- Inspired by [Persistence Sniper](https://github.com/last-byte/PersistenceSniper)

---

## License

GNU General Public License v3.0
