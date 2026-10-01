# abc_finder

abc_finder gui a tool for blue teamer 


**full "ABC" finder** — a GUI tool that detects common malware persistence/execution artifacts. "ABC" here means **A**utoruns, **B**rowser extensions/hijacks, and **C**omponents/services — i.e., a broad "find the suspicious stuff" scanner. It covers:

- **A** — Autorun locations: Run/RunOnce keys, Startup folder, Winlogon, IFEO, AppInit_DLLs, COM hijacks in HKCU\Software\Classes\CLSID
- **B** — Browser: Chrome/Edge/Firefox extensions and hijacked settings
- **C** — Services, Drivers, Scheduled Tasks, WMI event subscriptions

Each result is scored by a simple heuristic (unsigned binary, path outside Program Files, hidden/odd extension, recently modified, etc.).

## What it finds

### Category **A** — Autoruns / persistence
| Source | Why |
|---|---|
| HKCU/HKLM `…\Run`, `…\RunOnce` (+ Wow6432Node) | Classic auto-start |
| Startup folders (user + common) | Auto-launch on login |
| `Image File Execution Options\…\Debugger` | Debugger hijack |
| `AppInit_DLLs` | DLL injection into every GUI process |
| `Winlogon\Shell`, `Userinit`, `Taskman`, `VmApplet` | Login hijack |
| `HKCU\Software\Classes\CLSID\{…}\InprocServer32` | User-scoped COM hijack (no admin required) |

### Category **B** — Browser
- Chrome, Edge, Brave extensions (`%LOCALAPPDATA%\…\User Data\Default\Extensions\*`)
- Firefox extensions (`%APPDATA%\Mozilla\Firefox\Profiles\*\extensions\*`)

### Category **C** — Components / services / tasks
- **Services** whose binary path is unsigned, outside `System32`/`Program Files`, or in a user-writable folder
- **Scheduled Tasks** (`schtasks /query /fo CSV /v`) whose action path is suspicious
- **WMI event subscriptions** (`root\subscription\__EventFilter`) — fileless persistence

## Scoring heuristics (`ScorePath`)

| Trigger | Score |
|---|---|
| Referenced file missing | +30 |
| Unsigned binary | +25 |
| Script extension (`.vbs/.js/.jse/.wsf/.hta/.scr/.pif`) | +25 |
| User-writable path (`AppData`, `Temp`, `Downloads`, `Public`) | +20 |
| LOLBin (`powershell`, `mshta`, `rundll32`, `regsvr32`, `wscript`, `certutil`, `bitsadmin`) | +15 |
| Encoded/obfuscated command (`-enc`, `-EncodedCommand`, `FromBase64String`, `DownloadString`, `IEX(`) | +35 |
| IFEO debugger, AppInit_DLLs, HKCU COM hijack (baseline) | +20…+45 |

Rows are **sorted by score descending**, so the most suspicious stuff floats to the top.

## GUI features

- **Filter box** — live substring match on location/name/value/reason
- **Radio buttons: All / A / B / C** — category filter
- **Scan** — runs the full sweep (a few seconds)
- **Export CSV** — UTF-16 LE with BOM, opens a Save-As dialog
- **Copy Value** — copies the selected item's value field
- **Open Location** — opens Explorer at the folder containing the referenced EXE
- **Details pane** (monospace) — full info for the selected row
- **ListView columns**: Cat, Score, Location, Name, Value, Reason

## Build

```
cl /EHsc /W3 abc_finder.cpp /link user32.lib gdi32.lib comctl32.lib ^
    wintrust.lib crypt32.lib shell32.lib advapi32.lib ole32.lib
```

Or in Visual Studio: **Windows Desktop Application**, subsystem **Windows**, link the same libs.

## Notes / caveats

- **Run as Administrator** to see HKLM Run keys, services, and IFEO fully. Without elevation you'll still get HKCU, Startup, browsers, and the WMI check.
- The `IsSigned` check uses `WinVerifyTrust` with **`WTD_CACHE_ONLY_URL_RETRIEVAL`** to avoid network stalls. It returns *false* for Microsoft catalog-signed binaries on some systems — that's why `System32` paths are given a baseline of 0 and not auto-flagged.
- Scheduled Task parsing uses `schtasks /query /fo CSV /v` and a naive CSV splitter — good enough for finding the action path, but not a full task parser.
- WMI subscription detection shells out to `powershell.exe Get-WmiObject -Namespace root\subscription`. If PowerShell is blocked by policy you can replace it with a WMI COM query (like the AntivirusDetector class earlier) against `__EventFilter`.
- This is a **triage tool**, not a definitive malware scanner. Everything is a heuristic; verify before acting.
