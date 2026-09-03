# snitch

Seven small Windows watchdogs in one PowerShell file. **No install, no admin, no
dependencies, no network access.**

That last part is the point. Every feature below exists somewhere else in better
form, listed under [Prior art](#prior-art). What doesn't exist is
**all of it in one script you can paste onto a machine you're not allowed to install
software on.** If you can install things and have admin, use the dedicated tools.

| Watcher | What it does |
|---|---|
| **mic/cam** | Which app is on your microphone or camera *right now*, as a toast, plus an unbounded log. |
| **usb** | Logs every device plugged in *and pulled out*. Alerts loudly on new keyboards and storage: that's the BadUSB / O.MG cable shape. |
| **buskill** | Tether a USB stick to your wrist. Yank the laptop away, it locks. |
| **clipboard** | Spots private keys, AWS/GitHub/Slack/Google/API keys and JWTs on your clipboard, warns, then clears them. |
| **session** | Lock and unlock log. "Your laptop was unlocked at 3:14am." |
| **posture drift** | 11 read-only checks: firewall, Secure Boot, UAC, RDP, SMB1, Defender, patch age, lock screen, autologon, BitLocker. Alerts only when one **changes**. |
| **network diary** | Outbound connections by process. Toasts the first time a program ever phones home. |

## Install

No installer, no admin, nothing to compile. PowerShell 5.1 ships with Windows:

```powershell
git clone https://github.com/BeForce1/snitch && cd snitch
Get-ChildItem *.ps1 | Unblock-File    # clears the downloaded-from-internet flag
.\aura.ps1
```

If script execution is blocked: `powershell -ExecutionPolicy Bypass -File .\aura.ps1`

## Run

```
  █████╗ ██╗   ██╗██████╗  █████╗
 ██╔══██╗██║   ██║██╔══██╗██╔══██╗
 ███████║██║   ██║██████╔╝███████║
 ██╔══██║██║   ██║██╔══██╗██╔══██║
 ██║  ██║╚██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
 ══════════════════════════════════
  w a t c h d o g      mic cam usb clip lock

  [1] mic / cam .......... ON    LIVE: microphone
  [2] usb devices ........ ON    5 attached
  [3] clipboard .......... ON    clear after 30s
  [4] session lock ....... ON    unlocked
  [5] buskill ............ OFF   no tether armed
  [6] posture drift ...... ON    11 checks, WARN: rdp lockscreen
  [7] network diary ...... ON    6 procs, 13 dests

  [a] all on   [z] all off   [l] log   [q] quit
  ------------------------------------------------------------------
  12:22:05  CLIP  AWS key on clipboard - clearing in 30s
  12:23:14  LOCK  locked
  12:52:24  DRIFT rdp_open : False -> True
  13:03:23  NET   chrome made its first outbound connection
```

```powershell
.\aura.ps1                # the console above - toggle watchers by hand
.\aura.ps1 -Draw          # render one frame and exit

.\snitch.ps1              # headless, all watchers on
.\snitch.ps1 -Once        # one poll cycle, then exit
.\snitch.ps1 -ListUsb     # print USB ids
.\snitch.ps1 -Posture     # print all 11 posture checks and exit
.\snitch.ps1 -Net         # print every current outbound connection by process
.\test-snitch.ps1         # 40 asserts
```

Press `5` in the console to arm BusKill. It waits for you to plug the tether in
and records whatever appears. No config editing.

Log lands in `%LOCALAPPDATA%\snitch\snitch.log`:

```
2026-07-27 12:19:32  CLIP  AWS key on clipboard - clearing in 30s
2026-07-27 12:19:34  CLIP  cleared (AWS key)
2026-07-27 14:02:11  AV    microphone in use: zoom.exe
2026-07-27 14:44:03  USB   plugged in: USB Input Device [HidUsb]
```

## Config

Top of `snitch.ps1`:

```powershell
$Cfg = @{
    IntervalSec  = 2
    TetherUsbId  = ''    # BusKill: substring of an id from -ListUsb. Empty = off.
    ClipClearSec = 30    # warn now, clear after N seconds. 0 = warn only.
    ...
}
```

To arm BusKill: `.\snitch.ps1 -ListUsb`, find your stick, paste enough of its id to be
unique into `TetherUsbId`. Pull it out, the workstation locks.

## Autostart

```powershell
$s = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PWD\snitch.ps1`""
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' snitch $s
```

## Prior art

Every one of these has a better-resourced rival. Use them if you can install software:

| This watcher | Do it properly with |
|---|---|
| mic/cam | **Windows 11 itself**: Settings → Privacy & security → Microphone → *Recent activity* already lists apps with timestamps, 7 days back. `snitch` adds a real-time toast and retention past 7 days. That is the whole delta. |
| network diary | **[GlassWire](https://www.glasswire.com/)** (paid) has alerted on first network access for a decade. **[Portmaster](https://safing.io/)** is free, open source, and actually *blocks* at the kernel. `snitch` only narrates. |
| buskill | **[buskill-app](https://github.com/BusKill/buskill-app)** is free, open source, cross-platform, and pairs with real magnetic hardware. `snitch` just watches for the device to vanish. |
| posture | **[Pareto Security](https://paretosecurity.com/)**: free, open source, on Windows, more checks, nicer UI. It reports state; `snitch` reports *change*. |
| usb history | USBDeview, or Event Viewer, both free. |

What I can't find an equivalent of: the **clipboard secret guard**, and **posture drift**
as opposed to posture state. Those two are the genuinely new bits.

## Limits

Deliberate, in exchange for needing no admin rights and no drivers:

**USB**
- **Presence comes from `Win32_PnPEntity`, not `Enum\USB`.** That registry key records every device ever seen and survives removal, so diffing it never detects an unplug. One machine listed 17 devnodes where 5 were attached. Being right costs ~700ms against ~15ms.
- **Device changes jump the 2s queue.** A `Win32_DeviceChangeEvent` subscription (extrinsic, so genuinely pushed, and it registers without admin) cuts the wait in 100ms slices. Measured on a real unplug: the indication landed **1,689ms** before the poll saw it.
- **The indication only decides when to look.** The diff stays the only authority, so a machine that delivers none behaves exactly as before. The tests assert this.
- **An empty or failed enumeration is never read as "everything was unplugged".** With a tether armed that would lock the workstation over a transient WMI hiccup.
- **A poll cycle costs 80-140ms**, under 7% of a core. A device plugged *and* pulled inside one cycle with no indication is still missed.
- **BusKill only locks.** It does not wipe, unmount, or kill processes.

**Posture**
- **Checked every 5 minutes.** Signature and patch ages bucket to `ok`/`stale`, so an ordinary passing day isn't reported as drift.
- **`Get-HotFix` is cached for 12h.** It alone was ~1.5s of a ~1.9s pass. Now 2,208ms on the first pass, then 108-145ms. The *date* is cached, not the bucket, so `ok` still flips to `stale` on the right day. (`Get-MpComputerStatus`, long assumed to be the other expensive one, measured ~100ms.)
- **BitLocker needs admin.** Reported as `needs admin` rather than guessed; the API takes 5.7s to fail without elevation, so it isn't attempted.
- **Baseline lives in** `%LOCALAPPDATA%\snitch\posture.json`. Delete it to re-baseline.

**Network**
- **Checked every 30s.** `Get-NetTCPConnection` measured ~190ms warm, ~700ms on the first call. A connection opened and closed inside that window is missed.
- **No reverse DNS.** `GetHostEntry` took 4.5s to return *no PTR* on a live IP. No ASN lookup either. That would mean telling a third party about your own traffic.
- **Two tiers.** A new *process* phoning home toasts; a new destination is only a log line, because one browser touches dozens of rotating CDN IPs.
- **TCP only, established only.**

**Other**
- **No failed-login detection.** Events 4625/4776 need admin. Lock/unlock is inferred from `LogonUI.exe`.
- **Clipboard is text-only** and regex-matched rather than entropy-scored. Contents are never logged or stored, only a hash to notice when it changes.
- **`snitch.log` is never rotated.** That is the point, it outlives the 7 days Windows keeps. But nothing trims it either.

## License

MIT. See [LICENSE](LICENSE).
