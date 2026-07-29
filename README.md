# snitch

Seven small Windows watchdogs in one PowerShell file. **No install, no admin, no
dependencies, no network access.**

That last part is the point. Every feature below exists somewhere else in better
form — see [Prior art](#prior-art), which is honest about it. What doesn't exist is
**all of it in one script you can paste onto a machine you're not allowed to install
software on.** If you can install things and have admin, use the dedicated tools.

| Watcher | What it does |
|---|---|
| **mic/cam** | Which app is on your microphone or camera *right now*, as a toast, plus an unbounded log. |
| **usb** | Logs every device plugged in. Alerts loudly on new keyboards and storage — that's the BadUSB / O.MG cable shape. |
| **buskill** | Tether a USB stick to your wrist. Yank the laptop away, it locks. |
| **clipboard** | Spots private keys, AWS/GitHub/Slack/Google/API keys and JWTs on your clipboard, warns, then clears them. |
| **session** | Lock and unlock log. "Your laptop was unlocked at 3:14am." |
| **posture drift** | 11 read-only checks — firewall, Secure Boot, UAC, RDP, SMB1, Defender, patch age, lock screen, autologon, BitLocker. Alerts only when one **changes**. |
| **network diary** | Outbound connections by process. Toasts the first time a program ever phones home. |

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
  [2] usb devices ........ ON    39 devices
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
.\test-snitch.ps1         # 34 asserts
```

Press `5` in the console to arm BusKill — it waits for you to plug the tether in
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
| mic/cam | **Windows 11 itself** — Settings → Privacy & security → Microphone → *Recent activity* already lists apps with timestamps, 7 days back. `snitch` adds a real-time toast and retention past 7 days. That is the whole delta. |
| network diary | **[GlassWire](https://www.glasswire.com/)** has alerted on first network access for a decade. **[Portmaster](https://safing.io/)** is free, open source, and actually *blocks* at the kernel. `snitch` only narrates. |
| buskill | **[buskill-app](https://github.com/BusKill/buskill-app)** — free, open source, cross-platform, and pairs with real magnetic hardware. `snitch` just watches for the device to vanish. |
| posture | **[Pareto Security](https://paretosecurity.com/)** — free, open source, on Windows, more checks, nicer UI. It reports state; `snitch` reports *change*. |
| usb history | USBDeview, or Event Viewer, both free. |

What I can't find an equivalent of: the **clipboard secret guard**, and **posture drift**
as opposed to posture state. Those two are the genuinely new bits.

## Limits

Deliberate, in exchange for needing no admin rights and no drivers:

- **Polls every 2s** instead of subscribing to events. Registry enumeration costs ~30ms, so this is cheap, but a device plugged and pulled inside 2s is invisible.
- **No failed-login detection.** Events 4625/4776 live in the Security log, which needs admin. Lock/unlock is inferred from `LogonUI.exe` instead.
- **Clipboard is text-only,** and matched by regex rather than entropy. Copy a secret as an image and nothing happens.
- **Clipboard contents are never logged or stored** — only a hash, to notice when the clipboard changes. The log records the pattern name only.
- **BusKill only locks.** It does not wipe, unmount, or kill processes.
- **BitLocker status needs admin** — reported as `needs admin` rather than guessed. Without elevation the API takes 5.7s to fail, so it isn't even attempted.
- **Posture is checked every 5 minutes,** not every 2s. A pass costs ~1.9s (Defender and hotfix queries dominate) and posture does not move quickly. Signature and patch ages are bucketed to `ok`/`stale` so an ordinary passing day isn't reported as drift.
- **Baseline lives in** `%LOCALAPPDATA%\snitch\posture.json`. Delete it to re-baseline.
- **The network diary does no reverse DNS.** `GetHostEntry` took 4.5s to return *no PTR* on a live IP, so destinations are raw `ip:port`. There is no ASN lookup either — that would mean calling out to a third party about your own traffic.
- **Two tiers on purpose.** One browser touches dozens of rotating CDN IPs, so per-IP toasts would be unusable. Process names persist across restarts (`netdiary.txt`); destinations are per-session, so a restart doesn't re-report every live connection as new.
- **TCP only, established only.** UDP has no remote peer to record for most sockets — that's what a DNS log would be for.
- **Checked every 30s.** `Get-NetTCPConnection` is ~380ms. A connection opened and closed inside that window is missed.
