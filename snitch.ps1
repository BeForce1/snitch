<#
  snitch.ps1 - five small Windows watchdogs in one tray app. No admin, no dependencies.

    mic/cam in use    who is listening/watching, right now, with history
    usb insert        every device plugged in, flags new keyboards (BadUSB)
    buskill           yank the tethered USB stick -> workstation locks
    clipboard guard   secrets on the clipboard get warned about and cleared
    session watch     lock / unlock log

  Usage:  .\snitch.ps1              run
          .\snitch.ps1 -Once        one poll cycle, then exit
          .\snitch.ps1 -ListUsb     print USB ids (to pick a BusKill tether)
#>
param([switch]$Once, [switch]$ListUsb, [switch]$Posture, [switch]$Net, [switch]$NoRun)

$Cfg = @{
    IntervalSec     = 2
    TetherUsbId     = ''   # BusKill: substring of a USB id from -ListUsb. Empty = off.
    ClipClearSec    = 30   # warn now, clear after this many seconds. 0 = warn only.
    PostureEverySec = 300  # posture drift is slow to check and slow to change
    NetEverySec     = 30   # Get-NetTCPConnection is ~380ms, don't do it every 2s
    WatchAv         = $true
    WatchUsb        = $true
    WatchClip       = $true
    WatchSession    = $true
    WatchPosture    = $true
    WatchNet        = $true
}

$script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole('Administrators')

$LogDir = Join-Path $env:LOCALAPPDATA 'snitch'
$LogFile = Join-Path $LogDir 'snitch.log'

$script:Quiet = $false                                        # aura.ps1 draws its own feed
$script:Recent = New-Object 'System.Collections.Generic.List[string]'

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# --- secrets worth panicking about -------------------------------------------
# ponytail: regex, not entropy scoring. Add patterns when something leaks past these.
$SecretPatterns = [ordered]@{
    'private key'  = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'AWS key'      = '\bAKIA[0-9A-Z]{16}\b'
    'GitHub token' = '\bgh[pousr]_[A-Za-z0-9]{30,}'
    'Slack token'  = '\bxox[baprs]-[A-Za-z0-9-]{10,}'
    'Google key'   = '\bAIza[0-9A-Za-z_-]{35}\b'
    'API key'      = '\bsk-[A-Za-z0-9_-]{20,}'
    'JWT'          = '\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
}

function Find-Secret([string]$Text) {
    if (-not $Text) { return $null }
    foreach ($name in $SecretPatterns.Keys) {
        if ($Text -match $SecretPatterns[$name]) { return $name }
    }
    $null
}

# --- readers (no state, no side effects) -------------------------------------

# Windows shows a tray dot for this and keeps no history. The registry does.
function Get-AvInUse {
    $out = @()
    foreach ($hive in 'HKCU:', 'HKLM:') {
        foreach ($cap in 'microphone', 'webcam') {
            $root = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
            if (-not (Test-Path $root)) { continue }
            foreach ($k in Get-ChildItem $root -Recurse) {
                $p = Get-ItemProperty $k.PSPath
                if ($p.PSObject.Properties.Name -notcontains 'LastUsedTimeStart') { continue }
                if ($p.LastUsedTimeStart -gt 0 -and $p.LastUsedTimeStop -eq 0) {
                    $out += "$cap|$($k.PSChildName -replace '#','\')"
                }
            }
        }
    }
    $out | Sort-Object -Unique
}

function Get-UsbSet {
    $map = @{}
    foreach ($vid in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB') {
        try { $insts = Get-ChildItem $vid.PSPath } catch { continue }
        foreach ($i in $insts) {
            $p = Get-ItemProperty $i.PSPath
            $desc = $p.FriendlyName
            if (-not $desc) { $desc = $p.DeviceDesc }
            if ($desc) { $desc = ($desc -split ';')[-1] }
            $map["$($vid.PSChildName)\$($i.PSChildName)"] = [pscustomobject]@{
                Desc = $desc; Service = $p.Service
            }
        }
    }
    $map
}

# ponytail: LogonUI.exe present == lock screen up. Cheap poll, no event plumbing.
function Test-Locked { [bool](Get-Process logonui -ErrorAction Ignore) }

function Get-RegVal([string]$Path, [string]$Name) {
    # -ErrorAction Stop: a missing value is a *non-terminating* error, which
    # try/catch would otherwise let leak straight to the console.
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# Registry over cmdlets wherever possible: Get-NetFirewallProfile is 1.4s, the
# registry is 47ms. Ages are bucketed to ok/stale so a passing day isn't "drift".
function Get-Posture {
    $p = [ordered]@{}

    $fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    $p['firewall'] = ((Get-ChildItem $fw | Where-Object { $_.PSChildName -like '*Profile' } |
        Sort-Object PSChildName | ForEach-Object {
            '{0}={1}' -f ($_.PSChildName -replace 'Profile$', ''), (Get-RegVal $_.PSPath 'EnableFirewall')
        }) -join ' ')

    $p['secure_boot'] = '' + (Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')
    $p['rdp_open']    = '' + ((Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
    $p['uac']         = '' + (Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
    $p['autologon']   = '' + ((Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon') -eq 1)
    $p['smb1']        = '' + ((Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -eq 1)

    $secure = Get-RegVal 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
    $mins = Get-RegVal 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
    $p['lock_screen'] = 'secure={0} timeout={1}' -f
        $(if ($secure -eq '1') { 'yes' } else { 'no' }),
        $(if ($mins) { '{0}m' -f [int]([int]$mins / 60) } else { 'unset' })

    try {
        $d = Get-MpComputerStatus
        $p['defender_rtp'] = '' + $d.RealTimeProtectionEnabled
        $p['defender_sig'] = if ($d.AntivirusSignatureAge -le 7) { 'ok' } else { "stale ($($d.AntivirusSignatureAge)d)" }
    }
    catch { $p['defender_rtp'] = 'unknown'; $p['defender_sig'] = 'unknown' }

    try {
        $days = [int]((Get-Date) - (Get-HotFix | Sort-Object InstalledOn -Descending)[0].InstalledOn).TotalDays
        $p['last_patch'] = if ($days -le 45) { 'ok' } else { 'stale ({0}d)' -f $days }
    }
    catch { $p['last_patch'] = 'unknown' }

    # ponytail: BitLocker needs admin and burns 5.7s failing without it. Don't ask.
    if (-not $script:IsAdmin) { $p['bitlocker'] = 'needs admin' }
    else {
        try { $p['bitlocker'] = '' + (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus }
        catch { $p['bitlocker'] = 'unknown' }
    }

    $p
}

# Loopback, RFC1918, link-local. Talking to your own router is not phoning home.
$PrivateNet = '^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1$|fe80:|fc|fd)'

# ponytail: no rDNS. GetHostEntry took 4.5s to return "no PTR" on a live IP.
function Get-NetOut {
    $names = @{}
    Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
    $out = @{}
    foreach ($c in Get-NetTCPConnection -State Established) {
        if ($c.RemoteAddress -match $PrivateNet) { continue }
        $n = $names[[int]$c.OwningProcess]
        if (-not $n) { $n = "pid$($c.OwningProcess)" }
        $out['{0}|{1}:{2}' -f $n, $c.RemoteAddress, $c.RemotePort] = $n
    }
    $out
}

# Two tiers, because one browser hits dozens of IPs: a NEW PROCESS talking out is
# rare and worth a toast, a new destination is just a diary line.
function Test-NetDiary {
    # ponytail: plain text, one name per line. PS 5.1's ConvertFrom-Json emits an
    # array as ONE object without enumerating, which silently collapsed every name
    # into a single space-joined key. A flat list never needed JSON.
    $file = Join-Path $LogDir 'netdiary.txt'

    # Two independent baselines:
    #   procs persist across runs, so a genuinely new program still alerts on a fresh start
    #   pairs are per-session, so a restart doesn't re-report every live connection as new
    $firstPoll = $false
    if ($null -eq $script:SeenProcs) {
        $script:SeenProcs = @{}
        if (Test-Path $file) {
            foreach ($p in @(Get-Content $file)) { if ($p) { $script:SeenProcs[$p] = $true } }
        }
        $script:SeenPairs = @{}
        $script:NetVirgin = ($script:SeenProcs.Count -eq 0)
        $firstPoll = $true
    }

    $now = Get-NetOut
    $fresh = @()
    foreach ($k in $now.Keys) {
        if (-not $script:SeenPairs.ContainsKey($k)) {
            $script:SeenPairs[$k] = $true
            if (-not $firstPoll) { Write-Snitch 'NET' "new dest: $k" }
        }
        $n = $now[$k]
        if (-not $script:SeenProcs.ContainsKey($n)) { $script:SeenProcs[$n] = $true; $fresh += $n }
    }

    if ($script:NetVirgin) {
        Write-Snitch 'NET' "diary baselined ($($script:SeenProcs.Count) processes, $($now.Count) destinations)"
        $script:NetVirgin = $false
    }
    else {
        foreach ($n in ($fresh | Sort-Object -Unique)) {
            Alert 'NET' 'New program phoning home' "$n made its first outbound connection"
        }
    }
    # Only process names persist. Pairs would grow without bound; snitch.log is the diary.
    @($script:SeenProcs.Keys) | Sort-Object | Set-Content $file -Encoding utf8
}

function Compare-Posture($Old, $New) {
    $known = $Old.PSObject.Properties.Name
    $out = @()
    foreach ($k in $New.Keys) {
        if ($known -notcontains $k) { continue }          # newly added check, not drift
        if ("$($Old.$k)" -ne "$($New[$k])") { $out += "$k : $($Old.$k) -> $($New[$k])" }
    }
    $out
}

function Test-PostureDrift {
    $now = Get-Posture
    $file = Join-Path $LogDir 'posture.json'
    if (Test-Path $file) {
        foreach ($d in Compare-Posture (Get-Content $file -Raw | ConvertFrom-Json) $now) {
            Alert 'DRIFT' 'Security posture changed' $d
        }
    }
    else { Write-Snitch 'DRIFT' "posture baselined ($($now.Count) checks)" }
    $script:PostureNow = $now      # not $script:Posture - that aliases the -Posture switch
    ($now | ConvertTo-Json) | Set-Content $file -Encoding utf8
}

# --- output -----------------------------------------------------------------
function Write-Snitch([string]$Tag, [string]$Msg) {
    $line = '{0}  {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Tag, $Msg
    if (-not $script:Quiet) { Write-Host $line }
    $script:Recent.Add($line)
    while ($script:Recent.Count -gt 12) { $script:Recent.RemoveAt(0) }
    Add-Content -Path $LogFile -Value $line -Encoding utf8
}

function Start-Tray {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $script:Tray = New-Object System.Windows.Forms.NotifyIcon
    $script:Tray.Icon = [System.Drawing.SystemIcons]::Shield
    $script:Tray.Text = 'snitch'
    $script:Tray.Visible = $true
}

function Notify([string]$Title, [string]$Msg, [string]$Icon = 'Warning') {
    if ($script:Tray) {
        $script:Tray.ShowBalloonTip(5000, $Title, $Msg, [System.Windows.Forms.ToolTipIcon]::$Icon)
    }
}

function Alert([string]$Tag, [string]$Title, [string]$Msg) {
    Write-Snitch $Tag $Msg
    Notify $Title $Msg
}

# --- one poll cycle ---------------------------------------------------------
function Invoke-Poll {
    if ($Cfg.WatchAv) {
        $now = @(Get-AvInUse)
        if ($null -ne $script:PrevAv) {
            foreach ($x in $now  | Where-Object { $script:PrevAv -notcontains $_ }) {
                $p = $x -split '\|', 2
                Alert 'AV' "$($p[0]) ON" "$($p[0]) in use: $(Split-Path $p[1] -Leaf)"
            }
            foreach ($x in $script:PrevAv | Where-Object { $now -notcontains $_ }) {
                $p = $x -split '\|', 2
                Write-Snitch 'AV' "$($p[0]) released: $(Split-Path $p[1] -Leaf)"
            }
        }
        $script:PrevAv = $now
    }

    if ($Cfg.WatchUsb -or $Cfg.TetherUsbId) {
        $now = Get-UsbSet
        if ($null -ne $script:PrevUsb) {
            foreach ($id in $now.Keys | Where-Object { -not $script:PrevUsb.ContainsKey($_) }) {
                $d = $now[$id]
                $suspect = $d.Service -in 'HidUsb', 'kbdclass', 'kbdhid', 'USBSTOR', 'disk'
                $what = "plugged in: $($d.Desc) [$($d.Service)]"
                if ($suspect) { Alert 'USB' 'New USB input/storage device' $what }
                else { Write-Snitch 'USB' $what }
            }
            foreach ($id in $script:PrevUsb.Keys | Where-Object { -not $now.ContainsKey($_) }) {
                Write-Snitch 'USB' "removed: $($script:PrevUsb[$id].Desc)"
                if ($Cfg.TetherUsbId -and $id -like "*$($Cfg.TetherUsbId)*") {
                    Write-Snitch 'KILL' "tether pulled ($id) - locking"
                    rundll32.exe 'user32.dll,LockWorkStation'
                }
            }
        }
        $script:PrevUsb = $now
    }

    if ($Cfg.WatchClip) {
        $text = Get-Clipboard -Raw
        $hash = if ($text) { $text.GetHashCode() } else { 0 }
        # ponytail: only the hash is kept. Never log or store clipboard contents.
        if ($script:ClipFlag -and $script:ClipFlag.Hash -ne $hash) { $script:ClipFlag = $null }
        if (-not $script:ClipFlag) {
            $hit = Find-Secret $text
            if ($hit) {
                $script:ClipFlag = @{ Hash = $hash; At = Get-Date; Name = $hit }
                $msg = if ($Cfg.ClipClearSec) { "$hit on clipboard - clearing in $($Cfg.ClipClearSec)s" }
                       else { "$hit on clipboard" }
                Alert 'CLIP' 'Secret on clipboard' $msg
            }
        }
        elseif ($Cfg.ClipClearSec -and ((Get-Date) - $script:ClipFlag.At).TotalSeconds -ge $Cfg.ClipClearSec) {
            Set-Clipboard -Value ' '   # ponytail: a space, not Clipboard::Clear - no STA worries
            Write-Snitch 'CLIP' "cleared ($($script:ClipFlag.Name))"
            $script:ClipFlag = $null
        }
    }

    if ($Cfg.WatchPosture -and ((-not $script:PostureNext) -or (Get-Date) -ge $script:PostureNext)) {
        # ponytail: ~1.9s, so it blocks the loop briefly every PostureEverySec.
        $script:PostureNext = (Get-Date).AddSeconds($Cfg.PostureEverySec)
        Test-PostureDrift
    }

    if ($Cfg.WatchNet -and ((-not $script:NetNext) -or (Get-Date) -ge $script:NetNext)) {
        $script:NetNext = (Get-Date).AddSeconds($Cfg.NetEverySec)
        Test-NetDiary
    }

    if ($Cfg.WatchSession) {
        $locked = Test-Locked
        if ($null -ne $script:PrevLocked -and $locked -ne $script:PrevLocked) {
            if ($locked) { Write-Snitch 'LOCK' 'locked' }
            else { Alert 'LOCK' 'Session unlocked' "unlocked as $env:USERNAME" }
        }
        $script:PrevLocked = $locked
    }
}

# --- entry ------------------------------------------------------------------
function Main {
    if ($Posture) {
        (Get-Posture).GetEnumerator() | ForEach-Object { '{0,-14} {1}' -f $_.Key, $_.Value }
        return
    }

    if ($Net) {
        (Get-NetOut).Keys | Sort-Object | ForEach-Object { '  ' + $_ }
        return
    }

    if ($ListUsb) {
        (Get-UsbSet).GetEnumerator() | Sort-Object Key | ForEach-Object {
            '{0,-46} {1}' -f $_.Key, $_.Value.Desc
        }
        return
    }

    Start-Tray

    Invoke-Poll                      # first pass baselines silently
    Write-Snitch 'BOOT' "watching (log: $LogFile). Ctrl+C to stop."
    if ($Cfg.TetherUsbId) { Write-Snitch 'BOOT' "buskill armed on *$($Cfg.TetherUsbId)*" }

    if ($Once) { Invoke-Poll; $script:Tray.Dispose(); return }

    try {
        while ($true) {
            Invoke-Poll
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds $Cfg.IntervalSec
        }
    }
    finally { $script:Tray.Dispose() }
}

if (-not $NoRun) { Main }
