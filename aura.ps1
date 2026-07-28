<#
  aura.ps1 - console for snitch. Toggle watchers by hand, watch events land.
  ponytail: 7-bit ASCII only. Block-drawing chars mojibake in legacy conhost.
#>
param([switch]$Draw)          # -Draw: render one frame and exit

. (Join-Path $PSScriptRoot 'snitch.ps1') -NoRun

$script:Quiet = $true          # we draw the feed ourselves
$script:Dirty = $true

$Rows = @(
    @{ K = '1'; Name = 'mic / cam';    Flag = 'WatchAv' }
    @{ K = '2'; Name = 'usb devices';  Flag = 'WatchUsb' }
    @{ K = '3'; Name = 'clipboard';    Flag = 'WatchClip' }
    @{ K = '4'; Name = 'session lock'; Flag = 'WatchSession' }
    @{ K = '5'; Name = 'buskill';      Flag = 'Tether' }
    @{ K = '6'; Name = 'posture drift'; Flag = 'WatchPosture' }
    @{ K = '7'; Name = 'network diary'; Flag = 'WatchNet' }
)

function Get-RowOn([string]$Flag) {
    if ($Flag -eq 'Tether') { return [bool]$Cfg.TetherUsbId }
    $Cfg[$Flag]
}

function Get-RowStatus([string]$Flag) {
    if (-not (Get-RowOn $Flag)) {
        if ($Flag -eq 'Tether') { return 'no tether armed' }
        return '--'
    }
    switch ($Flag) {
        'WatchAv' {
            $live = @($script:PrevAv)
            if ($live.Count) { return 'LIVE: ' + (($live | ForEach-Object { ($_ -split '\|')[0] }) -join ', ') }
            'idle'
        }
        'WatchUsb' {
            if ($script:PrevUsb) { "$($script:PrevUsb.Count) devices" } else { 'idle' }
        }
        'WatchClip' {
            if ($script:ClipFlag) { "HOLDING $($script:ClipFlag.Name)" }
            elseif ($Cfg.ClipClearSec) { "clear after $($Cfg.ClipClearSec)s" }
            else { 'warn only' }
        }
        'WatchSession' {
            if ($null -eq $script:PrevLocked) { 'idle' }
            elseif ($script:PrevLocked) { 'locked' }
            else { 'unlocked' }
        }
        'WatchPosture' {
            if (-not $script:PostureNow) { 'checking...' }
            else {
                $n = $script:PostureNow.Count
                $warn = @()
                if ($script:PostureNow['rdp_open'] -eq 'True') { $warn += 'rdp' }
                if ($script:PostureNow['autologon'] -eq 'True') { $warn += 'autologon' }
                if ($script:PostureNow['smb1'] -eq 'True') { $warn += 'smb1' }
                if ($script:PostureNow['uac'] -ne '1') { $warn += 'uac' }
                if ($script:PostureNow['secure_boot'] -ne '1') { $warn += 'secureboot' }
                if ($script:PostureNow['defender_rtp'] -ne 'True') { $warn += 'defender' }
                if ($script:PostureNow['firewall'] -match '=0') { $warn += 'firewall' }
                if ($script:PostureNow['lock_screen'] -like '*secure=no*') { $warn += 'lockscreen' }
                if ($warn.Count) { "$n checks, WARN: " + ($warn -join ' ') } else { "$n checks, all clear" }
            }
        }
        'WatchNet' {
            if ($null -eq $script:SeenProcs) { 'checking...' }
            else { '{0} procs, {1} dests' -f $script:SeenProcs.Count, $script:SeenPairs.Count }
        }
        'Tether' { "armed: $($Cfg.TetherUsbId)" }
    }
}

function Render {
    Clear-Host
    # ponytail: block chars live in banner.txt, decoded explicitly. Keeps this
    # file 7-bit ASCII so no BOM has to survive an editor round-trip.
    if (-not $script:Banner) {
        $script:Banner = @(Get-Content (Join-Path $PSScriptRoot 'banner.txt') -Encoding UTF8)
    }
    $last = $script:Banner.Count - 1
    for ($i = 0; $i -le $last; $i++) {
        $c = 'White'
        if ($i -eq $last) { $c = 'DarkRed' }          # rule
        elseif ($i -eq $last - 1) { $c = 'DarkGray' } # the font's shadow row
        Write-Host $script:Banner[$i] -ForegroundColor $c
    }
    Write-Host '  w a t c h d o g      mic cam usb clip lock' -ForegroundColor DarkGray
    Write-Host ''

    foreach ($r in $Rows) {
        $on = Get-RowOn $r.Flag
        Write-Host ('  [' + $r.K + '] ') -NoNewline -ForegroundColor DarkGray
        Write-Host (($r.Name + ' ').PadRight(20, '.')) -NoNewline
        if ($on) { Write-Host ' ON  ' -NoNewline -ForegroundColor Green }
        else { Write-Host ' OFF ' -NoNewline -ForegroundColor DarkGray }
        Write-Host ('  ' + (Get-RowStatus $r.Flag)) -ForegroundColor DarkYellow
    }

    Write-Host ''
    Write-Host '  [a] all on   [z] all off   [l] log   [q] quit' -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkGray
    if ($script:Recent.Count -eq 0) { Write-Host '  (quiet)' -ForegroundColor DarkGray }
    foreach ($line in $script:Recent) {
        $c = 'Gray'
        if ($line -match '\s(CLIP|KILL)\s') { $c = 'Red' }
        elseif ($line -match '\s(AV|USB)\s') { $c = 'Yellow' }
        Write-Host ('  ' + $line) -ForegroundColor $c
    }
}

function Set-Tether {
    Clear-Host
    Write-Host ''
    Write-Host '  ARM BUSKILL' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  1. Make sure the tether device is UNPLUGGED right now.'
    Write-Host '  2. Plug it in.'
    Write-Host ''
    Write-Host '  Waiting for a new USB device... (any key to cancel)' -ForegroundColor DarkGray
    $before = Get-UsbSet
    while (-not [Console]::KeyAvailable) {
        Start-Sleep -Milliseconds 400
        $now = Get-UsbSet
        $new = @($now.Keys | Where-Object { -not $before.ContainsKey($_) })
        if ($new.Count) {
            $Cfg.TetherUsbId = $new[0]
            $script:PrevUsb = $now
            Write-Snitch 'BOOT' "buskill armed on $($new[0])"
            return
        }
    }
    [void][Console]::ReadKey($true)
}

function Invoke-Key([char]$C) {
    $script:Dirty = $true
    $row = $Rows | Where-Object { $_.K -eq $C }
    if ($row) {
        if ($row.Flag -eq 'Tether') {
            if ($Cfg.TetherUsbId) { $Cfg.TetherUsbId = ''; Write-Snitch 'BOOT' 'buskill disarmed' }
            else { Set-Tether }
        }
        else { $Cfg[$row.Flag] = -not $Cfg[$row.Flag] }
        return $true
    }
    switch ($C) {
        'a' { foreach ($r in $Rows) { if ($r.Flag -ne 'Tether') { $Cfg[$r.Flag] = $true } } }
        'z' { foreach ($r in $Rows) { if ($r.Flag -ne 'Tether') { $Cfg[$r.Flag] = $false } } }
        'l' { Invoke-Item $LogFile }
        'q' { return $false }
    }
    $true
}

# --- main -------------------------------------------------------------------
Start-Tray
Invoke-Poll                        # baseline silently
$script:Recent.Clear()

if ($Draw) { Render; $script:Tray.Dispose(); return }

try {
    $running = $true
    while ($running) {
        Invoke-Poll
        if ($script:Dirty -or $script:Recent.Count -ne $script:LastCount) {
            Render
            $script:LastCount = $script:Recent.Count
            $script:Dirty = $false
        }
        [System.Windows.Forms.Application]::DoEvents()
        $until = (Get-Date).AddSeconds($Cfg.IntervalSec)
        while ((Get-Date) -lt $until) {
            if ([Console]::KeyAvailable) {
                $running = Invoke-Key ([char]([Console]::ReadKey($true).KeyChar.ToString().ToLower()))
                break
            }
            Start-Sleep -Milliseconds 80
        }
    }
}
finally {
    $script:Tray.Dispose()
    Write-Host ''
    Write-Host '  aura out. snitch stopped watching.' -ForegroundColor DarkGray
}
