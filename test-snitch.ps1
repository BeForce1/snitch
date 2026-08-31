# Run: .\test-snitch.ps1              everything
#      .\test-snitch.ps1 -PureOnly    skip asserts that need real hardware (for CI)
#
# All credentials below are fake and deliberately non-functional.
param([switch]$PureOnly)

. (Join-Path $PSScriptRoot 'snitch.ps1') -NoRun

$fail = 0
function Check([string]$What, [scriptblock]$Cond) {
    if (& $Cond) { "  ok   $What" }
    else { $script:fail++; "  FAIL $What" }
}

'Find-Secret catches:'
Check 'private key'  { (Find-Secret "x`n-----BEGIN RSA PRIVATE KEY-----`nMIIE") -eq 'private key' }
Check 'AWS key'      { (Find-Secret 'AKIAIOSFODNN7EXAMPLE') -eq 'AWS key' }
Check 'GitHub token' { (Find-Secret "ghp_$('x' * 36)") -eq 'GitHub token' }
Check 'Slack token'  { (Find-Secret 'xoxb-0000000000-abcdefghij') -eq 'Slack token' }
Check 'Google key'   { (Find-Secret "AIza$('x' * 35)") -eq 'Google key' }
Check 'API key'      { (Find-Secret "sk-ant-$('x' * 24)") -eq 'API key' }
Check 'JWT'          { (Find-Secret 'eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM') -eq 'JWT' }

'Find-Secret ignores:'
Check 'plain prose'  { $null -eq (Find-Secret 'lets clone the tier one windows apps') }
Check 'short sk-'    { $null -eq (Find-Secret 'sk-abc') }
Check 'empty'        { $null -eq (Find-Secret '') }
Check 'null'         { $null -eq (Find-Secret $null) }

'Readers:'
if (-not $PureOnly) {
    # A CI runner is a VM with no webcam and almost nothing on the USB bus.
    $usb = Get-UsbSet
    Check 'Get-UsbSet returns devices'  { $usb.Count -gt 0 }
    # The regression this guards: Get-UsbSet used to read Enum\USB, a record of every
    # device ever seen, so it reported long-gone hardware as attached and never saw a
    # removal. Cross-checked against Get-PnpDevice, a deliberately different API - on
    # the box where this was found the old reading was 17 against a true 5.
    Check 'Get-UsbSet is present-only' {
        $pfx = 'USB' + [char]92
        $live = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
                  Where-Object { $_.InstanceId -and $_.InstanceId.StartsWith($pfx) }).Count
        $usb.Count -eq $live
    }
    Check 'Get-UsbSet keys are VID\inst' { ($usb.Keys | Where-Object { $_ -match '^VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\.+' }).Count -gt 0 }
}
Check 'Get-AvInUse returns a list'      { $null -ne @(Get-AvInUse) }
Check 'Test-Locked is bool'             { (Test-Locked) -is [bool] }
Check 'Test-Locked false while running' { -not (Test-Locked) }

'Posture:'
$post = Get-Posture
Check 'Get-Posture has checks'      { $post.Count -ge 10 }
Check 'no null values'              { ($post.Values | Where-Object { $null -eq $_ }).Count -eq 0 }
Check 'firewall has 3 profiles'     { ($post['firewall'] -split ' ').Count -eq 3 }
Check 'ages bucketed, not raw'      { $post['defender_sig'] -in 'ok', 'unknown' -or $post['defender_sig'] -like 'stale*' }

# Compare-Posture takes the shape ConvertFrom-Json produces
$old = [pscustomobject]@{ firewall = 'Domain=1'; rdp_open = 'False'; uac = '1' }
$new = [ordered]@{ firewall = 'Domain=1'; rdp_open = 'True'; uac = '1' }
$drift = @(Compare-Posture $old $new)
Check 'drift detected'              { $drift.Count -eq 1 }
Check 'drift names old -> new'      { $drift[0] -eq 'rdp_open : False -> True' }
Check 'no drift when identical'     { @(Compare-Posture $old ([ordered]@{ firewall = 'Domain=1'; rdp_open = 'False'; uac = '1' })).Count -eq 0 }
Check 'new check is not drift'      { @(Compare-Posture $old ([ordered]@{ bitlocker = 'On' })).Count -eq 0 }

'Network diary:'
Check '127.0.0.1 is private'   { '127.0.0.1' -match $PrivateNet }
Check '10.x is private'        { '10.1.2.3' -match $PrivateNet }
Check '192.168.x is private'   { '192.168.1.1' -match $PrivateNet }
Check '172.20.x is private'    { '172.20.0.1' -match $PrivateNet }
Check '172.15.x is PUBLIC'     { -not ('172.15.0.1' -match $PrivateNet) }
Check '8.8.8.8 is public'      { -not ('8.8.8.8' -match $PrivateNet) }
Check '203.0.113.10 is public' { -not ('203.0.113.10' -match $PrivateNet) }
$nout = Get-NetOut   # not $net - that aliases snitch.ps1's -Net switch parameter
# 'no private dests leak' and the key-shape check pass vacuously on an empty set,
# so only the "returns anything at all" assert actually needs a live machine.
if (-not $PureOnly) { Check 'Get-NetOut returns pairs' { $nout.Count -gt 0 } }
Check 'keys are proc|ip:port'    { ($nout.Keys | Where-Object { $_ -match '^.+\|[0-9a-fA-F:.]+:\d+$' }).Count -eq $nout.Count }
Check 'no private dests leak'    { ($nout.Keys | Where-Object { ($_ -split '\|')[1] -match $PrivateNet }).Count -eq 0 }

'Device events:'
# Windows firing an indication on real hardware cannot be triggered from a test, so
# these drive the reaction path with a synthetic event on the same source identifier.
# Timings are deliberately loose - a CI runner is not a real-time system.
Check 'Start-DeviceWatch returns bool' { (Start-DeviceWatch) -is [bool] }
Check 'no event -> waits it out'       {
    $sw = [Diagnostics.Stopwatch]::StartNew(); $r = Wait-Interval 1; $sw.Stop()
    (-not $r) -and $sw.ElapsedMilliseconds -ge 900
}
Check 'queued event -> returns early'  {
    New-Event -SourceIdentifier 'snitchDevChange' -Sender 'test' | Out-Null
    $sw = [Diagnostics.Stopwatch]::StartNew(); $r = Wait-Interval 10; $sw.Stop()
    $r -and $sw.ElapsedMilliseconds -lt 1000
}
Check 'queue drained after firing'     {
    $sw = [Diagnostics.Stopwatch]::StartNew(); $r = Wait-Interval 1; $sw.Stop()
    (-not $r) -and $sw.ElapsedMilliseconds -ge 900
}
Check 'Stop-DeviceWatch unsubscribes'  {
    Stop-DeviceWatch
    -not [bool](Get-EventSubscriber -SourceIdentifier 'snitchDevChange' -Force -ErrorAction Ignore)
}

''
if ($fail) { "$fail FAILED"; exit 1 } else { 'all passed'; exit 0 }
