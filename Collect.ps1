# Windows PowerShell 5.1; passive diagnostic collector, version 1.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $PSScriptRoot ('results_' + $stamp + '_' + [guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $out | Out-Null
$script:issues = New-Object System.Collections.Generic.List[string]
function Save-Json($Name, $Value) {
    ConvertTo-Json -InputObject $Value -Depth 8 | Set-Content -LiteralPath (Join-Path $out $Name) -Encoding UTF8
}
function Issue($Text) { $script:issues.Add($Text); Write-Host $Text -ForegroundColor Yellow }
function Pick-File($Title, $Filter) {
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Title = $Title; $d.Filter = $Filter
    try { if ($d.ShowDialog() -eq 'OK') { return $d.FileName } } finally { $d.Dispose() }
    return $null
}
function Find-Tshark {
    $cmd = Get-Command tshark.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { $p = Join-Path $root 'Wireshark\tshark.exe'; if (Test-Path -LiteralPath $p) { return $p } }
    }
    return $null
}
$capStatus = 'not attempted'
try {
    Write-Host 'USB Recovery Diagnostic v1.0' -ForegroundColor Cyan
    Write-Host 'Select the original application EXE. It will NOT be executed automatically.'
    Write-Host 'This tool only collects information and records traffic. No response modification.'
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Save-Json 'environment.json' ([ordered]@{ time=(Get-Date).ToString('o'); os=[Environment]::OSVersion.VersionString; powershell=$PSVersionTable.PSVersion.ToString(); is64bit=[Environment]::Is64BitProcess; administrator=$admin; collector='1.0' })
    $exe = Pick-File 'Select the device-writing application EXE (Cancel to skip)' 'Executable (*.exe)|*.exe'
    if ($exe) {
        $item = Get-Item -LiteralPath $exe
        Save-Json 'application.json' ([ordered]@{ name=$item.Name; size=$item.Length; sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash; version=$item.VersionInfo.FileVersion; product=$item.VersionInfo.ProductName })
        $files = @(Get-ChildItem -LiteralPath $item.DirectoryName -File | Where-Object { $_.Extension -in @('.dll','.exe','.config') } | ForEach-Object { [pscustomobject]@{name=$_.Name; size=$_.Length; version=$_.VersionInfo.FileVersion} })
        Save-Json 'neighbor_files.json' $files
        # Scan only known communication names, not arbitrary embedded strings/secrets.
        if ($item.Length -le 64MB) {
            $bytes = [IO.File]::ReadAllBytes($exe)
            $ascii = [Text.Encoding]::ASCII.GetString($bytes)
            $wide = [Text.Encoding]::Unicode.GetString($bytes)
            $names = @('WinUsb_ReadPipe','WinUsb_WritePipe','WinUsb_ControlTransfer','winusb.dll','hid.dll','HidD_GetFeature','HidD_SetFeature','ReadFile','WriteFile','DeviceIoControl','CreateFileW','CreateFileA','libusb','FT_Read','FT_Write','ftd2xx','CP210','SerialPort','mscoree.dll')
            $hits = @($names | Where-Object { $ascii.IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0 -or $wide.IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0 })
            Save-Json 'api_name_hints.json' ([ordered]@{method='Known-name byte search; presence is only a hint, absence is inconclusive. Not an import-table parser.'; hits=$hits})
            $ascii=$null; $wide=$null; $bytes=$null
        } else { Issue 'EXE exceeds 64 MiB: byte-name scan skipped.' }
    }
    try {
        $devs = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match '^(USB|HID)\\' } | Select-Object Name,PNPDeviceID,Service,Status,ConfigManagerErrorCode)
        Save-Json 'usb_devices.json' $devs
        $drivers = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceID -match '^(USB|HID)\\' } | Select-Object DeviceName,DeviceID,DriverProviderName,DriverVersion,InfName)
        Save-Json 'usb_drivers.json' $drivers
    } catch { Issue ('Device inventory: ' + $_.Exception.Message) }
    Write-Host ''
    Write-Host 'Optional: select the encrypted input file. Only size/hash/first 64 bytes are recorded.'
    if ((Read-Host 'Inspect input file? [y/N]') -match '^[yY]$') {
        $inputFile = Pick-File 'Select encrypted input file' 'All files (*.*)|*.*'
        if ($inputFile) {
            $f = Get-Item -LiteralPath $inputFile
            $stream = [IO.File]::OpenRead($inputFile)
            try { $head=New-Object byte[] 64; $n=$stream.Read($head,0,64) } finally { $stream.Dispose() }
            $hex = if ($n -gt 0) { [BitConverter]::ToString($head,0,$n) } else { '' }
            Save-Json 'input_file.json' ([ordered]@{name=$f.Name; size=$f.Length; sha256=(Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash; first64bytes=$hex})
        }
    }
    $tshark = Find-Tshark
    if (-not $tshark) {
        Write-Host 'TShark not found. Wireshark + USBPcap are needed for USB capture.'
        if ((Read-Host 'Locate an existing tshark.exe manually? [y/N]') -match '^[yY]$') {
            $tshark = Pick-File 'Select tshark.exe' 'TShark (tshark.exe)|tshark.exe'
        }
    }
    if ($tshark) {
        # Avoid PowerShell 5.1 treating native stderr as a terminating error.
        $oldPref=$ErrorActionPreference; $ErrorActionPreference='Continue'
        $listing = @(& $tshark -D 2> (Join-Path $out 'interface_errors.txt'))
        $listCode=$LASTEXITCODE; $ErrorActionPreference=$oldPref
        $listing | Set-Content -LiteralPath (Join-Path $out 'interfaces.txt') -Encoding UTF8
        $usbLines = @($listing | Where-Object { $_ -match 'USBPcap' })
        if ($listCode -eq 0 -and $usbLines.Count -gt 0) {
            Write-Host '\nUSB capture interfaces:' -ForegroundColor Cyan
            $usbLines | ForEach-Object { Write-Host $_ }
            Write-Host 'Choose the USBPcap interface for the target root hub; never a network interface.'
            Write-Host 'If unsure, use Wireshark Capture Options / USBPcap settings to inspect hub devices.'
            $pick=Read-Host 'Interface number (Enter to skip)'
            $selected=@($usbLines | Where-Object { $_ -match ('^' + [regex]::Escape($pick) + '\.\s') })
            if ($pick -match '^\d+$' -and $selected.Count -eq 1) {
                $duration=45
                $seconds=Read-Host 'Capture duration in seconds, 10-300 [45]'
                if ($seconds) { $parsed=0; if ([int]::TryParse($seconds,[ref]$parsed) -and $parsed -ge 10 -and $parsed -le 300) { $duration=$parsed } else { Write-Host 'Invalid duration; using 45 seconds.' } }
                Write-Host 'Capture includes ALL traffic on the selected USB root hub, possibly other devices.' -ForegroundColor Yellow
                Write-Host 'Close the target application. After capture starts, open it and reproduce the message once.'
                Write-Host 'The original application may still perform its normal device-writing operations.'
                Read-Host 'Press Enter when ready' | Out-Null
                $capture=Join-Path $out 'capture.pcapng'
                $argsLine='-i ' + $pick + ' -a duration:' + $duration + ' -w "' + $capture + '"'
                $start=(Get-Date).ToString('o')
                $proc=Start-Process -FilePath $tshark -ArgumentList $argsLine -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $out 'capture_stdout.txt') -RedirectStandardError (Join-Path $out 'capture_stderr.txt')
                Write-Host ('Capture requested. Reproduce the message now. Auto-stop in about ' + $duration + ' seconds.') -ForegroundColor Green
                if (-not $proc.WaitForExit(($duration+30)*1000)) {
                    Issue 'Capture did not stop on time; collector stopped its own capture process. Capture may be incomplete.'
                    $proc.Kill(); $proc.WaitForExit(); $capStatus='timeout/incomplete'
                } else { $capStatus='process exited; check packet_count and capture_stderr' }
                $proc.Refresh()
                Save-Json 'capture_session.json' ([ordered]@{start=$start; end=(Get-Date).ToString('o'); interface=$selected[0]; seconds=$duration; exitCode=$proc.ExitCode; status=$capStatus})
                if ((Test-Path -LiteralPath $capture) -and (Get-Item -LiteralPath $capture).Length -gt 0) {
                    $oldPref=$ErrorActionPreference; $ErrorActionPreference='Continue'
                    $countLines=@(& $tshark -r $capture -T fields -e frame.number 2> (Join-Path $out 'parse_errors.txt'))
                    $parseCode=$LASTEXITCODE
                    $countLines.Count | Set-Content -LiteralPath (Join-Path $out 'packet_count.txt')
                    & $tshark -r $capture -Y usb -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_relative -e usb.bus_id -e usb.device_address -e usb.endpoint_address -e usb.transfer_type -e frame.len 2> (Join-Path $out 'summary_errors.txt') | Set-Content -LiteralPath (Join-Path $out 'usb_frames.csv') -Encoding UTF8
                    $ErrorActionPreference=$oldPref
                    if ($parseCode -ne 0 -or $countLines.Count -eq 0) { Issue 'Capture empty or unreadable. See capture_stderr.txt and parse_errors.txt.' }
                } else { Issue 'No capture file was produced. See capture_stderr.txt.' }
            } else { $capStatus='skipped: no valid USB interface selected' }
        } else { $capStatus='USBPcap unavailable'; Issue 'No USBPcap capture interface. Install USBPcap, reboot if requested, and run again as administrator.' }
    } else { $capStatus='TShark unavailable'; Issue 'Capture skipped: tshark.exe not installed.' }
    if ($exe) {
        try {
            $mods=@(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($exe)) -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules | ForEach-Object { [pscustomobject]@{name=$_.ModuleName; version=$_.FileVersionInfo.FileVersion} } } | Sort-Object name -Unique)
            Save-Json 'loaded_module_names.json' $mods
        } catch { Issue ('Loaded modules unavailable: ' + $_.Exception.Message) }
    }
    $message=Read-Host 'Exact message shown by the application (Korean OK)'
    $timing=Read-Host 'When did it appear? e.g. immediately / after file selection / after Write click'
    Save-Json 'observations.json' ([ordered]@{message=$message; timing=$timing; captureStatus=$capStatus})
} catch {
    Issue ('Collector error: ' + $_.Exception.Message)
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $out 'fatal_error.txt') -Encoding UTF8
} finally {
    Save-Json 'issues.json' @($script:issues.ToArray())
    @('USB Recovery Diagnostic v1.0',('Capture status: '+$capStatus),'Share this result ZIP for the next analysis step.','No EXE/DLL/input-file copies are included.','Capture contains real USB payloads; device IDs can contain serial numbers.','API-name matches are clues, not proof of a transport or decryption scheme.') | Set-Content -LiteralPath (Join-Path $out 'SUMMARY.txt') -Encoding UTF8
    try {
        $zip=$out+'.zip'
        Compress-Archive -LiteralPath $out -DestinationPath $zip -CompressionLevel Optimal
        Write-Host ('Result ZIP: ' + $zip) -ForegroundColor Green
        Start-Process explorer.exe -ArgumentList ('/select,"' + $zip + '"')
    } catch { Write-Host ('ZIP failed. Send the result folder manually: ' + $out) -ForegroundColor Yellow }
    Read-Host 'Finished. Press Enter to close' | Out-Null
}
