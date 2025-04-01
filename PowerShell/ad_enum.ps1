<#
    Simple wrapper around PowerView, used to generate a basic domain enumeration information. It depends on a loader PowerView.ps1
#>
function Enumerate-Basic {
    Param([string]$domain)

    Write-Host "[+] Domain SID" -ForegroundColor Blue
    Get-DomainSID -Domain $domain
    Write-Host ""

    Write-Host "[+] Domain Controller" -ForegroundColor Blue
    Get-DomainController -Domain $domain | Select-Object Forest,Name,OSVersion,IPAddress |fl
    Write-Host ""

    Write-Host "[+] Users" -ForegroundColor Blue
    Get-DomainUser -Domain $domain -Properties samaccountname,objectsid,memberof,description |fl
    Write-Host ""

    Write-Host "[+] Computers" -ForegroundColor Blue
    Get-DomainComputer -Domain $domain -Properties dnshostname,objectsid,operatingsystem,operatingsystemversion |fl
    Write-Host ""

    Write-Host "[+] SPNs" -ForegroundColor Blue
    Get-DomainUser -SPN -Domain $domain -Properties samaccountname,serviceprincipalname |fl
    Write-Host ""

    Write-Host "[+] Accounts with Kerberos PreauthNotRequired" -ForegroundColor Blue
    Get-DomainUser -PreauthNotRequired -Domain $domain -Properties samaccountname,objectsid |fl 
    Write-HOst ""
}


function Enumerate-Foreign {
        Param([string]$domain)

        Write-Host "[+] Foreign group memberships" -ForegroundColor Blue
        $foreign = Get-DomainForeignGroupMember -Domain $domain 
        if ($foreign) {
                $foreign | foreach-object { 
                        $group = $_.GroupName 
                        $group_domain = $_.GroupDomain 
                        $member = ConvertFrom-SID -Sid $_.MemberName 
                        Write-Host "`nDomain: $group_domain`nGroup: $group`nMember: $member" 
                }
        } else {
                Write-Host "No Results"
        }
        Write-Host ""
}



function Enumerate-Trust-GPO {
    Param([string]$domain)

    Write-Host "[+] Domain Trusts" -ForegroundColor Blue
    $trust = Get-DomainTrust -Domain $domain
    if ($trust) { $trust } else { Write-Host "No Results" }
    Write-Host ""

    Write-Host "[+] Domain GPOs" -ForegroundColor Blue
    Get-DomainGPO -Domain $domain | foreach-object { 
        if (($_.displayname -ne "Default Domain Policy") -and ($_.displayname -ne "Default Domain Controllers Policy")) { 
                $name = $_.displayname
                $guid = $_.cn
                $sys_path = $_.gpcfilesyspath
                $hosts=Get-DomainOU -Domain $domain -GPLink "$guid" | % {Get-DomainComputer -Domain $domain -SearchBase $_.distinguishedname -Properties dnshostname}

                Write-Host "GPO: $name"
                Write-Host "`tPath: $sys_path"
                Write-Host "`tHosts:"
                $hosts | ForEach-Object { Write-Host "`t`t$($_.dnshostname)" }
        } 
    }
    Write-Host "`n`n"
}


function Enumerate-Delegation {
    Param([string]$domain)

    Write-Host "[+] Unconstrained delegation" -ForegroundColor Blue
    $unc = Get-DomainComputer -Domain $domain -Unconstrained
    if ($unc) { $unc | ForEach-Object { Write-Host $_.dnshostname } } else { Write-Host "No Results" }
    Write-Host ""

    Write-Host "[+] Constrained delegation" -ForegroundColor Blue
    $const = Get-DomainUser -Domain $domain -TrustedToAuth -Properties samaccountname,msDS-AllowedToDelegateTo|fl
    if ($const) { $const } else { Write-Host "No Results" }
    Write-Host ""

    Write-Host "[+] RBCD" -ForegroundColor Blue
    Get-DomainComputer -Domain $domain -Properties dnsHostName, msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } | foreach-object {
        $bytes = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $SD = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $bytes, 0
        $SDDL = $SD.GetSddlForm("All")
        $sid_string = $SDDL -split ";;;"
        $sid = $sid_string[1].Substring(0, $sid_string[1].Length - 1)
        Write-Host "DelegateTo: $($_.dnsHostName)"
        Write-Host "DelegateFrom: $(ConvertFrom-SID -sid $sid)"
    }
    Write-Host ""

    Write-Host "[+] Permissions that can be abused for RBCD" -ForegroundColor Blue
    $sid = Get-DomainSID -Domain $domain
    $rbcd = Get-DomainComputer -Domain $domain | Get-DomainObjectAcl -Domain $domain -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "$($sid)-[\d]{4,10}" }
    if ($rbcd) {
        
        Write-Host "Permission: $($rbcd.ActiveDirectoryRights)"
        Write-Host "To: $($rbcd.ObjectDN)"
        $sec_ident = $rbcd.SecurityIdentifier
        $identity = ConvertFrom-SID -sid $sec_ident
        Write-Host "From: $identity"
         
    } else { Write-Host "No Results" }
    Write-Host ""
}


function Invoke-Enum {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    Enumerate-Basic $Domain
    Enumerate-Foreign $Domain
    Enumerate-Trust-GPO $Domain
    Enumerate-Delegation $Domain
}

#Invoke-Enum -Domain cowmotors.com