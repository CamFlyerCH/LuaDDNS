# LuaDNS PowerShell Functions
# Inspired by https://github.com/rmbolger/Posh-ACME/blob/39cdd3e222e224f8567f28a282ac833c984d021a/Posh-ACME/Plugins/LuaDns.ps1
# Modified by https://github.com/CamFlyerCH


function Add-LuaDnsRecord {
    [CmdletBinding(DefaultParameterSetName='Secure')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    param(
        [Parameter(Mandatory,Position=0)]
        [string]$RecordName,
        [Parameter(Mandatory,Position=1)]
        [ValidateSet("A","AAAA","ALIAS","CAA","CNAME","DS","FORWARD","MX","NS","PTR","REDIRECT","SOA","SPF","SRV","SSHFP","TLSA","TXT", IgnoreCase=$false)]
        [string]$RecordType,
        [Parameter(Mandatory,Position=2)]
        [string]$RecordValue,
        [Parameter(Position=3)]
        [ValidateRange(60,86400)]
        [int]$RecordTTL=3600,
        [string]$Mode="Modify",
        [Parameter(ParameterSetName='Secure',Mandatory,Position=4)]
        [pscredential]$LuaCredential,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=5)]
        [string]$LuaUsername,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=6)]
        [string]$LuaPassword,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    # create a pscredential from insecure args if necessary
    if ('DeprecatedInsecure' -eq $PSCmdlet.ParameterSetName) {
        $secpass = ConvertTo-SecureString $LuaPassword -AsPlainText -Force
        $LuaCredential = [pscredential]::new($LuaUsername,$secpass)
    }

    $apiRoot = 'https://api.luadns.com/v1'
    $restParams = @{
        Headers = @{Accept='application/json'}
        ContentType = 'application/json'
        Credential = $LuaCredential
    }

    # get the zone name for our record
    $zoneID = Find-LuaZone $RecordName $restParams
    Write-Debug "Found zone $zoneID"

    # Search for the record we care about
    try {
        $rec = @( (Invoke-RestMethod "$apiRoot/zones/$zoneID/records" @restParams -UseBasicParsing:$true) |
                Where-Object { $_.name -eq "$RecordName." -and $_.type -eq $RecordType -and $_.content -eq $RecordValue } )
    } catch { throw }

    if (-not $rec) {
        # add new record
        try {
            Write-Verbose "Adding a new $RecordType record for $RecordName with value $RecordValue and TTL $RecordTTL"
            $bodyJson = @{name="$RecordName.";type=$RecordType;content=$RecordValue;ttl=$RecordTTL } | ConvertTo-Json -Compress
            Invoke-RestMethod "$apiRoot/zones/$zoneID/records" -Method Post -Body $bodyJson @restParams -UseBasicParsing:$true | Out-Null
        } catch { throw }
    } else {
        $recSubset = @($rec | Where-Object {$_.ttl -eq $RecordTTL })
        If ($recSubset.count -eq 1){
            Write-Verbose "Record already exists. Nothing to do."
        } Else {
            # update a record ttl
            try {
                Write-Verbose "Modify $RecordType record $RecordName and value $RecordValue with TTL $RecordTTL"
                $bodyJson = @{name="$RecordName.";type=$RecordType;content=$RecordValue;ttl=$RecordTTL} | ConvertTo-Json -Compress
                Invoke-RestMethod "$apiRoot/zones/$zoneID/records/$($rec.id)" -Method Put -Body $bodyJson @restParams -UseBasicParsing:$true | Out-Null
            } catch { throw }
        }
    }

    <#
    .SYNOPSIS
        Add a DNS record to LuaDns.

    .DESCRIPTION
        Add or update (if TTL is different) a DNS record to LuaDns.

    .PARAMETER RecordName
        The fully qualified name of the DNS record.

    .PARAMETER RecordType
        The type of the DNS record like A, AAAA, TXT .....

    .PARAMETER RecordValue
        The value to set for the DNS record

    .PARAMETER RecordTTL
        The TTL in seconds to set for the DNS record (default is 3600 s)

    .PARAMETER LuaCredential
        A PSCredential object containing the account email address as the username and API token as the password.

    .PARAMETER LuaUsername
        (DEPRECATED) The account email address.

    .PARAMETER LuaPassword
        (DEPRECATED) The account API token.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Add-LuaDnsRecord -RecordName "website.contoso.com" -RecordValue "My text record" -RecordType TXT -LuaUsername "dnsadmin@contoso.com" -LuaPassword "3d0939b10edb30f4028198747c624f4d" -Verbose

        Adds a TXT record for the specified site with the specified values.
    #>
}

function Set-LuaDnsRecord {
    [CmdletBinding(DefaultParameterSetName='Secure')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    param(
        [Parameter(Mandatory,Position=0)]
        [string]$RecordName,
        [Parameter(Mandatory,Position=1)]
        [ValidateSet("A","AAAA","ALIAS","CAA","CNAME","DS","FORWARD","MX","NS","PTR","REDIRECT","SOA","SPF","SRV","SSHFP","TLSA","TXT", IgnoreCase=$false)]
        [string]$RecordType,
        [Parameter(Mandatory,Position=2)]
        [string]$RecordValue,
        [Parameter(Position=3)]
        [ValidateRange(60,86400)]
        [int]$RecordTTL=3600,
        [Parameter(ParameterSetName='Secure',Mandatory,Position=4)]
        [pscredential]$LuaCredential,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=5)]
        [string]$LuaUsername,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=6)]
        [string]$LuaPassword,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    # create a pscredential from insecure args if necessary
    if ('DeprecatedInsecure' -eq $PSCmdlet.ParameterSetName) {
        $secpass = ConvertTo-SecureString $LuaPassword -AsPlainText -Force
        $LuaCredential = [pscredential]::new($LuaUsername,$secpass)
    }

    $apiRoot = 'https://api.luadns.com/v1'
    $restParams = @{
        Headers = @{Accept='application/json'}
        ContentType = 'application/json'
        Credential = $LuaCredential
    }

    # get the zone name for our record
    $zoneID = Find-LuaZone $RecordName $restParams
    Write-Debug "Found zone $zoneID"

    # Search for the record we care about
    try {
        $rec = @( (Invoke-RestMethod "$apiRoot/zones/$zoneID/records" @restParams -UseBasicParsing:$true) |
                Where-Object { $_.name -eq "$RecordName." -and $_.type -eq $RecordType } )
    } catch { throw }

    $WorkDone = $false

    if (-not $rec) {
        # add new record
        try {
            Write-Verbose "Adding a new $RecordType record for $RecordName with value $RecordValue and TTL $RecordTTL"
            $bodyJson = @{name="$RecordName.";type=$RecordType;content=$RecordValue;ttl=$RecordTTL } | ConvertTo-Json -Compress
            Invoke-RestMethod "$apiRoot/zones/$zoneID/records" -Method Post -Body $bodyJson @restParams -UseBasicParsing:$true | Out-Null
            $WorkDone = $true
        } catch { throw }
    } else {
        # update a record ttl
        $recSubset = @($rec | Where-Object { $_.content -eq $RecordValue })
        If ($recSubset){
            If ($recSubset.ttl -eq $RecordTTL){
                Write-Verbose "Record already exists. Nothing to do."
            } Else {
                # update a record ttl
                try {
                    Write-Verbose "Modify TTL of $RecordType record $RecordName and value $RecordValue with TTL $RecordTTL"
                    $bodyJson = @{name="$RecordName.";type=$RecordType;content=$RecordValue;ttl=$RecordTTL} | ConvertTo-Json -Compress
                    Invoke-RestMethod "$apiRoot/zones/$zoneID/records/$($recSubset.id)" -Method Put -Body $bodyJson @restParams -UseBasicParsing:$true | Out-Null
                } catch { throw }
            }
            $WorkDone = $true
        }

        # update one record and delete the rest
        $recSubset = @($rec | Where-Object { $_.content -ne $RecordValue })
        If ($recSubset){
            ForEach($recSub in $recSubset){
                If($WorkDone){
                    # delete record
                    try {
                        Write-Verbose ("Removing record id " + $recSub.id + " for $RecordName with value " + $recSub.content)
                        Invoke-RestMethod "$apiRoot/zones/$zoneID/records/$($recSub.id)" -Method Delete @restParams -UseBasicParsing:$true | Out-Null
                    } catch { throw }
                } else {
                    try {
                        Write-Verbose "Modify $RecordType record $RecordName and value $RecordValue with TTL $RecordTTL"
                        $bodyJson = @{name="$RecordName.";type=$RecordType;content=$RecordValue;ttl=$RecordTTL} | ConvertTo-Json -Compress
                        Invoke-RestMethod "$apiRoot/zones/$zoneID/records/$($recSub.id)" -Method Put -Body $bodyJson @restParams -UseBasicParsing:$true | Out-Null
                        $WorkDone = $true
                    } catch { throw }
                }
            }
        }
    }

    <#
    .SYNOPSIS
        Add or update one record in LuaDNS and delete others with the same RecordName.

    .DESCRIPTION
        Update (or add if missing) one DNS record in LuaDNS and delete others with the same RecordName.

    .PARAMETER RecordName
        The fully qualified name of the DNS record.

    .PARAMETER RecordType
        The type of the DNS record like A, AAAA, TXT .....

    .PARAMETER RecordValue
        The value to set for the DNS record

    .PARAMETER RecordTTL
        The TTL in seconds to set for the DNS record (default is 3600 s)

    .PARAMETER LuaCredential
        A PSCredential object containing the account email address as the username and API token as the password.

    .PARAMETER LuaUsername
        (DEPRECATED) The account email address.

    .PARAMETER LuaPassword
        (DEPRECATED) The account API token.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Set-LuaDnsRecord -RecordName "website.contoso.com" -RecordValue "My text record" -RecordType TXT -LuaUsername "dnsadmin@contoso.com" -LuaPassword "3d0939b10edb30f4028198747c624f4d" -Verbose

        Adds a TXT record for the specified site with the specified values.
    #>
}

function Remove-LuaDnsRecord {
    [CmdletBinding(DefaultParameterSetName='Secure')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    param(
        [Parameter(Mandatory,Position=0)]
        [string]$ZoneName,
        [Parameter(Mandatory,Position=1)]
        [string]$RecordId,
        [Parameter(ParameterSetName='Secure',Mandatory,Position=2)]
        [pscredential]$LuaCredential,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=3)]
        [string]$LuaUsername,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=4)]
        [string]$LuaPassword,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    # create a pscredential from insecure args if necessary
    if ('DeprecatedInsecure' -eq $PSCmdlet.ParameterSetName) {
        $secpass = ConvertTo-SecureString $LuaPassword -AsPlainText -Force
        $LuaCredential = [pscredential]::new($LuaUsername,$secpass)
    }

    $apiRoot = 'https://api.luadns.com/v1'
    $restParams = @{
        Headers = @{Accept='application/json'}
        ContentType = 'application/json'
        Credential = $LuaCredential
    }

    # get the zone name for our record
    $zoneID = Find-LuaZone $ZoneName $restParams
    Write-Debug "Found zone $zoneID"

    # delete record
    try {
        Write-Verbose ("Removing record id $RecordId from zone $ZoneName ($zoneID)")
        Invoke-RestMethod "$apiRoot/zones/$zoneID/records/$RecordId" -Method Delete @restParams -UseBasicParsing:$true | Out-Null
    } catch { throw }

    <#
    .SYNOPSIS
        Delete one record in LuaDNS

    .DESCRIPTION
        Deletes a record by specifying ZoneName and RecordId.

    .PARAMETER RecordName
        The fully qualified name of the DNS record.

    .PARAMETER RecordType
        The type of the DNS record like A, AAAA, TXT .....

    .PARAMETER RecordValue
        The value to set for the DNS record

    .PARAMETER RecordTTL
        The TTL in seconds to set for the DNS record (default is 3600 s)

    .PARAMETER LuaCredential
        A PSCredential object containing the account email address as the username and API token as the password.

    .PARAMETER LuaUsername
        (DEPRECATED) The account email address.

    .PARAMETER LuaPassword
        (DEPRECATED) The account API token.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Set-LuaDnsRecord -RecordName "website.contoso.com" -RecordValue "My text record" -RecordType TXT -LuaUsername "dnsadmin@contoso.com" -LuaPassword "3d0939b10edb30f4028198747c624f4d" -Verbose

        Adds a TXT record for the specified site with the specified values.
    #>
}


function Get-LuaDnsZone {
    [CmdletBinding(DefaultParameterSetName='Secure')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
    param(
        [Parameter(Mandatory,Position=0)]
        [string]$ZoneName,
        [Parameter(ParameterSetName='Secure',Mandatory,Position=1)]
        [pscredential]$LuaCredential,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=2)]
        [string]$LuaUsername,
        [Parameter(ParameterSetName='DeprecatedInsecure',Mandatory,Position=3)]
        [string]$LuaPassword,
        [Parameter(ValueFromRemainingArguments)]
        $ExtraParams
    )

    # create a pscredential from insecure args if necessary
    if ('DeprecatedInsecure' -eq $PSCmdlet.ParameterSetName) {
        $secpass = ConvertTo-SecureString $LuaPassword -AsPlainText -Force
        $LuaCredential = [pscredential]::new($LuaUsername,$secpass)
    }

    $apiRoot = 'https://api.luadns.com/v1'
    $restParams = @{
        Headers = @{Accept='application/json'}
        ContentType = 'application/json'
        Credential = $LuaCredential
    }

    # get the zone name for our record
    $zoneID = Find-LuaZone $ZoneName $restParams
    Write-Debug "Found zone $zoneID"

    # Search for the record we care about
    try {
        $RestResult = Invoke-RestMethod "$apiRoot/zones/$zoneID/records" @restParams -UseBasicParsing:$true
        return $RestResult
    } catch { throw }

    <#
    .SYNOPSIS
        List DNS records from LuaDNS.

    .DESCRIPTION
        List all DNS records of a specified DNS zone from LuaDNS.

    .PARAMETER ZoneName
        The fully qualified name of the DNS zone.

    .PARAMETER LuaCredential
        A PSCredential object containing the account email address as the username and API token as the password.

    .PARAMETER LuaUsername
        (DEPRECATED) The account email address.

    .PARAMETER LuaPassword
        (DEPRECATED) The account API token.

    .PARAMETER ExtraParams
        This parameter can be ignored and is only used to prevent errors when splatting with more parameters than this function supports.

    .EXAMPLE
        Get-LuaDnsZone -ZoneName "contoso.com" -LuaUsername "dnsadmin@contoso.com" -LuaPassword "3d0939b10edb30f4028198747c624f4d" -Verbose

        Outputs the DNS zone contoso.com records.
    #>
}


# Helper Functions

# API Docs
# http://www.luadns.com/api.html

function Find-LuaZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [string]$RecordName,
        [Parameter(Mandatory,Position=1)]
        [hashtable]$RestParams
    )

    # setup a module variable to cache the record to zone mapping
    # so it's quicker to find later
    if (!$script:LuaRecordZones) { $script:LuaRecordZones = @{} }

    # check for the record in the cache
    if ($script:LuaRecordZones.ContainsKey($RecordName)) {
        return $script:LuaRecordZones.$RecordName
    }

    $apiRoot = 'https://api.luadns.com/v1'

    # Since the provider could be hosting both apex and sub-zones, we need to find the closest/deepest
    # sub-zone that would hold the record rather than just adding it to the apex. So for something
    # like _acme-challenge.site1.sub1.sub2.example.com, we'd look for zone matches in the following
    # order:
    # - site1.sub1.sub2.example.com
    # - sub1.sub2.example.com
    # - sub2.example.com
    # - example.com

    # get the list of zones
    try {
        $zones = Invoke-RestMethod "$apiRoot/zones" @RestParams -UseBasicParsing
    } catch { throw }

    $pieces = $RecordName.Split('.')
    for ($i=0; $i -lt ($pieces.Count-1); $i++) {
        $zoneTest = $pieces[$i..($pieces.Count-1)] -join '.'
        Write-Debug "Checking $zoneTest"
        if ($zoneTest -in $zones.name) {
            $zoneID = ($zones | Where-Object { $_.name -eq $zoneTest }).id
            $script:LuaRecordZones.$RecordName = $zoneID
            return $zoneID
        }
    }

    return $null

}



# Dynamic DNS solution for IPv4 and IPv6
# Support multiple IPv6 server addresses


# create a pscredential from insecure args if necessary
$SecString = ConvertTo-SecureString "30d39bdb78324f4f402847c6147c610e" -AsPlainText -Force
$LuaCredential = [pscredential]::new("yourmail@gmail.com",$SecString)

$DnsZone = "contoso.com"
$TTL = 600

#$LiveRecord = @(Resolve-DnsName -Name $DnsRecord -Type AAAA -DnsOnly -Server "ns3.luadns.net")[0] | Select-Object -ExpandProperty IPAddress
#$InterfaceIpv6 = (Get-NetIPAddress | Where-Object {$_.AddressFamily -like "IPv6" -AND $_.PrefixOrigin -eq "RouterAdvertisement"} | Sort-Object -Property PrefixLength -Descending)[0] | Select-Object -ExpandProperty IPAddress

#$LiveRecords = @(Resolve-DnsName -Name $DnsRecord -Type AAAA -DnsOnly -Server "ns3.luadns.net" | Where-Object {$_.IpAddress} | Select-Object -ExpandProperty IPAddress)
#(Invoke-WebRequest -uri "https://ipinfo.io/" -UseBasicParsing -).Content

#$ExternalIPv4 = (Invoke-WebRequest -uri "https://api.ipify.org/" -UseBasicParsing).Content
#$ExternalIPv6 = (Invoke-WebRequest -uri "https://api64.ipify.org/" -UseBasicParsing).Content

#$ExternalIPv4 = $(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress
#$ExternalIPv6 = $(Resolve-DnsName -Name myip.opendns.com -Type AAAA -Server resolver1.ipv6-sandbox.opendns.com).IPAddress

#Get actual addresses
$ExternalIPv4 = (Invoke-WebRequest -uri "https://api.ipify.org/" -UseBasicParsing).Content
$InterfaceIpv6s = @(Get-NetIPAddress | Where-Object {$_.AddressFamily -like "IPv6" -AND $_.PrefixOrigin -eq "RouterAdvertisement"} | Select-Object -ExpandProperty IPAddress)

#Get DNS entries from zone via API
$DnsRecordLists = @(Get-LuaDnsZone -ZoneName $DnsZone -LuaCredential $LuaCredential)

# Work on ipv4 entries
$HostFqdn = "ipv4.$DnsZone"
$DnsRecord = (@($DnsRecordLists | Where-Object { $_.name -eq ($HostFqdn + ".") -and $_.type -eq "A" }))[0]

# Update or add DNS entry if needed
If($DnsRecord){
    If($ExternalIPv4 -like $DnsRecord.content){
        Write-Host "DNS entry $($DnsRecord.id) for $($DnsRecord.type) record $($DnsRecord.name) with value $($DnsRecord.content) is OK"
    } Else {
        Set-LuaDnsRecord -RecordName $HostFqdn -RecordValue $ExternalIPv4 -RecordType A -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
    }
} else {
    Add-LuaDnsRecord -RecordName $HostFqdn -RecordValue $ExternalIPv4 -RecordType A -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
}


$HostFqdn = "homedyn.$DnsZone"
$DnsRecord = (@($DnsRecordLists | Where-Object { $_.name -eq ($HostFqdn + ".") -and $_.type -eq "A" }))[0]

# Update or add DNS entry if needed
If($DnsRecord){
    If($ExternalIPv4 -like $DnsRecord.content){
        Write-Host "DNS entry $($DnsRecord.id) for $($DnsRecord.type) record $($DnsRecord.name) with value $($DnsRecord.content) is OK"
    } Else {
        Set-LuaDnsRecord -RecordName $HostFqdn -RecordValue $ExternalIPv4 -RecordType A -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
    }
} else {
    Add-LuaDnsRecord -RecordName $HostFqdn -RecordValue $ExternalIPv4 -RecordType A -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
}





# Work on ipv6 entries
$HostFqdn = "ipv6.$DnsZone"
$DnsRecords = $DnsRecordLists | Where-Object { $_.name -eq ($HostFqdn + ".") -and $_.type -eq "AAAA" }

# Remove invalid DNS entries
$DnsRecords | ForEach-Object {
    If($InterfaceIpv6s -notcontains $_.content){
        Remove-LuaDnsRecord -ZoneName $DnsZone -RecordId $_.id -LuaCredential $LuaCredential -Verbose
    } else {
        Write-Host "DNS entry $($_.id) for $($_.type) record $($_.name) with value $($_.content) is OK"
    }
}

# Add missing DNS entries
$InterfaceIpv6s | ForEach-Object {
    If($DnsRecords.content -notcontains $_){
        Add-LuaDnsRecord -RecordName $HostFqdn -RecordValue $_ -RecordType AAAA -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
    } else {
        Write-Host "DNS entry for IP $_ exists"
    }
}

$HostFqdn = "homedyn.$DnsZone"
$DnsRecords = $DnsRecordLists | Where-Object { $_.name -eq ($HostFqdn + ".") -and $_.type -eq "AAAA" }

# Remove invalid DNS entries
$DnsRecords | ForEach-Object {
    If($InterfaceIpv6s -notcontains $_.content){
        Remove-LuaDnsRecord -ZoneName $DnsZone -RecordId $_.id -LuaCredential $LuaCredential -Verbose
    } else {
        Write-Host "DNS entry $($_.id) for $($_.type) record $($_.name) with value $($_.content) is OK"
    }
}

# Add missing DNS entries
$InterfaceIpv6s | ForEach-Object {
    If($DnsRecords.content -notcontains $_){
        Add-LuaDnsRecord -RecordName $HostFqdn -RecordValue $_ -RecordType AAAA -RecordTTL $TTL -LuaCredential $LuaCredential -Verbose
    } else {
        Write-Host "DNS entry for IP $_ exists"
    }
}


