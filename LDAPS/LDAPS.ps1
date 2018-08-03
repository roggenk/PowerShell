## Purpose: Retrieve Active Directory Domain Controller certificate properties
## Requirement: Dependency on PowerShell module 'ActiveDirectory' (WindowsFeature: RSAT-AD-PowerShell)

####################################################################################
function Get-ADDomainControllerCertifiate
{
    <#
        .SYNOPSIS
            Retrieves the LDAPS certificate properties.
        .PARAMETER ComputerName
            Specifies the Active Directory domain controller.
        .PARAMETER Domain
            Specifies the Active Directory DNS name.
        .PARAMETER Port
            LDAPS port for domain controller: 636 (default)
            LDAPS port for global catalog: 3269
        .DESCRIPTION
            The cmdlet 'Get-ADDomainControllerCertifiate' retrieves the LDAP over TSL/SSL certificate properties.
        .EXAMPLE
            Get-ADDomainControllerCertifiate -ComputerName DC01
        .EXAMPLE
            Get-ADDomainControllerCertifiate -ComputerName DC01,DC02 | Select ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertifiate DC01,DC02
        .EXAMPLE
            Get-ADDomainControllerCertifiate DC01 -Port 3269
        .EXAMPLE
            Get-ADDomainControllerCertifiate -Domain domain.local
        .EXAMPLE
            Get-ADDomainControllerCertifiate -Domain domain.local | Select-Object ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertifiate -Domain domain.local -Port 3269 | Select-Object ComputerName,Port,Subject,Thumbprint
    #>
    [Cmdletbinding(DefaultParameterSetName='ComputerName')]
    param(
        [Parameter(ParameterSetName='ComputerName',Mandatory,Position=0)]
        [Alias('CN')]
        [string[]]$ComputerName,

        [Parameter(ParameterSetName='DomainName',Mandatory,Position=0)]
        [string]$Domain,

        [string]$Port = "636"
    )

    if($ComputerName)
    { $DomainDCs = $ComputerName | Get-ADDomainController | Sort-Object -Property Name }

    if($Domain)
    { $DomainDCs = Get-ADDomainController -Server $Domain -Filter * | Sort-Object -Property Name }

    foreach($DC in $DomainDCs)
    {
	    $Server = $DC.HostName
        try 
	    {	
		    $Connection = New-Object System.Net.Sockets.TcpClient($Server,$Port)	
		    $TLSStream  = New-Object System.Net.Security.SslStream($Connection.GetStream())
		    # Try to validate certificate, break out if we don't
		    try 
            {
                $TLSStream.AuthenticateAsClient($Server)
                $Status = "Validated"
            } 
		    catch 
            { 
                $Status = "Validation Failed" 
                $Connection.Close 
                Break 
            }
		    #Grab the Cert and it's Basic Properties
		    $RemoteCert = New-Object system.security.cryptography.x509certificates.x509certificate2($TLSStream.get_remotecertificate())
		    # Advanced Properties
		    try { $SAN            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.17'}).Format(0)} catch{}
		    try { $AppPolicies    = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.21.10'}).Format(0)} catch{}
		    try { $V1TemplateName = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.20.2'}).Format(0)} catch{}
		    try { $V2TemplateName = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'}).Format(0)} catch{}
		    try { $SKI            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.14'}).Format(0)} catch{}
		    try { $AKI            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.35'}).Format(0)} catch{}
		    try { $BKU            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.15'}).Format(0)} catch{}
		    try { $EKU            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'}).Format(0)} catch{}
		    try { $CDP            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.31'}).Format(0)} catch{}
		    try { $AIA            = ($RemoteCert.Extensions | Where-Object {$_.Oid.Value -eq '1.3.6.1.5.5.7.1.1'}).Format(0)} catch{}
            # Object creation
            New-Object -TypeName PSObject -Property ([ordered]@{
                ComputerName       = $Server
                Port               = $Port
                Status             = $Status
                Subject            = $RemoteCert.Subject
                SAN                = $SAN
                FriendlyName       = $RemoteCert.FriendlyName
		        Issuer             = $RemoteCert.Issuer
		        ValidFrom          = $RemoteCert.NotBefore
		        ValidTo            = $RemoteCert.NotAfter
		        Thumbprint         = $RemoteCert.Thumbprint
                SignatureAlgorithm = $RemoteCert.SignatureAlgorithm.FriendlyName
                AIA                = $AIA
                AKI                = $AKI
                BKU                = $BKU
                CDP                = $CDP
                EKU                = $EKU
                SKI                = $SKI
                AppPolicies        = $AppPolicies
                V1TemplateName     = $V1TemplateName
                V2TemplateName     = $V2TemplateName
            })
	    }
	    catch { $Status = 'Connection Failed' }
	    finally { $Connection.Close() }	
    }
}
####################################################################################
function Get-ADLDAPUnsecureConnection
{
    <#
        .SYNOPSIS
            Retrieves unsecure LDAP connections from the 'Directory Service' eventlog.
        .DESCRIPTION
            The cmdlet 'Get-ADLDAPUnsecureConnection' retrieves unsecure LDAP connections from the 'Directory Service' eventlog with eventid 2889.
            Use -ComputerName to connect to a remote computer.
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01 | Format-Table
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01 -LastDays 5 | Format-Table
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01 -LastDays 10 | Out-GridView
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01 -LastDays 5 | Select-Object -Unique -Property IPAddress | Out-GridView
        .EXAMPLE
            Get-ADLDAPUnsecureConnection -Computer DC01 -LastDays 5 | Select-Object -Unique -Property IPAddress | Select-Object -Property IPAddress,@{Name='HostName';Expression={(Resolve-DnsName -Name $_.IPAddress -EA 0).NameHost}} | Sort-Object
    #>
    param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [int]$LastDays = 3
        )

    PROCESS
    {
        foreach($Computer in $ComputerName)
        {
            $Events = Get-WinEvent -FilterHashtable @{LogName="Directory Service";ID='2889';StartTime="$(Get-Date)";EndTime="$((Get-Date).AddDays(-$LastDays))"} -ComputerName $Computer -ErrorAction SilentlyContinue
            # $Events = Get-WinEvent -FilterHashtable @{LogName="Directory Service";ID='2889'} -ComputerName $Computer -ErrorAction SilentlyContinue
            foreach ($Event in $Events)
            {
                $XMlEvent = [xml]$Event.ToXml()  
                $Client = $XMlEvent.Event.EventData.Data
                #Object Creation
                $Object = New-Object -Type PSObject -Property ([ordered]@{
                            Source       = $Client[0]
                            IPAddress    = $Client[0].SubString(0,$Client[0].LastIndexOf(":"))
	                        Port         = $Client[0].SubString($Client[0].LastIndexOf(":")+1)
                            UserName     = $Client[1]
                            BindType     = switch ($Client[2]) { 0 {"Unsigned"} 1 {"Simple"} default {$Client[2]} }
                            TimeCreated  = $Event.TimeCreated
                            ComputerName = $Computer
                        })
                $Object
            }
        }
    }
}
####################################################################################
function Set-ADDomainControllerDiagnostics
{
    <#
        .SYNOPSIS
            Set the LDAP diagnostics logging level for the 'Directory Service' eventlog.
        .DESCRIPTION
            The cmdlet 'Set-ADDomainControllerDiagnostics' sets the LDAP diagnostics logging level.
            The information which is collected in the 'Directory Service' log can be used to diagnose and resolve possible problems or monitor the activity of Active Directory-related events on your server.

            Use -ComputerName to specify a remote computer.

            The logging levels are:
            - None, Disabled (0) - Only critical events and error events are logged. This is the default and should only be modified to investigate problems.
            - Minimal (1)        - Records very high-level events in the event log.
            - Basic, Enabled (2) - Records basic information.
            - Extensive (3)      - Records more detailed information than the lower levels, such as steps that are performed to complete a task.
            - Verbose (4)        - Records even more detailed information.
            - Internal (5)       - Records all events, including debug strings and configuration changes. A complete log of the service is recorded.

            For more detailed information, see https://support.microsoft.com/en-in/help/314980

        .EXAMPLE
            Set-ADDomainControllerDiagnostics -ComputerName DC01 -LDAP Enabled
        .EXAMPLE
            Set-ADDomainControllerDiagnostics -ComputerName DC01,DC02 -LDAP Disabled -Passthru
        .LINK
            Get-ADDomainControllerDiagnostics
    #>
    param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Enabled','Disabled','Minimal','Basic','Extensive','Verbose')]
        [string]$LDAP,

        [switch]$Passthru
    )
    $LogLevel = @{'None'='0';'Minimal'='1';'Basic'='2';'Extensive'='3';'Verbose'='4';'Internal'='5';'Disabled'='0';'Enabled'='2'}
    $ValueName = "16 LDAP Interface Events"
    $ValueData = $LogLevel[$LDAP]

    foreach($Computer in $ComputerName)
    {
        # Write registry value
        $BaseKey   = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer)
        $SubKey    = $BaseKey.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics",$true)
        $SubKey.SetValue($ValueName,$ValueData,[Microsoft.Win32.RegistryValueKind]::DWORD)
        # Retrieve existing value when parameter '-Passthru' is specified
        if($Passthru) { Get-ADDomainControllerDiagnostics -ComputerName $Computer }
    }
} 
####################################################################################
function Get-ADDomainControllerDiagnostics
{
    <#
        .SYNOPSIS
            Retrieves the LDAP diagnostics logging level for the 'Directory Service' eventlog.
        .DESCRIPTION
            The cmdlet 'Get-ADDomainControllerDiagnostics' retrieves the LDAP diagnostics logging level 
            The information which is collected in the 'Directory Service' log can be used to diagnose and resolve possible problems or monitor the activity of Active Directory-related events on your server.

            Use -ComputerName to specify a remote computer.

        .EXAMPLE
            Get-ADDomainControllerDiagnostics -ComputerName DC01

            16 LDAP Interface Events ComputerName
            ------------------------ ------------
                                   2 DC01     

        .EXAMPLE
            Get-ADDomainControllerDiagnostics -ComputerName DC01,DC02,DC03,DC04

            16 LDAP Interface Events ComputerName
            ------------------------ ------------
                                   2 DC01     
                                   2 DC02     
                                   0 DC03     
                                   2 DC04
        .LINK
            Set-ADDomainControllerDiagnostics
    #>
    param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    foreach($Computer in $ComputerName)
    {
        # Retrieve registry value
        $BaseKey   = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer)
        $SubKey    = $BaseKey.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics",$true)
        $ValueName = "16 LDAP Interface Events"
        try { $ValueData = $SubKey.GetValue($ValueName) } catch { Write-Verbose "Unable to retrieve registry value on computer '$Computer'" ; }
        # Create object 
        New-Object -TypeName PSObject -Property ([ordered]@{
            "16 LDAP Interface Events" = $ValueData
            ComputerName               = $Computer
        })
        # Cleanup
        Remove-Variable -Name ValueData -Force -ErrorAction SilentlyContinue
    }
}
####################################################################################
