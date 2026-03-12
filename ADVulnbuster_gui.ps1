<#
CREATOR: JOEL C. LOPEZ AKA K0B4KS AKA JOCAROLO
.SYNOPSIS
Application Name: AD VULN BUSTER
.DESCRIPTION
Scans Active Directory for vulnerabilities and misconfigurations.
Analyzes escalation paths starting from a user or group.
Extracts a complete report in HTML format of the AD status.
Detects and mitigates DCsync attacks in real time.

.IMPORTANT INFORMATION
For the application to work, the executable must be located in the c:\adaudit\vulnbuster folder.

< AD VULN BUSTER IS A REGISTERED TRADEMARK. ITS USE OR DISSEMINATION IS PROHIBITED WITHOUT THE EXPLICIT PERMISSION OF THE CREATOR >
<USE THIS APPLICATION AT YOUR OWN RISK AND ONLY FOR ETHICAL PURPOSE. WE ARE NOT RESPONSIBLE FOR ANY BAD USE>
<IF YOU ARE GOING TO USE THIS APPLICATION IN A PRODUCTION ENVIRONMENT, PLEASE BE SURE TO TEST IT IN A PRE-PRODUCTION ENVIRONMENT FIRST.>


  # ==============================================================================
    # VulnBuster AD Audit Report 
    #Latest improvements as of 11/05/2025
    # - The part of the console output that shows
    # the final table with (Category/Count/Severity/MITRE/Mitigation) has been restored.
    # - The "GPO Misconfigurations" (old) category has been removed
    # to avoid confusion with 0 results.
    # - The integration of Extended GPO Analysis and GPOAdditionalAnalysis is maintained
    # with its 3 categories: GPO Restricted Groups, GPO LAN Manager Auth, GPO NetEncryption (DES).
    # The analysis of all ACLs has been removed from the final report; it was significantly slowing down the extraction.
    # (The ACLs port has been moved to the ACL Reports button and updated to only extract ACLs from OUs.)
    # The Bloodhound Json integration has been removed. 
    # Escalation paths function improved with export csv function 
    # ==============================================================================

    #Next updates coming soon 

    #Entra ID Audit
    #Azure Resources Audit 
#>

###### FALSE NOEXIT GUI ###############################

Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
"@ -Name "Win32Console" -Namespace "Win32Functions"

Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindow" -Namespace "Win32Functions"

$consoleWindow = [Win32Functions.Win32Console]::GetConsoleWindow()
if ($consoleWindow -ne [IntPtr]::Zero) {
    # 0 = SW_HIDE (ocultar la ventana)
    [Win32Functions.Win32ShowWindow]::ShowWindow($consoleWindow, 0)
}


#####################  REGIONS ############################################################


#region ACLReport


$aclScript = @'
Import-Module ActiveDirectory

function Get-Riesgo {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Rights
    )
    switch ($Rights) {
        'GenericAll' { return 'High' }
        'GenericRead' { return 'Down' }
        default       { return 'Medium' }
    }
}

function Get-ACLClassification {
    $Results = @()

    $Domain = (Get-ADDomain).DistinguishedName
 
    $Objects = Get-ADObject -Filter * -SearchBase $Domain -Properties ntSecurityDescriptor
    foreach ($Object in $Objects) {
        $ACLs = $Object.nTSecurityDescriptor.Access
        foreach ($ACL in $ACLs) {
            $Riesgo = Get-Riesgo -Rights $ACL.ActiveDirectoryRights
            $Entry = [PSCustomObject]@{
                ObjectName         = $Object.Name
                DistinguishedName  = $Object.DistinguishedName
                IdentityReference  = $ACL.IdentityReference
                AccessControlType  = $ACL.AccessControlType
                Rights             = $ACL.ActiveDirectoryRights
                InheritanceFlags   = $ACL.InheritanceFlags
                Riesgo             = $Riesgo
            }
            $Results += $Entry
        }
    }

    $allOUs = Get-ADOrganizationalUnit -SearchBase $Domain -Filter * -Properties nTSecurityDescriptor
    foreach ($ou in $allOUs) {
        $ACLs = $ou.nTSecurityDescriptor.Access
        foreach ($ACL in $ACLs) {
            $Riesgo = Get-Riesgo -Rights $ACL.ActiveDirectoryRights
            $Entry = [PSCustomObject]@{
                ObjectName         = $ou.Name
                DistinguishedName  = $ou.DistinguishedName
                IdentityReference  = $ACL.IdentityReference
                AccessControlType  = $ACL.AccessControlType
                Rights             = $ACL.ActiveDirectoryRights
                InheritanceFlags   = $ACL.InheritanceFlags
                Riesgo             = $Riesgo
            }
            $Results += $Entry
        }
    }

    $OutputPath = 'C:\adaudit\advulnbuster\ACL_Report.csv'
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Reporte generado: $OutputPath" -ForegroundColor Green
}

function RunACLReport {
    Get-ACLClassification
}

# Llamada final
RunACLReport
'@


#endregion ACLReport

#region DcSync


$checkDcsyncScript = @'
Import-Module ActiveDirectory

Write-Host "Checking DCSync RDC permissions for users and groups" -ForegroundColor Green

function Check-ADPermission(
    [System.DirectoryServices.DirectoryEntry]$entry, 
    [string]$subject, 
    [string[]]$permissions,
    [string]$subjectType
) {
    $dse = [ADSI]"LDAP://Rootdse"
    $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
    $hasPermission = $false

    foreach ($permission in $permissions) {
        $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }
        if ($right -ne $null) {
            $perms = $entry.psbase.ObjectSecurity.Access |
                Where-Object { $_.IdentityReference -like "*$subject" } |
                Where-Object { $_.ObjectType -eq [GUID]$right.RightsGuid.Value }
            if ($perms -ne $null) {
                Write-Host "$subjectType '$subject' has the '$permission' permission on '$($entry.distinguishedName)'" -ForegroundColor Green
                $hasPermission = $true
            }
        }
    }
    
    return $hasPermission
}

$permissions = @("Replicating Directory Changes", "Replicating Directory Changes All")
$userList = @()
$groupList = @()

$dse = [ADSI]"LDAP://Rootdse"
$users = Get-ADUser -Filter * -Property sAMAccountName
$groups = Get-ADGroup -Filter * -Property Name

foreach ($user in $users) {
    $userName = $user.sAMAccountName
    $entries = @(
        [ADSI]("LDAP://" + $dse.defaultNamingContext), 
        [ADSI]("LDAP://" + $dse.configurationNamingContext)
    )
    foreach ($entry in $entries) {
        if (Check-ADPermission $entry $userName $permissions "User") {
            $userList += $userName
        }
    }
}

foreach ($group in $groups) {
    $groupName = $group.Name
    foreach ($entry in $entries) {
        if (Check-ADPermission $entry $groupName $permissions "Group") {
            $groupList += $groupName
        }
    }
}

if ($userList.Count -gt 0) {
    $userList | Select-Object @{Name="Username"; Expression={$_}} | Export-Csv -Path "C:\adaudit\UsersWithPermissions.csv" -NoTypeInformation
    Write-Host "Exported users with permissions to 'c:\adaudit\UsersWithPermissions.csv'" -ForegroundColor Cyan
} else {
    Write-Host "No users with specified permissions found to export." -ForegroundColor Yellow
}

# Se eliminan las líneas de pausa para que se ejecute sin esperar entrada:
# Write-Host "`nPress any key return menu..."
# [System.Console]::ReadKey($true) | Out-Null
'@

$restoreDcsyncScript = @'
Function RestoreDcsync {
    # Especifica la ruta del archivo CSV para usuarios y grupos
    $userCsvPath = "C:\adaudit\UsersWithPermissions.csv"

    # Carga los usuarios y los grupos desde el CSV
    $users = Import-Csv -Path $userCsvPath

    # Obtiene el objeto de dominio AD
    $domainDistinguishedName = (Get-ADDomain).DistinguishedName
    $ADObject = [ADSI]("LDAP://$domainDistinguishedName")

    # Lista de GUIDs para los permisos que se aplicarán
    $guids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # Replicating Directory Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   # Replicating Directory Changes All
        "89e95b76-444d-4c62-991a-0facbeda640c"    # Replication Synchronization
    )

    # Función para aplicar permisos
    function Apply-DCSyncPermissions($subject, $subjectType) {
        $sid = $subject.SID
        foreach ($guid in $guids) {
            $objectGuid = New-Object Guid $guid
            $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", $objectGuid)
            $ADObject.psbase.ObjectSecurity.AddAccessRule($ACEGetChanges)
        }
        $ADObject.psbase.CommitChanges()
        Write-Host "Restored DCSync to: $($subject.SamAccountName) ($subjectType)" -ForegroundColor Green
    }

    # Restaurar permisos para usuarios
    foreach ($user in $users) {
        $adUser = Get-ADUser -Identity $user.Username -ErrorAction SilentlyContinue
        if ($adUser -ne $null) {
            Apply-DCSyncPermissions $adUser "User"
            Set-ADUser $adUser -Description "Replication Account"  # Establece la descripción del usuario en AD
        }
        else {
            Write-Host "Usuario no encontrado: $($user.Username)" -ForegroundColor Yellow
        }
    }
}

# Ejecuta la función sin esperar input adicional
RestoreDcsync
'@

$removeDcsyncScript = @'
Import-Module ActiveDirectory 

function Remove-ADPermission(
    [System.DirectoryServices.DirectoryEntry]$entry, 
    [string]$subject,
    [string[]]$permissions,
    [string]$subjectType
)
{
    $dse = [ADSI]"LDAP://Rootdse"
    $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)

    foreach ($permission in $permissions) {
        $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }
        if ($right -ne $null) {
            $rightsGuid = [GUID]$right.RightsGuid.Value
            $perms = $entry.psbase.ObjectSecurity.Access |
                Where-Object { $_.IdentityReference -like "*$subject" -and $_.ObjectType -eq $rightsGuid }
            foreach ($perm in $perms) {
                $isRemoved = $entry.psbase.ObjectSecurity.RemoveAccessRule($perm)
                if ($isRemoved) {
                    Write-Host "Successfully removed '$permission' permission from $subjectType '$subject' on '$($entry.distinguishedName)'" -ForegroundColor Green
                }
                else {
                    Write-Host "Failed to remove '$permission' permission from $subjectType '$subject' on '$($entry.distinguishedName)'" -ForegroundColor Red
                }
            }
            $entry.psbase.CommitChanges()
        }
        else {
            Write-Warning "Permission '$permission' not found."
        }
    }
}

# Globals
$permissions = @("Replicating Directory Changes", "Replicating Directory Changes All", "Replicating Directory Changes In Filtered Set")
$excludedAccounts = @( 
    'Administrators', 
    'Domain Controllers', 
    'Read-only Domain Controllers', 
    'Enterprise Read-only Domain Controllers'
)

# Main
$dse = [ADSI]"LDAP://Rootdse"
$csvUsers = Import-Csv -Path "C:\temp\UsersWithPermissions.csv"
$csvGroups = Import-Csv -Path "C:\temp\GroupsWithPermissions.csv"

foreach ($user in $csvUsers) {
    $userName = $user.Username
    if ($excludedAccounts -notcontains $userName -and $userName -notmatch "^MSOL") {
        $entries = @(
            [ADSI]("LDAP://" + $dse.defaultNamingContext),
            [ADSI]("LDAP://" + $dse.configurationNamingContext)
        )
        foreach ($entry in $entries) {
            Remove-ADPermission $entry $userName $permissions "User"
        }
    }
    else {
        Write-Host "Skipping excluded account: $userName" -ForegroundColor Yellow
    }
}

foreach ($group in $csvGroups) {
    $groupName = $group.GroupName
    if ($excludedAccounts -notcontains $groupName -and $groupName -notmatch "^MSOL") {
        $entries = @(
            [ADSI]("LDAP://" + $dse.defaultNamingContext),
            [ADSI]("LDAP://" + $dse.configurationNamingContext)
        )
        foreach ($entry in $entries) {
            Remove-ADPermission $entry $groupName $permissions "Group"
        }
    }
    else {
        Write-Host "Skipping excluded group: $groupName" -ForegroundColor Yellow
    }
}
'@

#endregion Dcsync

#region kerberos

$detectGoldenTicketScript = @'
function Detect-GoldenTicket {
    Write-Host "Analyzing Kerberos TGT (4768)..." -ForegroundColor Yellow

    # Buscar eventos 4768 en el log de seguridad
    $events = Get-WinEvent -LogName "Security" -FilterXPath "*[System/EventID=4768]" -ErrorAction SilentlyContinue
    $found = $false  # Variable para rastrear si se encuentra un ticket sospechoso

    foreach ($event in $events) {
        $message = $event.Message

        # Detectar patrones sospechosos
        if ($message -match "krbtgt" -and $message -match "0x0") {
            # Validar si la dirección IP está vacía o no esperada
            if ($message -match "Client Address:\s+(-|0\.0\.0\.0)") {
                Write-Host "[ALERT] Golden Ticket Detected:" -ForegroundColor Red
                Write-Host $message
                $found = $true
            }
        }
    }

    if (-not $found) {
        Write-Host "Scan completed: no suspicious tickets detected." -ForegroundColor Green
    } else {
        Write-Host "Scan completed: suspicious tickets found." -ForegroundColor Red
    }

    # Ejecutar el comando klist y capturar la salida
    $klistOutput = klist | Out-String

    # Verificar si hay tickets Kerberos
    if ($klistOutput -match "No tickets available") {
        Write-Host "No ticket kerberos Active." -ForegroundColor Green
    } else {
        # Filtrar líneas con tickets
        $tickets = $klistOutput -split "`n" | Where-Object { $_ -match "^[\s]*\d" }

        # Obtener la fecha actual y calcular el límite de 10 años
        $currentDate = Get-Date
        $tenYearsAgo = $currentDate.AddYears(-10)

        $foundOldTicket = $false

        # Revisar cada ticket
        foreach ($ticket in $tickets) {
            # Extraer fecha de emisión (suponiendo formato estándar MM/dd/yyyy)
            if ($ticket -match "\s+(\d{1,2}/\d{1,2}/\d{4})\s") {
                $ticketDate = [datetime]::ParseExact($matches[1], "MM/dd/yyyy", $null)

                # Verificar si el ticket es de hace 10 años o más
                if ($ticketDate -le $tenYearsAgo) {
                    Write-Host "Old ticket found: $ticket" -ForegroundColor Red
                    $foundOldTicket = $true
                }
            }
        }

        if (-not $foundOldTicket) {
            Write-Host "No Golden Ticket detected." -ForegroundColor Green
        }
    }
}

# Llamamos a la función para que se ejecute
Detect-GoldenTicket
'@


$detectSilverTicketScript = @'
function Detect-SilverTicket {
    Write-Host "Analyzing Kerberos TGS (4769)..." -ForegroundColor Yellow

    # Buscar eventos 4769 en el log de seguridad
    $events = Get-WinEvent -LogName "Security" -FilterXPath "*[System/EventID=4769]" -ErrorAction SilentlyContinue
    $found = $false  # Variable para rastrear si se encuentra un ticket sospechoso

    foreach ($event in $events) {
        $message = $event.Message

        # Detectar patrones sospechosos (servicios sensibles o cuentas inusuales)
        if ($message -match "Service Name:\s+(CIFS|HOST|MSSQL|LDAP)" -and $message -match "0x0") {
            # Validar si hay una dirección IP sospechosa
            if ($message -match "Client Address:\s+(-|0\.0\.0\.0)") {
                Write-Host "[ALERT] Posible Silver Ticket detected:" -ForegroundColor Red
                Write-Host $message
                $found = $true
            }
        }
    }

    if (-not $found) {
        Write-Host "Check completed: No Silver ticket Detected" -ForegroundColor Green
    } else {
        Write-Host "Check completed: Posible ticket Detected" -ForegroundColor Red
    }
}

# Llamamos a la función para que se ejecute automáticamente
Detect-SilverTicket
'@

$detectDiamondTicketScript = @'
function Detect-DiamondTicket {
    # Configuración inicial
    $StartDate = (Get-Date).AddDays(-7)  # Ajusta la ventana de tiempo si lo deseas
    $OutputFile = "$env:USERPROFILE\Desktop\DiamondTicketCheck.csv"  # Ruta del archivo CSV

    Write-Host "Analyzing kerberos event... Checking Posible Diamond Tickets..." -ForegroundColor Cyan

    # Extraer eventos Kerberos relevantes
    $Events = Get-EventLog -LogName Security -After $StartDate | Where-Object {
        $_.EventID -in @(4624, 4768, 4769)  # Eventos de autenticación y tickets
    }

    if ($Events.Count -eq 0) {
        Write-Host "No events found in specified period." -ForegroundColor Green
        return
    }

    # Analizar eventos sospechosos
    $SuspectEvents = @()

    foreach ($Event in $Events) {
        $Message = $Event.Message

        # Indicadores de posible Diamond Ticket
        if ($Message -match "krbtgt" -or $Message -match "TGT") {
            $SuspectEvents += [PSCustomObject]@{
                EventID       = $Event.EventID
                TimeGenerated = $Event.TimeGenerated
                Message       = $Message
            }
        }

        # Detectar solicitudes TGT/TGS anómalas
        if ($Event.EventID -eq 4769) {
            if ($Message -match "Cifrado:.*RC4" -or $Message -match "Encryotion:.*des-cbc-crc") {
                $SuspectEvents += [PSCustomObject]@{
                    EventID       = $Event.EventID
                    TimeGenerated = $Event.TimeGenerated
                    Message       = $Message
                }
            }
        }

        # Analizar entradas de autenticación sospechosas
        if ($Event.EventID -eq 4624) {
            if ($Message -match "Logon session:.*Type: 3" -and $Message -match "Name account:.*krbtgt") {
                $SuspectEvents += [PSCustomObject]@{
                    EventID       = $Event.EventID
                    TimeGenerated = $Event.TimeGenerated
                    Message       = $Message
                }
            }
        }
    }

    # Mostrar resultados por pantalla y exportar a CSV
    if ($SuspectEvents.Count -gt 0) {
        Write-Host "Suspicious events detected:" -ForegroundColor Yellow

        foreach ($Event in $SuspectEvents) {
            Write-Host "-------------------------------------" -ForegroundColor White
            Write-Host "Event ID: $($Event.EventID)" -ForegroundColor Yellow
            Write-Host "Date and hour: $($Event.TimeGenerated)" -ForegroundColor Cyan
            Write-Host "Message: $($Event.Message)" -ForegroundColor Gray
            Write-Host "-------------------------------------"
        }

        Write-Host "Exporting events to CSV..." -ForegroundColor Yellow
        $SuspectEvents | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    }
    else {
        Write-Host "No Diamond ticket indicators found." -ForegroundColor Green
    }

    # Recomendaciones adicionales
    Write-Host "`nSugerencias para mitigación:" -ForegroundColor Cyan
    Write-Host "- Cambiar la contraseña de la cuenta 'krbtgt' si sospechas de actividad." -ForegroundColor White
    Write-Host "- Monitorear claves de cifrado débiles como RC4 o DES en configuraciones de Kerberos." -ForegroundColor White
    Write-Host "- Usar herramientas SIEM para monitoreo avanzado." -ForegroundColor White
}

# Ejecutar la función automáticamente
Detect-DiamondTicket
'@

#endregion Kerberos

#region escalationPaths

$escalationPathFullScript = @'
function escalation_path_full {

    Import-Module ActiveDirectory

    ################################################################################
    # Escaltion-Full.ps1
    # - Show scalation paths from group
    # 
    ################################################################################

    Clear-Host
    Write-Host "===== Ad Vulnbuster scalation Paths =====" -ForegroundColor Cyan

    
    $StartIdentity = Read-Host "Enter user or group source:"
    if (-not $StartIdentity) {
        Write-Host "ERROR: Enter group or user source." -ForegroundColor Red
        return
    }

    
    Write-Host "[*] Collection users, groups and computers..." -ForegroundColor Yellow
    $AllUsers     = Get-ADUser     -Filter * -Properties SamAccountName,DistinguishedName,MemberOf
    $AllGroups    = Get-ADGroup    -Filter * -Properties SamAccountName,DistinguishedName,MemberOf
    $AllComputers = Get-ADComputer -Filter * -Properties SamAccountName,DistinguishedName

    $AllADObjects = $AllUsers + $AllGroups + $AllComputers

    # Mapa DistinguisehdName -> SamAccountName
    $DNtoSam = @{}
    foreach ($obj in $AllADObjects) {
        if ($obj.DistinguishedName -and $obj.SamAccountName) {
            $DNtoSam[$obj.DistinguishedName] = $obj.SamAccountName
        }
    }

    # grafo structure
    $Graph = @{}

    function Add-Edge($source, $target, $relation) {
        if (-not $Graph.ContainsKey($source)) {
            $Graph[$source] = New-Object System.Collections.Generic.List[object]
        }
        # Evitar duplicados exactos
        if (-not ($Graph[$source] | Where-Object { $_.Target -eq $target -and $_.Relation -eq $relation })) {
            $edge = [PSCustomObject]@{
                Target   = $target
                Relation = $relation
            }
            $Graph[$source].Add($edge)
        }
    }

    Write-Host "[*] Generating relations MemberOf..." -ForegroundColor Yellow
    foreach ($obj in $AllADObjects) {
        $fromSam = $obj.SamAccountName
        if ($fromSam -and $obj.MemberOf) {
            foreach ($dnGroup in $obj.MemberOf) {
                if ($DNtoSam.ContainsKey($dnGroup)) {
                    $toSam = $DNtoSam[$dnGroup]
                    Add-Edge $fromSam $toSam "MemberOf"
                }
            }
        }
    }

    Write-Host "[*] Analyzing ACLs (GenericAll, WriteDACL, ...)" -ForegroundColor Yellow
    function Map-AclRelations {
        param(
            [string]$DN,
            [string]$SamAcct
        )
        try {
            $acl = Get-Acl "AD:\$DN" -ErrorAction Stop
        } catch {
            return
        }

        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match 'NT AUTHORITY|BUILTIN') {
                continue
            }
            $principal = $ace.IdentityReference.Value
            if ($principal -match '\\') {
                $principal = $principal.Split('\')[1]
            }

            $rights = $ace.ActiveDirectoryRights
            if ($rights -match "GenericAll|WriteDACL|WriteOwner|GenericWrite") {
                Add-Edge $principal $SamAcct $rights.ToString()
            }

            # ForceChangePassword
            if ($ace.ObjectType -eq "ab721a53-1e2f-11d0-9819-00aa0040529b") {
                Add-Edge $principal $SamAcct "ForceChangePassword"
            }

            # DCSync
            if ($ace.ObjectType -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ab-9c07-11d1-f79f-00c04fc2dcd2") {
                Add-Edge $principal $SamAcct "DCSync"
            }
        }
    }

    foreach ($obj in $AllADObjects) {
        if ($obj.DistinguishedName -and $obj.SamAccountName) {
            Map-AclRelations -DN $obj.DistinguishedName -SamAcct $obj.SamAccountName
        }
    }

    Write-Host "[*] Revisando Resource-Based Constrained Delegation (RBCD)..." -ForegroundColor Yellow
    function Check-RBCD {
        param(
            [string]$DN,
            [string]$Sam
        )
        try {
            $val = Get-ADObject -Identity $DN -Properties msDS-AllowedToActOnBehalfOfOtherIdentity -ErrorAction Stop
        } catch {
            return
        }
        $sdBytes = $val."msDS-AllowedToActOnBehalfOfOtherIdentity"
        if (-not $sdBytes) {
            return
        }

        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        try {
            $sd.SetSecurityDescriptorBinaryForm($sdBytes)
        } catch {
            return
        }

        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
            $acct = $ace.IdentityReference.Value
            if ($acct -match '\\') {
                $acct = $acct.Split('\')[1]
            }
            $rights = $ace.ActiveDirectoryRights
            if ($rights -match "WriteOwner|WriteDacl|GenericAll|GenericWrite|ExtendedRight|FullControl") {
                Add-Edge $acct $Sam "RBCD"
            }
        }
    }

    foreach ($obj in $AllComputers) {
        if ($obj.DistinguishedName -and $obj.SamAccountName) {
            Check-RBCD -DN $obj.DistinguishedName -Sam $obj.SamAccountName
        }
    }

    Write-Host "[*] Finding paths from '$StartIdentity'." -ForegroundColor Green

    function Get-SamAccountName($name) {
        try {
            $u = Get-ADUser -Identity $name -ErrorAction Stop
            return $u.SamAccountName
        } catch { }
        try {
            $g = Get-ADGroup -Identity $name -ErrorAction Stop
            return $g.SamAccountName
        } catch { }
        try {
            $c = Get-ADComputer -Identity $name -ErrorAction Stop
            return $c.SamAccountName
        } catch { }
        if ($Graph.ContainsKey($name)) {
            return $name
        }
        return $null
    }

    $startSam = Get-SamAccountName $StartIdentity
    if (-not $startSam) {
        Write-Host "ERROR: Cant' resolve '$StartIdentity' en AD." -ForegroundColor Red
        return
    }

    Write-Host "[*] BFS from '$startSam' Discovering paths..." -ForegroundColor Cyan

    $queue   = New-Object System.Collections.Generic.Queue[object]
    $visited = New-Object System.Collections.Generic.HashSet[string]
    $paths   = @{}

    $paths[$startSam] = @(@{ Node=$startSam; Relation=$null })
    $queue.Enqueue($startSam)
    $visited.Add($startSam) | Out-Null

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if ($Graph.ContainsKey($current)) {
            foreach ($edge in $Graph[$current]) {
                $neighbor = $edge.Target
                $relation = $edge.Relation
                if (-not $visited.Contains($neighbor)) {
                    $visited.Add($neighbor) | Out-Null
                    $oldPath = $paths[$current]
                    $newPath = $oldPath + @(@{ Node=$neighbor; Relation=$relation })
                    $paths[$neighbor] = $newPath
                    $queue.Enqueue($neighbor)
                }
            }
        }
    }

     Write-Host "`n=== SHOWING ALL ROUTES FROM '$startSam' ===" -ForegroundColor Green

    # ----- NUEVO: coleccionaremos los resultados para exportarlos -----
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($dest in $paths.Keys | Sort-Object) {
        if ($dest -ne $startSam) {
            $chain  = $paths[$dest]
            $output = ""
            for ($i = 0; $i -lt $chain.Count; $i++) {
                $n = $chain[$i].Node
                $r = $chain[$i].Relation
                if ($i -eq 0) {
                    $output = "$n"
                } else {
                    $output += " -($r)-> $n"
                }
            }

            # Imprimimos por pantalla como antes
            Write-Host $output

            # ----- NUEVO: añadimos el dato a la lista -----
            $results.Add([PSCustomObject]@{
                Start       = $startSam
                Destination = $dest
                Path        = $output
            })
        }
    }

    # ----- Export CSV-----
    $csvPath = 'C:\adaudit\advulnbuster\escalation_paths.csv'
    try {
        $results |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[*] Results successfully exported to '$csvPath'." -ForegroundColor Green
    } catch {
        Write-Host "`n[!] Could not export the CSV: $_" -ForegroundColor Red
    }

    Write-Host "`n===== Process completed. =====" -ForegroundColor Cyan

    
}

# call function brom button
escalation_path_full
'@
#endregion escalation?Paths


#region reporte
$reporteScript = @'
function reporte {
    # ==============================================================================
    # VulnBuster AD Audit Report 
    #Latest improvements as of 11/05/2025
    # - The part of the console output that shows
    # the final table with (Category/Count/Severity/MITRE/Mitigation) has been restored.
    # - The "GPO Misconfigurations" (old) category has been removed
    # to avoid confusion with 0 results.
    # - The integration of Extended GPO Analysis and GPOAdditionalAnalysis is maintained
    # with its 3 categories: GPO Restricted Groups, GPO LAN Manager Auth, GPO NetEncryption (DES).
    # The analysis of all ACLs has been removed from the final report; it was significantly slowing down the extraction.
    # (The ACLs port has been moved to the ACL Reports button and updated to only extract ACLs from OUs.)
    # ==============================================================================
    
    # ---------------------------------------------------------------------------------
    # 1) Load the ActiveDirectory Module
    # ---------------------------------------------------------------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Loading ActiveDirectory module" -PercentComplete 0
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    # ---------------------------------------------------------------------------------
    # 2) Dictionaries for Mitigations, Severity and MITRE
    # ---------------------------------------------------------------------------------
    $vulnMitigations = @{
        "SPN Privileged (adminCount=1)"          = "Limit privileged accounts with SPN. Rotate passwords and audit their use."
        "AS-REP ROAST adminCount=1"              = "Disable DONT_REQ_PREAUTH for admin accounts. Strengthen passwords."
        "All SPN Users"                          = "Accounts with assigned SPN (possible service accounts)."
        "All AS-REP Roastable Users"             = "Disable DONT_REQ_PREAUTH when possible. Strengthen passwords."
        "Unconstrained Users"                    = "Remove unconstrained delegation from user accounts. Prefer constrained delegation."
        "Constrained Users"                      = "Review msDS-AllowedToDelegateTo, limit delegations to essentials."
        "Constrained Computers"                  = "Reduce delegations on computers. Review unnecessary SPNs."
        "Unconstrained DCs"                      = "Avoid DCs with unconstrained delegation. Very high escalation risk."
        "Unconstrained Computers (not DC)"       = "Remove TRUSTED_FOR_DELEGATION on non-required computers. Use constrained delegation."
        "Computers with RBCD"                    = "Review msDS-AllowedToActOnBehalfOfOtherIdentity, clear unwanted values."
        "Potential RBCD (WriteDACL/WriteOwner)"  = "Restrict ACLs that allow WriteOwner/WriteDACL on computers. Prevent unauthorized RBCD."
        "Non-admin DCSYNC"                       = "Remove DS-Replication-Get-Changes(ALL) from non-admins. Keep it limited to Domain/Enterprise Admins."
        "LAPS Readers"                           = "Restrict who can read ms-Mcs-AdmPwd (LAPS). Review groups with ReadProperty."
        "Interesting ACL (users/groups)"         = "Review ACLs that allow WriteOwner, ForceChangePassword, etc. Delegate only to trusted roles."
        "Functional Level"                       = "Update the domain/forest functional level to the latest possible."
        "Password Policy Weak"                   = "Review minimum password length, complexity, expiration, lockout, etc."
        "RC4 Encryption Kerberos"                = "Disable RC4 in Kerberos. Use AES and TLS 1.2/1.3."
        "LDAP signing not enforced"              = "Enable LDAP signing. Ensure a secure LDAP channel."
        "Sysvol Permissions"                     = "Restrict permissions on SYSVOL. Prevent unauthorized write access."
        "Privileged Accounts Analysis"           = "Review groups and membership in Protected Users."
        "Password Policy Details"                = "Specific values from the Default Domain Policy password settings."
        "Kerberoastable Accounts"                = "Accounts with SPN (not 'krbtgt' nor adminCount=1). Check for strong passwords."
        "gMSA Misconfigurations"                 = "Configure PrincipalsAllowedToRetrieveManagedPassword appropriately."
        "Privileged Group Misconfigurations"     = "Restrict modification permissions in privileged groups."
        "Service Accounts Analysis"              = "Service accounts (with SPN). Check for non-expiring passwords, asrep, etc."
        "Attack Vectors Summary"                 = "Global list of detected attack vectors."
        "AdminSDHolder Control"                  = "Review unexpected ACEs in AdminSDHolder and modification date."

        # Categorías GPO integradas
        "GPO Restricted Groups"                  = "Revisar configuración de grupos restringidos en GPO."
        "GPO LAN Manager Auth"                   = "Deshabilitar o restringir LAN Manager para evitar LM hashing."
        "GPO NetEncryption (DES)"                = "Deshabilitar DES_CBC_CRC y DES_CBC_MD5. Usar AES o algoritmos modernos."
    }
    
    $vulnSeverity = @{
        "SPN Privileged (adminCount=1)"          = "High"
        "AS-REP ROAST adminCount=1"              = "High"
        "All SPN Users"                          = "Medium"
        "All AS-REP Roastable Users"             = "Medium"
        "Unconstrained Users"                    = "High"
        "Constrained Users"                      = "Medium"
        "Constrained Computers"                  = "Medium"
        "Unconstrained DCs"                      = "Crítical"
        "Unconstrained Computers (not DC)"       = "High"
        "Computers with RBCD"                    = "High"
        "Potential RBCD (WriteDACL/WriteOwner)"  = "High"
        "Non-admin DCSYNC"                       = "Crítical"
        "LAPS Readers"                           = "Medium"
        "Interesting ACL (users/groups)"         = "Medium"
        "Functional Level"                       = "Medium"
        "Password Policy Weak"                   = "High"
        "RC4 Encryption Kerberos"                = "Medium"
        "LDAP signing not enforced"              = "High"
        "Sysvol Permissions"                     = "Medium"
        "Privileged Accounts Analysis"           = "Info"
        "Password Policy Details"                = "Info"
        "Kerberoastable Accounts"                = "Medium"
        "gMSA Misconfigurations"                 = "Medium"
        "Privileged Group Misconfigurations"     = "High"
        "Service Accounts Analysis"              = "Medium"
        "Attack Vectors Summary"                 = "Info"
        "AdminSDHolder Control"                  = "High"

        # Categorías GPO integradas
        "GPO Restricted Groups"                  = "Medium"
        "GPO LAN Manager Auth"                   = "Medium"
        "GPO NetEncryption (DES)"                = "Medium"
    }
    
    $vulnMitre = @{
        "SPN Privileged (adminCount=1)"          = "T1558.003"
        "AS-REP ROAST adminCount=1"              = "T1558.004"
        "All SPN Users"                          = "T1558.003"
        "All AS-REP Roastable Users"             = "T1558.004"
        "Unconstrained Users"                    = "T1550.002"
        "Constrained Users"                      = "T1550.003"
        "Constrained Computers"                  = "T1550.003"
        "Unconstrained DCs"                      = "T1550.003"
        "Unconstrained Computers (not DC)"       = "T1550.003"
        "Computers with RBCD"                    = "T1550.001"
        "Potential RBCD (WriteDACL/WriteOwner)"  = "T1550.001"
        "Non-admin DCSYNC"                       = "T1003.006"
        "LAPS Readers"                           = "T1003"
        "Interesting ACL (users/groups)"         = "N/A"
        "Functional Level"                       = "N/A"
        "Password Policy Weak"                   = "T1201"
        "RC4 Encryption Kerberos"                = "T1558"
        "LDAP signing not enforced"              = "T1557.002"
        "Sysvol Permissions"                     = "T1059.003"
        "Privileged Accounts Analysis"           = "N/A"
        "Password Policy Details"                = "N/A"
        "Kerberoastable Accounts"                = "T1558.003"
        "gMSA Misconfigurations"                 = "N/A"
        "Privileged Group Misconfigurations"     = "N/A"
        "Service Accounts Analysis"              = "N/A"
        "Attack Vectors Summary"                 = "N/A"
        "AdminSDHolder Control"                  = "N/A"

        # Categorías GPO integradas
        "GPO Restricted Groups"                  = "N/A"
        "GPO LAN Manager Auth"                   = "N/A"
        "GPO NetEncryption (DES)"                = "N/A"
    }
    
    # ---------------------------------------------------------------------------------
    # 3) Support Functions
    # ---------------------------------------------------------------------------------
    function Get-LastLogonInfo {
        param([DateTime]$LastLogonTime)
        if (-not $LastLogonTime -or $LastLogonTime -eq [DateTime]::MinValue) { return "NEVER" }
        $days = (Get-Date) - $LastLogonTime
        if     ($days.TotalDays -lt 180)  { return "< 6 months" }
        elseif ($days.TotalDays -lt 365)  { return "< 1 year" }
        elseif ($days.TotalDays -lt 1095) { return "> 1 year" }
        elseif ($days.TotalDays -lt 1825) { return "> 3 years" }
        else                              { return "> 5 years" }
    }

    function Is-AccountEnabled {
        param([int]$UserAccountControl)
        return -not ($UserAccountControl -band 0x2)
    }

    function Get-ASRepRoastable {
        param([int]$UserAccountControl)
        return ($UserAccountControl -band 0x00400000) -ne 0
    }

    function Has-UnconstrainedDelegation {
        param([int]$UserAccountControl)
        return ($UserAccountControl -band 0x80000) -ne 0
    }

    function Has-ConstrainedDelegation {
        param([string]$SamAccountName)
        $obj = Get-ADObject -LDAPFilter "(sAMAccountName=$SamAccountName)" -Properties 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue
        if ($obj -and $obj.'msDS-AllowedToDelegateTo') { return $obj.'msDS-AllowedToDelegateTo' }
        return $null
    }

    function Format-Percent {
        param([int]$part, [int]$whole)
        if ($whole -eq 0) { return "N/A" }
        return "{0:N2}" -f (($part / $whole) * 100)
    }

    # ---------------------------------------------------------------------------------
    # 4) Functions to check DCSYNC, RBCD, ACL, etc.
    # ---------------------------------------------------------------------------------
    function Get-ACLDomainDCSync {
        param([string]$DomainDN)
        if (-not $DomainDN) { return $null }
        $domainObj = Get-ADObject -Identity $DomainDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
        if (-not $domainObj) { return $null }
        $acl = $domainObj.nTSecurityDescriptor
        if (-not $acl) { return $null }
        $results = @()
        $guidDS_Rep_Changes    = [Guid]"e0fa1e9c-9b45-11d0-afdd-00c04fd930c9"
        $guidDS_Rep_ChangesAll = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        $excludedSIDs = @()
        try { $excludedSIDs += (Get-ADGroup "Domain Admins").SID.Value } catch {}
        try { $excludedSIDs += (Get-ADGroup "Enterprise Admins").SID.Value } catch {}
        try { $excludedSIDs += (Get-ADGroup "Administrators").SID.Value } catch {}
        try { $excludedSIDs += (Get-ADGroup "Schema Admins").SID.Value } catch {}
        $excludedSIDs = $excludedSIDs | Where-Object { $_ -ne $null } | Select-Object -Unique

        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                $objectTypeGuid = $ace.ObjectType
                if (($objectTypeGuid -eq $guidDS_Rep_Changes) -or ($objectTypeGuid -eq $guidDS_Rep_ChangesAll)) {
                    $idRef = $ace.IdentityReference -as [string]
                    if ($excludedSIDs -notcontains $idRef) {
                        $perm = if ($objectTypeGuid -eq $guidDS_Rep_ChangesAll) { "DCSync (All)" } else { "DCSync" }
                        $resolved = $null
                        try { $resolved = Get-ADUser -Identity $idRef -ErrorAction Stop } catch {
                            try { $resolved = Get-ADGroup -Identity $idRef -ErrorAction Stop } catch {}
                        }
                        if ($resolved) {
                            $results += [PSCustomObject]@{
                                Identity          = $resolved.SamAccountName
                                DistinguishedName = $resolved.DistinguishedName
                                Right             = $perm
                                Type              = if ($resolved.objectClass -eq 'user') {"User"} else {"Group"}
                            }
                        }
                        else {
                            $results += [PSCustomObject]@{
                                Identity          = $idRef
                                DistinguishedName = "Unresolved"
                                Right             = $perm
                                Type              = "Unknown"
                            }
                        }
                    }
                }
            }
        }
        return $results
    }

    function Get-ACLComputerLAPSAndRBCD {
        param([string]$ComputerDN)
        $results = @()
        if (-not $ComputerDN) { return $results }
        try {
            $adObj = Get-ADObject -Identity $ComputerDN -Properties 'nTSecurityDescriptor','msDS-AllowedToActOnBehalfOfOtherIdentity','ms-Mcs-AdmPwd' -ErrorAction Stop
        }
        catch [System.ArgumentException] {
            $adObj = Get-ADObject -Identity $ComputerDN -Properties 'nTSecurityDescriptor','msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction SilentlyContinue
        }
        catch { return $results }
        if (-not $adObj) { return $results }
        if ($adObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            $results += [PSCustomObject]@{
                ObjectDN = $ComputerDN
                Info     = "Has RBCD attribute (msDS-AllowedToActOnBehalfOfOtherIdentity)"
                Identity = $null
                Right    = "RBCD"
            }
        }
        $acl = $adObj.nTSecurityDescriptor
        if ($acl) {
            foreach ($ace in $acl.Access) {
                $rights   = $ace.ActiveDirectoryRights
                $identity = $ace.IdentityReference -as [string]
                $hasWriteDACL  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0
                $hasWriteOwner = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0
                if ($hasWriteDACL -or $hasWriteOwner) {
                    $results += [PSCustomObject]@{
                        ObjectDN = $ComputerDN
                        Info     = "Can set RBCD (WriteDACL/WriteOwner)"
                        Identity = $identity
                        Right    = "WriteDACL/WriteOwner"
                    }
                }
                $lapsPropertyGuid = [Guid]"3e0abfd0-126a-4edc-90a9-5b2bf2e96a00"
                $hasReadProperty  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -ne 0
                if ($hasReadProperty -and $ace.ObjectType -eq $lapsPropertyGuid) {
                    $results += [PSCustomObject]@{
                        ObjectDN = $ComputerDN
                        Info     = "Can read LAPS password (ms-Mcs-AdmPwd)"
                        Identity = $identity
                        Right    = "ReadLAPSPassword"
                    }
                }
            }
        }
        return $results
    }


    # ---------------------------------------------------------------------------------
    # NEW FUNCTION: Check-AdminSDHolder
    # ---------------------------------------------------------------------------------
    function Check-AdminSDHolder {
        param([string]$DomainDN)
        # It is assumed that the AdminSDHolder DN is: "CN=AdminSDHolder,CN=System,$DomainDN"
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
        try {
            $adminSDHolder = Get-ADObject -Identity $adminSDHolderDN -Properties nTSecurityDescriptor,whenChanged -ErrorAction Stop
        } catch {
            Write-Host "[!] Could not retrieve the AdminSDHolder object." -ForegroundColor Yellow
            return $null
        }
        $lastModified = $adminSDHolder.whenChanged
        $daysSinceModified = (Get-Date) - $lastModified
        $daysSince = [int]$daysSinceModified.TotalDays

        # Define whitelist of accepted identities
        $whitelist = @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins")

        $unexpectedACEs = @()
        # Only consider unexpected ACEs if modified within the last 60 days
        if ($daysSince -le 60) {
            foreach ($ace in $adminSDHolder.nTSecurityDescriptor.Access) {
                $idRef = $ace.IdentityReference.Value
                if ($whitelist -notcontains $idRef) {
                    $unexpectedACEs += $ace
                }
            }
        }
        else {
            # If not modified recently, consider no critical changes
            $unexpectedACEs = @()
        }

        $result = [PSCustomObject]@{
            LastModified         = $lastModified
            DaysSinceModified    = $daysSince
            UnexpectedACEs       = $unexpectedACEs
            UnexpectedACECount   = $unexpectedACEs.Count
        }
        return $result
    }

    # ---------------------------------------------------------------------------------
    # 5) Additional Functions
    # ---------------------------------------------------------------------------------
    function Get-ADFunctionalLevelCheck {
        Write-Host "[*] Checking Domain/Forest Functional Level" -ForegroundColor Cyan
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        $forest = Get-ADForest -ErrorAction SilentlyContinue
        if (-not $domain -or -not $forest) {
            Write-Host "[!] Could not retrieve Domain/Forest. Check permissions/domain membership." -ForegroundColor Yellow
            return @()
        }
        $domainLevel = $domain.DomainMode
        $forestLevel = $forest.ForestMode
        $latestRecommended = "Win2025"
        $results = @()
        if ($domainLevel -notmatch $latestRecommended) {
            $results += [PSCustomObject]@{
                Check       = "Functional Level"
                Description = "Domain functional level is $domainLevel. Recommended at least $latestRecommended."
            }
        }
        if ($forestLevel -notmatch $latestRecommended) {
            $results += [PSCustomObject]@{
                Check       = "Functional Level"
                Description = "Forest functional level is $forestLevel. Recommended at least $latestRecommended."
            }
        }
        return $results
    }

    function Get-ADPasswordPolicyCheck {
        Write-Host "[*] Checking Domain Password Policy (via Default Domain Policy)" -ForegroundColor Cyan
        $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if (-not $pwdPolicy) {
            Write-Host "[!] Could not retrieve Default Domain Policy. Check domain membership or privileges." -ForegroundColor Yellow
            return @()
        }
        $minLength = $pwdPolicy.MinPasswordLength
        $maxAge    = $pwdPolicy.MaxPasswordAge
        $complex   = $pwdPolicy.ComplexityEnabled
        $lockout   = $pwdPolicy.LockoutThreshold
        $results = @()
        if ($minLength -lt 12 -or -not $complex) {
            $results += [PSCustomObject]@{
                Check       = "Password Policy Weak"
                Description = "Password policy might be weak: Complexity=$complex, MinLength=$minLength"
            }
        }
        if ($maxAge.TotalDays -gt 90) {
            $results += [PSCustomObject]@{
                Check       = "Password Policy Weak"
                Description = "MaxPasswordAge is $($maxAge.Days) days; recommended <=90."
            }
        }
        if ($lockout -eq 0) {
            $results += [PSCustomObject]@{
                Check       = "Password Policy Weak"
                Description = "LockoutThreshold is 0. Consider enabling account lockout."
            }
        }
        return $results
    }

    function Get-ADPasswordPolicyDetails {
        Write-Host "[*] Collecting detailed Domain Password Policy parameters..." -ForegroundColor Cyan
        $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        if (-not $pwdPolicy) {
            Write-Host "[!] Could not retrieve Default Domain Policy for password. Possibly no domain membership or insufficient privileges." -ForegroundColor Yellow
            return @()
        }
        Write-Host "  MinLength: $($pwdPolicy.MinPasswordLength)"
        Write-Host "  MaxAge   : $($pwdPolicy.MaxPasswordAge)"
        Write-Host "  Complex? : $($pwdPolicy.ComplexityEnabled)"
        Write-Host "  Lockout T: $($pwdPolicy.LockoutThreshold)"
        Write-Host "  LockoutD : $($pwdPolicy.LockoutDuration)"
        Write-Host "  LockoutW : $($pwdPolicy.LockoutObservationWindow)"
        $results = @()
        $results += [PSCustomObject]@{ Parameter="MinPasswordLength"; Value=$pwdPolicy.MinPasswordLength }
        $results += [PSCustomObject]@{ Parameter="MaxPasswordAge (days)"; Value=$pwdPolicy.MaxPasswordAge.Days }
        $results += [PSCustomObject]@{ Parameter="ComplexityEnabled"; Value=$pwdPolicy.ComplexityEnabled }
        $results += [PSCustomObject]@{ Parameter="LockoutThreshold"; Value=$pwdPolicy.LockoutThreshold }
        $results += [PSCustomObject]@{ Parameter="LockoutDuration (mins)"; Value=$pwdPolicy.LockoutDuration.TotalMinutes }
        $results += [PSCustomObject]@{ Parameter="LockoutObservationWindow (mins)"; Value=$pwdPolicy.LockoutObservationWindow.TotalMinutes }
        return $results
    }

    function Get-ADRc4EncryptionCheck {
        Write-Host "[*] Checking if any privileged account uses RC4 encryption (Kerberos)" -ForegroundColor Cyan
        $adminFilter = "(&(adminCount=1)(|(msDS-SupportedEncryptionTypes=4)(!(msDS-SupportedEncryptionTypes=*))))"
        $rc4Admins = Get-ADUser -LDAPFilter $adminFilter -Properties msDS-SupportedEncryptionTypes,SamAccountName -ErrorAction SilentlyContinue
        $results = @()
        if ($rc4Admins) {
            foreach ($adm in $rc4Admins) {
                $enc = $adm.'msDS-SupportedEncryptionTypes'
                if (-not $enc) { $enc = "Not defined => likely RC4 fallback" }
                $results += [PSCustomObject]@{
                    Check       = "RC4 Encryption Kerberos"
                    Description = "Admin $($adm.SamAccountName) with encryption type: $enc"
                }
            }
        }
        return $results
    }

    function Get-LDAPSigningCheck {
        Write-Host "[*] Checking LDAP signing requirements" -ForegroundColor Cyan
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $regName = "LDAPServerIntegrity"
        $results = @()
        try {
            $ldapSign = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
            if ($ldapSign.$regName -lt 2) {
                $results += [PSCustomObject]@{
                    Check       = "LDAP signing not enforced"
                    Description = "LDAPServerIntegrity=$($ldapSign.$regName). Should be 2 (Require) to enforce signing."
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Check       = "LDAP signing not enforced"
                Description = "Could not find or read LDAPServerIntegrity in registry. Possibly not enforced."
            }
        }
        return $results
    }

    function Get-SysvolPermissionsCheck {
        Write-Host "[*] Checking SYSVOL permissions" -ForegroundColor Cyan
        $results = @()
        $sysvolPath = "$env:SystemRoot\SYSVOL\sysvol"
        if (Test-Path $sysvolPath) {
            $acl = Get-Acl -Path $sysvolPath
            $acl.Access | ForEach-Object {
                if ($_.IdentityReference -match "Authenticated Users|Domain Users") {
                    if ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) {
                        $results += [PSCustomObject]@{
                            Check       = "Sysvol Permissions"
                            Description = "SYSVOL folder ($sysvolPath) has Modify permission for $($_.IdentityReference)"
                        }
                    }
                }
            }
        }
        else {
            $results += [PSCustomObject]@{
                Check       = "Sysvol Permissions"
                Description = "Cannot find path $sysvolPath or no access. Possibly DFS-based or alternative location."
            }
        }
        return $results
    }

    # ---------------------------------------------------------------------------------
    # 6) Analysis of Privileged Accounts and Groups
    # ---------------------------------------------------------------------------------
    function Get-PrivilegedAccountsAnalysis {
        param(
            [Parameter(Mandatory)] [array]$AdminUsers,
            [Parameter(Mandatory)] [string]$DomainName
        )
        Write-Host "[*] Building Privileged Accounts Analysis table..." -ForegroundColor Cyan
        $results = @()
        try {
            $protectedGroup = Get-ADGroup -Identity "Protected Users" -ErrorAction Stop
            $protectedMembers = (Get-ADGroupMember -Identity $protectedGroup -Recursive -ErrorAction SilentlyContinue |
                                 Select -ExpandProperty DistinguishedName) | ForEach-Object { $_.ToLower() }
        } catch {
            Write-Host "[!] 'Protected Users' group not found or error retrieving members." -ForegroundColor Yellow
            $protectedMembers = @()
        }
        foreach ($u in $AdminUsers) {
            $memberships = (Get-ADUser $u.SamAccountName -Properties memberOf).memberOf
            $groupNames = @()
            foreach ($m in $memberships) {
                try {
                    $obj = Get-ADObject -Identity $m
                    if ($obj) { $groupNames += $obj.Name }
                } catch {}
            }
            $groupListHtml = $groupNames -join "<br/>"
            $isProtected = $false
            if ($protectedMembers -contains $u.DistinguishedName.ToLower()) { $isProtected = $true }
            $results += [PSCustomObject]@{
                SamAccountName  = $u.SamAccountName
                Groups          = $groupListHtml
                IsProtectedUser = if ($isProtected) {"Yes"} else {"No"}
            }
        }
        return $results
    }

   function Get-PrivilegedGroupMisconfigurations {
    Write-Host "[*] Checking for misconfigurations in privileged groups" -ForegroundColor Cyan

    # Alias en inglés y español
    $groupAliases = @{
        "Domain Admins"        = @("Domain Admins", "Admins. del dominio")
        "Enterprise Admins"    = @("Enterprise Admins", "Administradores de empresa", "Administradores de empresas")
        "Schema Admins"        = @("Schema Admins", "Administradores de esquema")
        "Administrators"       = @("Administrators", "Administradores")
    }

    $results = @()

    foreach ($aliasSet in $groupAliases.Values) {
        foreach ($groupName in $aliasSet) {
            try {
                $groupObj = Get-ADGroup -Identity $groupName -ErrorAction Stop
                $acl = Get-Acl -Path ("AD:\" + $groupObj.DistinguishedName)
                foreach ($ace in $acl.Access) {
                    $isWriteDACL  = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0
                    $isWriteOwner = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0

                    $allTrusted = $groupAliases.Values | ForEach-Object { $_ } | Sort-Object -Unique

                    if (($isWriteDACL -or $isWriteOwner) -and ($allTrusted -notcontains $ace.IdentityReference.Value)) {
                        $results += [PSCustomObject]@{
                            Group    = $groupName
                            Identity = $ace.IdentityReference
                            Rights   = "WriteDACL/WriteOwner"
                        }
                    }
                }
                break # Si encuentra uno válido en el set, no sigue buscando en sus alias
            } catch {
                # Silenciar error si el grupo no existe
                continue
            }
        }
    }

    return $results
}


    # ---------------------------------------------------------------------------------
    # Extended GPO Analysis
    # ---------------------------------------------------------------------------------
    function Get-GPOExtendedAnalysis {
        Write-Host "[*] Starting extended GPO analysis..." -ForegroundColor Cyan
        $results = [ordered]@{
            "Obfuscated Passwords" = @()
            "Restricted Groups"    = @()
            "Audit Settings"       = @()
            "Privileges"           = @()
            "Login Settings"       = @()
        }
        try {
            $allGPOs = Get-GPO -All -ErrorAction Stop
        } catch {
            Write-Host "[!] Error retrieving GPOs. Ensure you have permissions and the GroupPolicy module installed." -ForegroundColor Red
            return $results
        }
        foreach ($gpo in $allGPOs) {
            # Obfuscated Passwords
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
                [xml]$xmlReport = $gpoReport
                $passwordNodes = $xmlReport.DocumentElement.SelectNodes("//PasswordSetting")
                foreach ($node in $passwordNodes) {
                    if ($node.InnerText -match "obfuscated") {
                        $results["Obfuscated Passwords"] += [PSCustomObject]@{
                            "GPO Name" = $gpo.DisplayName
                            "Setting"  = "Password obfuscated"
                            "Advice"   = "The password appears obfuscated and is not encrypted. Change it immediately."
                        }
                    }
                }
            } catch {}
            # Restricted Groups
            try {
                if (-not $xmlReport) {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
                    [xml]$xmlReport = $gpoReport
                }
                $gpoPerms = Get-GPPermissions -Guid $gpo.Id -All -ErrorAction Stop
                foreach ($perm in $gpoPerms) {
                    if ($perm.Permission -match "Edit Settings" -and $perm.Trustee -match "Administrators|Remote Desktop Users") {
                        $results["Restricted Groups"] += [PSCustomObject]@{
                            "GPO Name"      = $gpo.DisplayName
                            "User or Group" = $perm.Trustee
                            "Member Of"     = $perm.Permission
                            "Advice"        = "Review local group assignments in this GPO; may facilitate escalation."
                        }
                    }
                }
            } catch {}
            # Audit Settings
            try {
                if (-not $xmlReport) {
                    $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
                    [xml]$xmlReport = $gpoReport
                }
                $auditSettings = $xmlReport.DocumentElement.SelectNodes("//AuditSetting")
                foreach ($audit in $auditSettings) {
                    $settingName = $audit.SettingName
                    $value = $audit.Value
                    if ($settingName -eq "Credential Validation" -and $value -notmatch "Success and Failure") {
                        $results["Audit Settings"] += [PSCustomObject]@{
                            "GPO Name" = $gpo.DisplayName
                            "Setting"  = $settingName
                            "Value"    = $value
                            "Advice"   = "Set 'Credential Validation' to 'Success and Failure'."
                        }
                    }
                }
            } catch {}
            # Privileges
            try {
                $privNodes = $xmlReport.DocumentElement.SelectNodes("//PrivilegeSetting")
                foreach ($priv in $privNodes) {
                    $privilege = $priv.PrivilegeName
                    $members   = $priv.Members
                    if ($privilege -eq "SeDebugPrivilege" -and $members -notmatch "Administrators") {
                        $results["Privileges"] += [PSCustomObject]@{
                            "GPO Name"  = $gpo.DisplayName
                            "Privilege" = $privilege
                            "Members"   = $members
                            "Advice"    = "The SeDebugPrivilege should be restricted to Administrators."
                        }
                    }
                }
            } catch {}
            # Login Settings
            try {
                $loginNodes = $xmlReport.DocumentElement.SelectNodes("//LoginSetting")
                foreach ($login in $loginNodes) {
                    $setting = $login.SettingName
                    $value   = $login.Value
                    if ($setting -eq "Allow log on locally" -and $value -notmatch "Administrators") {
                        $results["Login Settings"] += [PSCustomObject]@{
                            "GPO Name" = $gpo.DisplayName
                            "Setting"  = $setting
                            "Value"    = $value
                            "Advice"   = "Review 'Allow log on locally'; permit only authorized users."
                        }
                    }
                }
            } catch {}
        }
        return $results
    }

    # ---------------------------------------------------------------------------------
    # GPO AdditionalAnalysis (Analyze-GPOs.ps1)
    # ---------------------------------------------------------------------------------
    function Get-GPOAdditionalAnalysis {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        
        $restrictedGroupsResults = @()
        $lanAuthResults = @()
        $netEncryptionResults = @()

        try {
            $allGPOs = Get-GPO -All -ErrorAction Stop
        } catch {
            Write-Warning "Error al obtener las GPOs. Verifica permisos y que el módulo GroupPolicy esté instalado."
            return [PSCustomObject]@{
                RestrictedGroups = $restrictedGroupsResults
                LanManagerAuth   = $lanAuthResults
                NetEncryption    = $netEncryptionResults
            }
        }

        foreach ($gpo in $allGPOs) {
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
                [xml]$xmlReport = $gpoReport
            } catch {
                Write-Warning "Error al procesar la GPO: $($gpo.DisplayName). Se omite..."
                continue
            }

            # 1. RestrictedGroups
            try {
                $restrictedNodes = $xmlReport.SelectNodes("//*[local-name()='RestrictedGroups']")
                foreach ($rGroup in $restrictedNodes) {
                    $groupNameNode = $rGroup.SelectSingleNode("*[local-name()='GroupName']")
                    $groupName = if ($groupNameNode -and $groupNameNode.SelectSingleNode("*[local-name()='Name']")) {
                        $groupNameNode.SelectSingleNode("*[local-name()='Name']").InnerText
                    } else {
                        "N/A"
                    }
                    $memberNodes = $rGroup.SelectNodes("*[local-name()='Member']")
                    $members = @()
                    foreach ($member in $memberNodes) {
                        $memberNameNode = $member.SelectSingleNode("*[local-name()='Name']")
                        if ($memberNameNode) {
                            $members += $memberNameNode.InnerText
                        } else {
                            $members += "N/A"
                        }
                    }
                    if ($groupName -ne "N/A" -or $members.Count -gt 0) {
                        $restrictedGroupsResults += [PSCustomObject]@{
                            "GPO Name" = $gpo.DisplayName
                            "Group"    = $groupName
                            "Members"  = ($members -join ", ")
                            "Advice"   = "Revisar configuración de grupos restringidos."
                        }
                    }
                }
            } catch {
                Write-Warning "Error analizando Restricted Groups para la GPO: $($gpo.DisplayName)"
            }

            # 2. LAN Manager Authentication
            try {
                $lanDisplayNodes = $xmlReport.SelectNodes("//*[local-name()='SecurityOptions']/*[local-name()='Display']")
                foreach ($display in $lanDisplayNodes) {
                    $displayNameNode = $display.SelectSingleNode("*[local-name()='Name']")
                    if ($displayNameNode -and $displayNameNode.InnerText -like "*LAN Manager*") {
                        $displayFields = $display.SelectNodes("*[local-name()='DisplayFields']/*[local-name()='Field']")
                        foreach ($field in $displayFields) {
                            $fieldNameNode = $field.SelectSingleNode("*[local-name()='Name']")
                            $fieldValueNode = $field.SelectSingleNode("*[local-name()='Value']")
                            if ($fieldNameNode -and $fieldValueNode) {
                                $lanAuthResults += [PSCustomObject]@{
                                    "GPO Name" = $gpo.DisplayName
                                    "Setting"  = $displayNameNode.InnerText
                                    "Field"    = $fieldNameNode.InnerText
                                    "Value"    = $fieldValueNode.InnerText
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Warning "Error analizando LAN Manager Authentication para la GPO: $($gpo.DisplayName)"
            }

            # 3. DES_CBC_CRC / DES_CBC_MD5
            try {
                $netEncNodes = $xmlReport.SelectNodes("//*[local-name()='Field']")
                foreach ($field in $netEncNodes) {
                    $algoNameNode = $field.SelectSingleNode("*[local-name()='Name']")
                    $algoValueNode = $field.SelectSingleNode("*[local-name()='Value']")
                    if ($algoNameNode -and $algoValueNode) {
                        $algoName = $algoNameNode.InnerText
                        $algoValue = $algoValueNode.InnerText
                        if (($algoName -match "DES_CBC_CRC" -or $algoName -match "DES_CBC_MD5") -and $algoValue -match "true") {
                            $netEncryptionResults += [PSCustomObject]@{
                                "GPO Name"  = $gpo.DisplayName
                                "Algorithm" = $algoName
                                "Value"     = $algoValue
                                "Advice"    = "El algoritmo obsoleto ($algoName) está habilitado."
                            }
                        }
                    }
                }
            } catch {
                Write-Warning "Error analizando Network Security Encryption para la GPO: $($gpo.DisplayName)"
            }
        }

        return [PSCustomObject]@{
            RestrictedGroups = $restrictedGroupsResults
            LanManagerAuth   = $lanAuthResults
            NetEncryption    = $netEncryptionResults
        }
    }

    # ---------------------------------------------------------------------------------
    # 7) Service Accounts Analysis (with SPN)
    # ---------------------------------------------------------------------------------
    function Get-ServiceAccountsAnalysis {
        Write-Host "[*] Checking Service Accounts (any user with an assigned SPN)" -ForegroundColor Cyan
        $results = @()
        $spnUsers = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties userAccountControl,servicePrincipalName,PasswordNeverExpires,PasswordLastSet,adminCount -ErrorAction SilentlyContinue

        Write-Host "[DEBUG] Total SPN Users enumerated: $($spnUsers.Count) (SamAccountName, adminCount, SPN)"
        foreach ($u in $spnUsers) {
            $acVal = if ($u.adminCount -eq $null) { "<null>" } else { $u.adminCount }
            Write-Host "   Sam='$($u.SamAccountName)' adminCount='$acVal' SPN=($($u.ServicePrincipalName -join ', '))"
        }
        Write-Host "-------------------------------------`n"

        foreach ($u in $spnUsers) {
            $asrep = Get-ASRepRoastable -UserAccountControl $u.userAccountControl
            $neverExpires = $u.PasswordNeverExpires
            $results += [PSCustomObject]@{
                SamAccountName       = $u.SamAccountName
                adminCount           = $u.adminCount
                SPN                  = ($u.ServicePrincipalName -join "; ")
                PasswordNeverExpires = if ($neverExpires) {"Yes"} else {"No"}
                ASREP_Roastable      = if ($asrep) {"Yes"} else {"No"}
                LastPassSet          = $u.PasswordLastSet
            }
        }
        return $results
    }

    # ---------------------------------------------------------------------------------
    # 8) Mapping of sections for the HTML report
    # ---------------------------------------------------------------------------------
    $groupMappings = @{
        "Attack Summary" = @("Attack Vectors Summary")
        "AD Delegation" = @(
            "Unconstrained Users","Constrained Users","Constrained Computers","Unconstrained DCs",
            "Unconstrained Computers (not DC)","Computers with RBCD","Potential RBCD (WriteDACL/WriteOwner)",
            "AdminSDHolder Control"
        )
        "AD Infrastructure Security" = @(
            "Functional Level","Non-admin DCSYNC","Sysvol Permissions","LDAP signing not enforced",
            "Interesting ACL (users/groups)","Privileged Group Misconfigurations"
        )
        "Account Security" = @(
            "All SPN Users","All AS-REP Roastable Users","Kerberoastable Accounts","Service Accounts Analysis",
            "LAPS Readers","Password Policy Weak","Password Policy Details","Privileged Accounts Analysis"
        )
        "Kerberos Security" = @(
            "SPN Privileged (adminCount=1)","AS-REP ROAST adminCount=1","RC4 Encryption Kerberos"
        )
        "GPO Security" = @(
            "GPO Restricted Groups",
            "GPO LAN Manager Auth",
            "GPO NetEncryption (DES)"
        )
    }

    # ---------------------------------------------------------------------------------
    # 9) Generate HTML Report
    # ---------------------------------------------------------------------------------
    function Generate-HTMLReport {
    param(
        [Parameter(Mandatory)] [hashtable]$VulnData,
        [Parameter(Mandatory)] [string]$OutputFile,
        [Parameter(Mandatory)] [string]$OverallRisk,
        [Parameter(Mandatory)] [string]$ClientName,
        [Parameter(Mandatory)] [string]$ReportDate
    )

    if ([string]::IsNullOrEmpty($OverallRisk)) {
        $OverallRisk = "Down"
    }
    # Ajustamos colores del OverallRisk, dejando 'white' como default en vez de 'black'
    $OverallRiskColor = switch ($OverallRisk) {
        "Critical" { "red" }
        "High" { "orange" }
        "Medium"   { "yellow" }
        "Down"     { "green" }
        default    { "Blue" }
    }

    # Cabecera HTML, con estilos actualizados en la hoja de estilos
    $htmlHeader = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>VulnBuster Active Directory Audit Report</title>
    <style>
        /* ==================== Retro Style ==================== */
        body.retro {
            background-color: #000000;
            color: #00FF00;
            font-family: 'Lucida Console', Courier, monospace;
            margin: 20px;
        }
        body.retro h1 {
            color: #00FF00;
            font-size: 1.8em;
            text-shadow: 1px 1px #333;
        }
        body.retro .riskTitle {
            color: #00AAAA;
            font-size: 1.5em;
            margin-top: 1em;
        }
        body.retro h3 {
            /* Secciones en verde */
            color: #00FF00;
        }
        body.retro details {
            margin-bottom: 1em;
            border: 1px dashed #00FF00;
            padding: 0.5em;
            background-color: #001000;
        }
        body.retro summary {
            font-weight: bold;
            font-size: 1.1em;
            cursor: pointer;
            outline: none;
            color: #00FF00;
        }
        body.retro table {
            border-collapse: collapse;
            margin: 1em 0;
            width: 100%;
            background-color: #000000;
        }
        body.retro th, body.retro td {
            border: 1px dashed #00FF00;
            padding: 0.5em;
            text-align: left;
        }
        body.retro th {
            background-color: #002200;
            color: #00FF00;
        }
        body.retro td {
            color: #00FF00;
        }
        body.retro .empty {
            font-style: italic;
            color: #009900;
        }
        body.retro .reportVulns {
            color: #00FF00;
        }

        /* ==================== Formal Style ==================== */
        body.formal {
            background-color: #FFFFFF;
            color: #000000;
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        body.formal h1 {
            color: #9B59B6;
            font-size: 2em;
            text-shadow: none;
        }
        body.formal .riskTitle {
            color: #8E44AD;
            font-size: 1.6em;
            margin-top: 1em;
        }
        /* Aquí definimos el color de las secciones en modo formal.
           Puedes poner azul oscuro (#3333CC) o un amarillo oscuro (#C8A600), etc. */
        body.formal h3 {
            color: #3333CC; /* Ejemplo: azul oscuro */
        }
        body.formal details {
            margin-bottom: 1em;
            border: 1px solid #CCCCCC;
            padding: 0.5em;
            background-color: #F9F9F9;
        }
        body.formal summary {
            font-weight: bold;
            font-size: 1.2em;
            cursor: pointer;
            outline: none;
            color: #9B59B6;
        }
        body.formal table {
            border-collapse: collapse;
            margin: 1em 0;
            width: 100%;
            background-color: #FFFFFF;
        }
        body.formal th, body.formal td {
            border: 1px solid #CCCCCC;
            padding: 0.5em;
            text-align: left;
        }
        body.formal th {
            background-color: #EEEEEE;
            color: #333333;
        }
        body.formal td {
            color: #333333;
        }
        body.formal .empty {
            font-style: italic;
            color: #777777;
        }
        body.formal .reportVulns {
            color: #9B59B6;
        }
    </style>
    <script>
        function toggleTheme() {
            var body = document.body;
            var btn = document.getElementById('themeToggleBtn');
            if (body.classList.contains('retro')) {
                body.classList.remove('retro');
                body.classList.add('formal');
                btn.textContent = 'Dark Skin';
            } else {
                body.classList.remove('formal');
                body.classList.add('retro');
                btn.textContent = 'Light Skin';
            }
        }
    </script>
</head>
<body class='retro'>
    <button id='themeToggleBtn' onclick='toggleTheme()' style='margin-bottom: 20px;'>Light Skin</button>
    <h1>VulnBuster Active Directory Audit Report - $ClientName</h1>
    <p style='font-style:italic;color:#6495ED;'>Report generated on: $ReportDate</p>
    <h2 class='riskTitle'>
      Total ON-PREMISE Risk Score:
      <span id='overallRiskSpan'></span>
    </h2>
    <hr/>
"@

    # Construimos el contenido (sin "style='color:#00FF00;'" en <h3>)
    $contentBuilder = [System.Text.StringBuilder]::new()
    foreach ($section in $groupMappings.Keys) {
        # En vez de poner color inline, lo dejamos en blanco: <h3>$section</h3>
        [void]$contentBuilder.AppendLine("<h3>$section</h3>")
        foreach ($category in $groupMappings[$section]) {
            if (-not $VulnData.ContainsKey($category)) { continue }
            $items = $VulnData[$category]
            $count = if ($items) { $items.Count } else { 0 }
            [void]$contentBuilder.AppendLine("<details>")
            [void]$contentBuilder.AppendLine("  <summary>$category (Total: $count)</summary>")
            
            if ($items -and $items.Count -gt 0) {
                $allProps = $items | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique
                [void]$contentBuilder.AppendLine("  <table>")
                [void]$contentBuilder.AppendLine("    <thead>")
                [void]$contentBuilder.AppendLine("      <tr>")
                foreach ($prop in $allProps) {
                    [void]$contentBuilder.AppendLine("        <th>$prop</th>")
                }
                [void]$contentBuilder.AppendLine("      </tr>")
                [void]$contentBuilder.AppendLine("    </thead>")
                [void]$contentBuilder.AppendLine("    <tbody>")
                foreach ($obj in $items) {
                    [void]$contentBuilder.AppendLine("      <tr>")
                    foreach ($prop in $allProps) {
                        $val = $obj.$prop
                        if ($val -is [array]) { $val = $val -join ", " }
                        if (-not $val) { $val = "" }
                        [void]$contentBuilder.AppendLine("        <td>$val</td>")
                    }
                    [void]$contentBuilder.AppendLine("      </tr>")
                }
                [void]$contentBuilder.AppendLine("    </tbody>")
                [void]$contentBuilder.AppendLine("  </table>")
            }
            else {
                [void]$contentBuilder.AppendLine("  <p class='empty'>No entries for this category.</p>")
            }
            [void]$contentBuilder.AppendLine("</details>")
        }
    }

    # Cerramos el HTML: el script JS pone el OverallRisk con color
    $htmlFooter = @"
<script>
document.getElementById('overallRiskSpan').innerHTML = '<span style="color:$($OverallRiskColor)">$OverallRisk</span>';
</script>
</body>
</html>
"@

    # Unimos todo
    $html = $htmlHeader + $contentBuilder.ToString() + $htmlFooter
    
    # Lo guardamos
    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "[*] HTML report generated: $OutputFile" -ForegroundColor Green
}


    # ---------------------------------------------------------------------------------
    # NEW STEPS FOR MITIGATION CONTROL (CAC)
    # ---------------------------------------------------------------------------------
    function Save-VulnSummaryToCSV {
        param(
            [Parameter(Mandatory)] [array]$SummaryData,
            [Parameter(Mandatory)] [string]$OutputFolder,
            [Parameter(Mandatory)] [string]$DateString
        )
        if (-not (Test-Path $OutputFolder)) {
            New-Item -Path $OutputFolder -ItemType Directory | Out-Null
        }
        $csvFile = Join-Path $OutputFolder "VulnSummary_$DateString.csv"
        $SummaryData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Vulnerability summary saved to: $csvFile" -ForegroundColor Green
        return $csvFile
    }

    function Get-PreviousSummaryFile {
        param(
            [Parameter(Mandatory)] [string]$Folder,
            [Parameter(Mandatory)] [string]$CurrentFile
        )
        $files = Get-ChildItem -Path $Folder -Filter "VulnSummary_*.csv" | Sort-Object LastWriteTime
        if ($files.Count -lt 2) { return $null }
        $current = Get-Item $CurrentFile
        $previousFiles = $files | Where-Object { $_.LastWriteTime -lt $current.LastWriteTime }
        if ($previousFiles.Count -gt 0) {
            return $previousFiles[-1].FullName
        }
        return $null
    }

    function Compare-VulnSummaries {
        param(
            [Parameter(Mandatory)] [string]$PrevFile,
            [Parameter(Mandatory)] [string]$CurrFile,
            [Parameter(Mandatory)] [string]$OutputFolder,
            [Parameter(Mandatory)] [string]$DateString
        )
        $prev = Import-Csv $PrevFile
        $curr = Import-Csv $CurrFile
        $allCategories = ($prev.Category + $curr.Category) | Select-Object -Unique
        $comparison = foreach ($cat in $allCategories) {
            $prevEntry = $prev | Where-Object { $_.Category -eq $cat }
            $currEntry = $curr | Where-Object { $_.Category -eq $cat }
            $prevCount = if ($prevEntry) { [int]$prevEntry.Count } else { 0 }
            $currCount = if ($currEntry) { [int]$currEntry.Count } else { 0 }
            $difference = $currCount - $prevCount
            $status = if ($difference -lt 0) { "Mitigated" } elseif ($difference -gt 0) { "Increased" } else { "Unchanged" }
            [PSCustomObject]@{
                Category      = $cat
                PreviousCount = $prevCount
                CurrentCount  = $currCount
                Difference    = $difference
                Status        = $status
            }
        }
        $comparisonFile = Join-Path $OutputFolder "Mitigation_Comparison_$DateString.csv"
        $comparison | Export-Csv -Path $comparisonFile -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Mitigation comparison report saved to: $comparisonFile" -ForegroundColor Green
        return $comparisonFile
    }

    # ---------------------------------------------------------------------------------
    # 10) Main Script
    # ---------------------------------------------------------------------------------
    Write-Host ""
    Write-Host "== Starting Vuln Buster AD Audit  ==" -ForegroundColor Magenta
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Requesting client name" -PercentComplete 0
    Write-Host "Please enter the client name:"
    $ClientName = Read-Host

    # Current date for the report
    $dateString = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $reportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Retrieving domain information" -PercentComplete 5
    $domainInfo = Get-ADDomain -ErrorAction SilentlyContinue
    if (-not $domainInfo) {
        Write-Host "[!] Could not retrieve domain information with Get-ADDomain. Ensure you are on a domain-joined computer with proper permissions." -ForegroundColor Yellow
    }
    else {
        $domainDN   = $domainInfo.DistinguishedName
        $domainName = $domainInfo.DNSRoot
    }
    $vulnSummary = @()

    # ---------------------------
    # Domain Admins Enumeration
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Retrieving Domain Admins" -PercentComplete 10
    Write-Host ""
    Write-Host "###########################################################" -ForegroundColor Green
    Write-Host "[*] Enumerating Domain Admins (RIDs 512|519|544) recursively" -ForegroundColor Green
    Write-Host "###########################################################" -ForegroundColor Green
    $adminRIDs = @(512, 519, 544)
    $allAdminUsers = @()
    if ($domainInfo) {
        foreach ($rid in $adminRIDs) {
            $targetSid = "$($domainInfo.DomainSID.Value)-$rid"
            try {
                $groupObj = Get-ADGroup -Identity $targetSid -ErrorAction Stop
                if ($groupObj) {
                    Write-Host "[+] Found group (RID:$rid): $($groupObj.Name.ToUpper())@$($domainName.ToUpper())" -ForegroundColor Green
                    $members = Get-ADGroupMember -Identity $groupObj.DistinguishedName -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }
                    foreach ($m in $members) {
                        $u = Get-ADUser -Identity $m.SamAccountName -Properties lastLogonTimestamp, userAccountControl, ServicePrincipalName, adminCount, PasswordLastSet -ErrorAction SilentlyContinue
                        if ($u) {
                            $enabled   = Is-AccountEnabled -UserAccountControl $u.userAccountControl
                            $logonInfo = Get-LastLogonInfo -LastLogonTime ([DateTime]::FromFileTime($u.lastLogonTimestamp))
                            $marker = ""
                            if (Get-ASRepRoastable -UserAccountControl $u.userAccountControl) { $marker += " [ASREP]" }
                            if ($u.ServicePrincipalName) { $marker += " [SPN]" }
                            if ($u.adminCount -eq 1)     { $marker += " [adminCount=1]" }
                            $status = if ($enabled) {"(enabled)"} else {"(disabled)"}
                            Write-Host "[+] DA $($status): $($u.SamAccountName.ToUpper())@$($domainName.ToUpper())$marker [LASTLOG: $logonInfo]" -ForegroundColor Green
                            $allAdminUsers += $u
                        }
                    }
                }
            } catch {}
        }
    }

    # ---------------------------
    # Enumerating SPN Privileged and AS-REP Roast
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating SPN Privileged (adminCount=1)" -PercentComplete 20
    Write-Host "[*] Enumerating SPN Privileged (adminCount=1)" -ForegroundColor Green
    $spnAdmin = Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(adminCount=1))" -Properties userAccountControl -ErrorAction SilentlyContinue
    $vulnSummary += [PSCustomObject]@{
        Category = "SPN Privileged (adminCount=1)"
        Count    = if ($spnAdmin) { $spnAdmin.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating AS-REP ROAST adminCount=1" -PercentComplete 25
    Write-Host "[*] Enumerating AS-REP ROAST adminCount=1" -ForegroundColor Green
    $asrepAdmin = Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(adminCount=1))" -Properties userAccountControl -ErrorAction SilentlyContinue
    $vulnSummary += [PSCustomObject]@{
        Category = "AS-REP ROAST adminCount=1"
        Count    = if ($asrepAdmin) { $asrepAdmin.Count } else { 0 }
    }

    # ---------------------------
    # ALL SPN Users and Kerberoastable Accounts
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating ALL SPN Users" -PercentComplete 30
    Write-Host "[*] Retrieving ALL SPN Users" -ForegroundColor Green
    $allSPNUsers = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName,userAccountControl,adminCount -ErrorAction SilentlyContinue
    $vulnSummary += [PSCustomObject]@{
        Category = "All SPN Users"
        Count    = if ($allSPNUsers) { $allSPNUsers.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating Kerberoastable Accounts" -PercentComplete 35
    Write-Host "[*] Enumerating Kerberoastable Accounts (SPN + not krbtgt + adminCount != 1)" -ForegroundColor Green
    $kerberoastableAccounts = @()
    foreach ($u in $allSPNUsers) {
        if ($u.ServicePrincipalName -and ($u.SamAccountName -ne 'krbtgt')) {
            $adminCountInt = 0
            if ($u.adminCount -ne $null) { $adminCountInt = [int]$u.adminCount }
            if ($adminCountInt -ne 1) {
                Write-Host " [DEBUG] => $($u.SamAccountName) IS kerberoastable (adminCount=$adminCountInt)" -ForegroundColor Cyan
                $kerberoastableAccounts += $u
            } else {
                Write-Host " [DEBUG] => $($u.SamAccountName) is NOT kerberoastable (adminCount=1)" -ForegroundColor Yellow
            }
        } else {
            Write-Host " [DEBUG] => $($u.SamAccountName) does not qualify (SPN? $($u.ServicePrincipalName) / krbtgt? $($u.SamAccountName -eq 'krbtgt'))" -ForegroundColor Magenta
        }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Kerberoastable Accounts"
        Count    = $kerberoastableAccounts.Count
    }

    # ---------------------------
    # ALL AS-REP Roastable
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating ALL AS-REP Roastable" -PercentComplete 40
    Write-Host "[*] Enumerating ALL AS-REP Roastable" -ForegroundColor Green
    $asrepUsers = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -Properties userAccountControl,adminCount -ErrorAction SilentlyContinue
    $vulnSummary += [PSCustomObject]@{
        Category = "All AS-REP Roastable Users"
        Count    = if ($asrepUsers) { $asrepUsers.Count } else { 0 }
    }

    # ---------------------------
    # Unconstrained & Constrained Users
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating Unconstrained Users" -PercentComplete 45
    Write-Host "[*] Enumerating Unconstrained Users" -ForegroundColor Green
    $allUsers = Get-ADUser -Filter * -Properties userAccountControl,lastLogonTimestamp -ErrorAction SilentlyContinue
    $unconstrainedUsers = $allUsers | Where-Object { Has-UnconstrainedDelegation -UserAccountControl $_.userAccountControl }
    $vulnSummary += [PSCustomObject]@{
        Category = "Unconstrained Users"
        Count    = if ($unconstrainedUsers) { $unconstrainedUsers.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating Constrained Users" -PercentComplete 50
    Write-Host "[*] Enumerating Constrained Users" -ForegroundColor Green
    $constrainedUsers = @()
    foreach ($u in $allUsers) {
        $deleg = Has-ConstrainedDelegation -SamAccountName $u.SamAccountName
        if ($deleg) { $constrainedUsers += $u }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Constrained Users"
        Count    = if ($constrainedUsers) { $constrainedUsers.Count } else { 0 }
    }

    # ---------------------------
    # Computers (Constrained/Unconstrained)
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating Computers (Constrained/Unconstrained)" -PercentComplete 55
    Write-Host "[*] Enumerating Constrained/Unconstrained Computers" -ForegroundColor Green
    $allComputers = Get-ADComputer -Filter * -Properties userAccountControl,'msDS-AllowedToDelegateTo','operatingSystem' -ErrorAction SilentlyContinue
    $constrainedComputers = @()
    $unconstrainedDC = @()
    $unconstrainedCompsNotDC = @()
    foreach ($c in $allComputers) {
        $deleg = $c.'msDS-AllowedToDelegateTo'
        if ($deleg) {
            if (-not (Has-UnconstrainedDelegation -UserAccountControl $c.userAccountControl)) {
                $constrainedComputers += $c
            }
        }
        if (Has-UnconstrainedDelegation -UserAccountControl $c.userAccountControl) {
            if ($c.Name -match "^DC" -or $c.operatingSystem -like "*Domain Controller*") {
                $unconstrainedDC += $c
            }
            else {
                $unconstrainedCompsNotDC += $c
            }
        }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Constrained Computers"
        Count    = if ($constrainedComputers) { $constrainedComputers.Count } else { 0 }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Unconstrained DCs"
        Count    = if ($unconstrainedDC) { $unconstrainedDC.Count } else { 0 }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Unconstrained Computers (not DC)"
        Count    = if ($unconstrainedCompsNotDC) { $unconstrainedCompsNotDC.Count } else { 0 }
    }

    # ---------------------------
    # RBCD Checks
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Enumerating RBCD" -PercentComplete 60
    Write-Host "[*] Enumerating RBCD" -ForegroundColor Green
    $rbcdComputers = @()
    foreach ($comp in $allComputers) {
        $dn = $comp.DistinguishedName
        try {
            $obj = Get-ADObject -Identity $dn -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            if ($obj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $rbcdComputers += $comp
            }
        } catch {}
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Computers with RBCD"
        Count    = if ($rbcdComputers) { $rbcdComputers.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Checking RBCD configuration" -PercentComplete 65
    Write-Host "[*] Checking who can configure RBCD (WriteDACL/WriteOwner)" -ForegroundColor Green
    $rbcdACLResults = @()
    foreach ($comp in $allComputers) {
        $res = Get-ACLComputerLAPSAndRBCD -ComputerDN $comp.DistinguishedName
        if ($res) {
            $rbcdHits = $res | Where-Object { $_.Right -eq "WriteDACL/WriteOwner" }
            if ($rbcdHits) { $rbcdACLResults += $rbcdHits }
        }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Potential RBCD (WriteDACL/WriteOwner)"
        Count    = if ($rbcdACLResults) { $rbcdACLResults.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Checking Non-admin DCSYNC" -PercentComplete 70
    Write-Host "[*] Checking Non-admins who can DCSYNC" -ForegroundColor Green
    $dcsyncResults = Get-ACLDomainDCSync -DomainDN $domainDN
    $vulnSummary += [PSCustomObject]@{
        Category = "Non-admin DCSYNC"
        Count    = if ($dcsyncResults) { $dcsyncResults.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Checking LAPS Readers" -PercentComplete 75
    Write-Host "[*] Checking LAPS Readers" -ForegroundColor Green
    $lapsACLResults = @()
    foreach ($comp in $allComputers) {
        $res = Get-ACLComputerLAPSAndRBCD -ComputerDN $comp.DistinguishedName
        if ($res) {
            $lapsHits = $res | Where-Object { $_.Right -eq "ReadLAPSPassword" }
            if ($lapsHits) { $lapsACLResults += $lapsHits }
        }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "LAPS Readers"
        Count    = if ($lapsACLResults) { $lapsACLResults.Count } else { 0 }
    }

  

    # ---------------------------
    # Extended GPO + Additional GPO Analysis
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Analyzing extended GPOs" -PercentComplete 83
    $gpoExtendedResults = Get-GPOExtendedAnalysis
    $gpoExtendedData = @()
    foreach ($category in $gpoExtendedResults.Keys) {
        foreach ($item in $gpoExtendedResults[$category]) {
            $item | Add-Member -MemberType NoteProperty -Name "Category" -Value $category -Force
            $gpoExtendedData += $item
        }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Analyze Additional GPO Misconfigurations" -PercentComplete 84
    $gpoExtra = Get-GPOAdditionalAnalysis
    $restrictedGroupsResults = $gpoExtra.RestrictedGroups
    $lanAuthResults          = $gpoExtra.LanManagerAuth
    $netEncryptionResults    = $gpoExtra.NetEncryption

    $vulnSummary += [PSCustomObject]@{
        Category = "GPO Restricted Groups"
        Count    = $restrictedGroupsResults.Count
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "GPO LAN Manager Auth"
        Count    = $lanAuthResults.Count
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "GPO NetEncryption (DES)"
        Count    = $netEncryptionResults.Count
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Analyzing Service Accounts" -PercentComplete 85
    $serviceAccounts = Get-ServiceAccountsAnalysis
    $vulnSummary += [PSCustomObject]@{
        Category = "Service Accounts Analysis"
        Count    = if ($serviceAccounts) { $serviceAccounts.Count } else { 0 }
    }

    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Checking Privileged Groups" -PercentComplete 86
    $privGroupMisconfigs = Get-PrivilegedGroupMisconfigurations
    $vulnSummary += [PSCustomObject]@{
        Category = "Privileged Group Misconfigurations"
        Count    = if ($privGroupMisconfigs) { $privGroupMisconfigs.Count } else { 0 }
    }

    # ---------------------------
    # AdminSDHolder Control
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "AdminSDHolder Control" -PercentComplete 87
    $adminSDHolderControl = Check-AdminSDHolder -DomainDN $domainDN
    $adminSDHolderData = @()
    if ($adminSDHolderControl) {
        Write-Host "[*] AdminSDHolder: Last Modified: $($adminSDHolderControl.LastModified) (Modified $($adminSDHolderControl.DaysSinceModified) days ago). Unexpected ACEs: $($adminSDHolderControl.UnexpectedACECount)" -ForegroundColor Cyan
        $vulnSummary += [PSCustomObject]@{
            Category = "AdminSDHolder Control"
            Count    = $adminSDHolderControl.UnexpectedACECount
        }
        $adminSDHolderData += [PSCustomObject]@{
            InfoType           = "General Info"
            LastModified       = $adminSDHolderControl.LastModified
            DaysSinceModified  = $adminSDHolderControl.DaysSinceModified
            UnexpectedACECount = $adminSDHolderControl.UnexpectedACECount
        }
        foreach ($ace in $adminSDHolderControl.UnexpectedACEs) {
            $adminSDHolderData += [PSCustomObject]@{
                InfoType              = "ACE"
                IdentityReference     = $ace.IdentityReference
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                IsInherited           = $ace.IsInherited
                ObjectType            = $ace.ObjectType
            }
        }
    }
    else {
        Write-Host "[!] Could not retrieve AdminSDHolder or no data available. Recording 0." -ForegroundColor Yellow
        $vulnSummary += [PSCustomObject]@{
            Category = "AdminSDHolder Control"
            Count    = 0
        }
    }

    # ---------------------------
    # Global Statistics
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Gathering global statistics" -PercentComplete 88
    Write-Host ""
    Write-Host "[*] Gathering global user statistics" -ForegroundColor Green
    $allUsers2 = Get-ADUser -Filter * -Properties userAccountControl,PasswordLastSet,lastLogonTimestamp -ErrorAction SilentlyContinue
    $totalUsers = $allUsers2.Count
    $enabledUsers  = $allUsers2 | Where-Object { Is-AccountEnabled -UserAccountControl $_.userAccountControl }
    $disabledUsers = $allUsers2 | Where-Object { -not (Is-AccountEnabled -UserAccountControl $_.userAccountControl) }
    $totalEnabled  = $enabledUsers.Count
    $totalDisabled = $disabledUsers.Count
    $domainAdminsCount = ($allAdminUsers | Select-Object -Unique SamAccountName).Count
    $cutOff6M = (Get-Date).AddMonths(-6)
    $notLoggedSince6M = $enabledUsers | Where-Object {
        $ll = [DateTime]::FromFileTime($_.lastLogonTimestamp)
        if ($ll -eq [DateTime]::MinValue) { $true }
        elseif ($ll -lt $cutOff6M)       { $true }
        else                             { $false }
    }
    $cutOff1Y = (Get-Date).AddYears(-1)
    $passNotChanged1Y = $enabledUsers | Where-Object { $_.PasswordLastSet -lt $cutOff1Y }
    $cutOff2Y = (Get-Date).AddYears(-2)
    $passNotChanged2Y = $enabledUsers | Where-Object { $_.PasswordLastSet -lt $cutOff2Y }
    Write-Host ""
    Write-Host "+--------------------------------------------+------------+-------+" -ForegroundColor Green
    Write-Host "|                Description                 | Percentage | Total |" -ForegroundColor Green
    Write-Host "+--------------------------------------------+------------+-------+" -ForegroundColor Green
    Write-Host ("|{0,-44}|{1,12}|{2,7} |" -f "All users", "N/A", $totalUsers) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "All users (enabled)", (Format-Percent $totalEnabled $totalUsers), $totalEnabled) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "All users (disabled)", (Format-Percent $totalDisabled $totalUsers), $totalDisabled) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "Users with 'domain admins' rights", (Format-Percent $domainAdminsCount $totalUsers), $domainAdminsCount) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "Not logged (enabled) since 6 months", (Format-Percent $notLoggedSince6M.Count $totalEnabled), $notLoggedSince6M.Count) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "Password not changed > 1 y (enabled)", (Format-Percent $passNotChanged1Y.Count $totalEnabled), $passNotChanged1Y.Count) -ForegroundColor White
    Write-Host ("|{0,-44}|{1,12}%|{2,7} |" -f "Password not changed > 2 y (enabled)", (Format-Percent $passNotChanged2Y.Count $totalEnabled), $passNotChanged2Y.Count) -ForegroundColor White
    Write-Host "+--------------------------------------------+------------+-------+" -ForegroundColor Green

    # ---------------------------
    # Additional Checks
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Gathering Additional Checks" -PercentComplete 90
    Write-Host ""
    Write-Host "###########################################################" -ForegroundColor Green
    Write-Host "[*] Additional Checks (Functional Level, Password Policy, RC4, LDAP, Sysvol)" -ForegroundColor Green
    Write-Host "###########################################################`n" -ForegroundColor Green
    $additionalChecksResults = @()
    $funcLevelResults = Get-ADFunctionalLevelCheck
    if ($funcLevelResults) { $additionalChecksResults += $funcLevelResults }
    $pwdPolicyResults = Get-ADPasswordPolicyCheck
    if ($pwdPolicyResults) { $additionalChecksResults += $pwdPolicyResults }
    $rc4Results = Get-ADRc4EncryptionCheck
    if ($rc4Results) { $additionalChecksResults += $rc4Results }
    $ldapSignResults = Get-LDAPSigningCheck
    if ($ldapSignResults) { $additionalChecksResults += $ldapSignResults }
    $sysvolResults = Get-SysvolPermissionsCheck
    if ($sysvolResults) { $additionalChecksResults += $sysvolResults }
    Write-Host "`n[*] Summary of Additional Checks:" -ForegroundColor Green
    if ($additionalChecksResults) {
        foreach ($item in $additionalChecksResults) {
            Write-Host "[+] $($item.Check): $($item.Description)" -ForegroundColor White
        }
    } else {
        Write-Host "[-] No findings in additional checks." -ForegroundColor DarkYellow
    }
    $pwdPolicyDetails = Get-ADPasswordPolicyDetails
    $privAnalysis = Get-PrivilegedAccountsAnalysis -AdminUsers $allAdminUsers -DomainName $domainName
    $vulnSummary += [PSCustomObject]@{
        Category = "Password Policy Details"
        Count    = if ($pwdPolicyDetails) { $pwdPolicyDetails.Count } else { 0 }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Privileged Accounts Analysis"
        Count    = if ($privAnalysis) { $privAnalysis.Count } else { 0 }
    }

    # ---------------------------
    # Attack Vectors Summary
    # ---------------------------
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Summarizing attack vectors" -PercentComplete 92
    Write-Host "[*] Generating Attack Vectors Summary" -ForegroundColor Green
    $attackVectors = @()
    foreach ($item in $vulnSummary) {
        if ($item.Count -gt 0) {
            $attackVectors += [PSCustomObject]@{
                VectorName = $item.Category
                Count      = $item.Count
            }
        }
    }
    $vulnSummary += [PSCustomObject]@{
        Category = "Attack Vectors Summary"
        Count    = $attackVectors.Count
    }

    # ---------------------------
    # Build $vulnData
    # ---------------------------
    $vulnData = @{
        "SPN Privileged (adminCount=1)"          = $spnAdmin
        "AS-REP ROAST adminCount=1"              = $asrepAdmin
        "All SPN Users"                          = $allSPNUsers
        "Kerberoastable Accounts"                = $kerberoastableAccounts
        "All AS-REP Roastable Users"             = $asrepUsers
        "Unconstrained Users"                    = $unconstrainedUsers
        "Constrained Users"                      = $constrainedUsers
        "Constrained Computers"                  = $constrainedComputers
        "Unconstrained DCs"                      = $unconstrainedDC
        "Unconstrained Computers (not DC)"       = $unconstrainedCompsNotDC
        "Computers with RBCD"                    = $rbcdComputers
        "Potential RBCD (WriteDACL/WriteOwner)"  = $rbcdACLResults
        "Non-admin DCSYNC"                       = $dcsyncResults
        "LAPS Readers"                           = $lapsACLResults
        "Interesting ACL (users/groups)"         = $aclUserGroup
        
        # Quitado GPO Misconfigurations
        "Service Accounts Analysis"              = $serviceAccounts
        "Privileged Group Misconfigurations"     = $privGroupMisconfigs
        "Functional Level"                       = $funcLevelResults
        "Password Policy Weak"                   = $pwdPolicyResults
        "RC4 Encryption Kerberos"                = $rc4Results
        "LDAP signing not enforced"              = $ldapSignResults
        "Sysvol Permissions"                     = $sysvolResults
        "Password Policy Details"                = $pwdPolicyDetails
        "Privileged Accounts Analysis"           = $privAnalysis
        "Attack Vectors Summary"                 = $attackVectors
        "AdminSDHolder Control"                  = $adminSDHolderData
        "GPO Extended Analysis"                  = $gpoExtendedData
        "GPO Restricted Groups"                  = $restrictedGroupsResults
        "GPO LAN Manager Auth"                   = $lanAuthResults
        "GPO NetEncryption (DES)"                = $netEncryptionResults
    }

    # ---------------------------
    # Risk Score & Final Summaries
    # ---------------------------
    Write-Host "`n###########################################################" -ForegroundColor Green
    Write-Host "[*] Final Summary of Detected Items (Category/Count/Severity/MITRE/Mitigation)" -ForegroundColor Green
    Write-Host "###########################################################`n" -ForegroundColor Green
    Write-Host "+------------------------------------------------------------------------------------------------------------------------------+" -ForegroundColor Green
    Write-Host ("|{0,-40}|{1,5}|{2,8}|{3,-10}|{4,-12}|" -f "Category", "Count", "Severity", "MITRE", "Mitigation") -ForegroundColor Green
    Write-Host "+------------------------------------------------------------------------------------------------------------------------------+" -ForegroundColor Green
    
    $severityWeights = @{
        "Crítical" = 4
        "High"     = 3
        "Medium"   = 2
        "Info"     = 1
        "Descon."  = 0
    }
    $totalRiskScore = 0
    foreach ($v in $vulnSummary) {
        $severity = if ($vulnSeverity.ContainsKey($v.Category)) { $vulnSeverity[$v.Category] } else { "Descon." }
        $mitigation = ""
        if ($v.Count -gt 0 -and $vulnMitigations.ContainsKey($v.Category)) {
            $mitigation = $vulnMitigations[$v.Category]
        }
        $mitre = if ($vulnMitre.ContainsKey($v.Category)) { $vulnMitre[$v.Category] } else { "N/A" }

        Write-Host ("|{0,-40}|{1,5}|{2,8}|{3,-10}|{4,-12}|" -f $v.Category, $v.Count, $severity, $mitre, $mitigation) -ForegroundColor White
    }
    Write-Host "+------------------------------------------------------------------------------------------------------------------------------+" -ForegroundColor Green

    Write-Host "`n-- Breakdown of contributions to total RiskScore (separate table) --" -ForegroundColor Cyan
    Write-Host "+--------------------------------------------------------------------------------+"
    Write-Host ("|{0,-40}|{1,5}|{2,8}|{3,10}|" -f "Category", "Count", "Severity", "Contribution")
    Write-Host "+--------------------------------------------------------------------------------+"
    foreach ($v in $vulnSummary) {
        $severity = if ($vulnSeverity.ContainsKey($v.Category)) { $vulnSeverity[$v.Category] } else { "Descon." }
        $weight = if ($severityWeights.ContainsKey($severity)) { $severityWeights[$severity] } else { 0 }
        $count = [int]$v.Count
        if ($v.Category -notin @("Attack Vectors Summary","Interesting ACL (users/groups)")) {
            $contrib = $count * $weight
            Write-Host ("|{0,-40}|{1,5}|{2,8}|{3,10}|" -f $v.Category, $count, $severity, $contrib) -ForegroundColor Yellow
            $totalRiskScore += $contrib
        }
    }
    Write-Host "+--------------------------------------------------------------------------------+"
    Write-Host ("|{0,-40}|{1,26}|" -f "TotalRiskScore =", $totalRiskScore) -ForegroundColor Magenta
    Write-Host "+--------------------------------------------------------------------------------+"
    
    if ($totalRiskScore -ge 300) {
        $overallRisk = "Critical"
    } elseif ($totalRiskScore -ge 150) {
        $overallRisk = "High"
    } elseif ($totalRiskScore -ge 70) {
        $overallRisk = "Medium"
    } else {
        $overallRisk = "Down"
    }

    Write-Host "`n[*] Overall assessment of the environment: $overallRisk" -ForegroundColor Magenta

    # Generar HTML
    Write-Progress -Activity "Vuln Buster AD Audit" -Status "Generating HTML Report" -PercentComplete 95
    $reportPath = "C:\adaudit\ADVULNBUSTER\VulnBusterAD_Report_$($dateString).html"
    Generate-HTMLReport -VulnData $vulnData -OutputFile $reportPath -OverallRisk $overallRisk -ClientName $ClientName -ReportDate $reportDate
    
    Write-Host "`n=== End of Vuln Buster AD Audit ===`n" -ForegroundColor Magenta
    
    # ---------------------------------------------------------------------------------
    # Continuous Audit Control (CAC)
    # ---------------------------------------------------------------------------------
    Write-Host "`n=== Starting CAC - Continuous Audit Control ===`n" -ForegroundColor Magenta
    $summaryFolder = "C:\adaudit\ADVULNBUSTER\Summaries"
    $currentSummaryFile = Save-VulnSummaryToCSV -SummaryData $vulnSummary -OutputFolder $summaryFolder -DateString $dateString
    $prevSummaryFile = Get-PreviousSummaryFile -Folder $summaryFolder -CurrentFile $currentSummaryFile
    if ($prevSummaryFile) {
        Write-Host "[*] Previous summary file found: $prevSummaryFile" -ForegroundColor Cyan
        $comparisonFile = Compare-VulnSummaries -PrevFile $prevSummaryFile -CurrFile $currentSummaryFile -OutputFolder $summaryFolder -DateString $dateString
    }
    else {
        Write-Host "[*] No previous summary file found. This is the first run or no older file exists." -ForegroundColor Cyan
    }
}

'@

#endregion reporte 


#region pki report


$pkiReportScript = @'
function Test-CAExistenceInAD {
    try {
        $configNC = (Get-ADRootDSE).ConfigurationNamingContext
        $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $allCAs = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } `
                   -SearchBase $searchBase -Properties Name, dNSHostName, DisplayName, DistinguishedName
        if (!$allCAs) {
            Write-Host "No Enterprise CA (pKIEnrollmentService) was detected in AD." -ForegroundColor Red
            Write-Host "Possibly the CA is Standalone or you do not have sufficient AD permissions/visibility."
            return $null
        }
        else {
            Write-Host "The following CA(s) were detected in AD:" -ForegroundColor Green
            foreach ($ca in $allCAs) {
                $caName  = $ca.PSObject.Properties["Name"].Value
                $dns     = $ca.dNSHostName
                $display = $ca.DisplayName
                $dn      = $ca.DistinguishedName
                Write-Host "CA: $caName  -  DisplayName: $display  -  dNSHostName: $dns" -ForegroundColor Cyan
                Write-Host "DistinguishedName: $dn" -ForegroundColor DarkCyan
                Write-Host "--------------------------------------------------------------"
            }
            return $allCAs
        }
    }
    catch {
        Write-Host "Error checking CA existence in AD: $_" -ForegroundColor Red
        return $null
    }
}

function Get-ADCSCertificateTemplates {
    $configNC = (Get-ADRootDSE).ConfigurationNamingContext
    $searchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } -SearchBase $searchBase -Properties *
}

function Find-ESC1 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.pkiExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2' -and -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            $results += [PSCustomObject]@{
                Vulnerability = "ESC1"
                Template      = $tpl.Name
                Issue         = "Allows inclusion of a SAN without Manager Approval."
                Recommendation= "Enable Manager Approval (set bit 2 in msPKI-Enrollment-Flag)."
            }
        }
    }
    return $results
}

function Find-ESC2 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.pkiExtendedKeyUsage -match '2\.5\.29\.37\.0' -and -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            $results += [PSCustomObject]@{
                Vulnerability = "ESC2"
                Template      = $tpl.Name
                Issue         = "Template for elevated purposes without approval."
                Recommendation= "Enable Manager Approval or restrict the EKU."
            }
        }
    }
    return $results
}

function Find-ESC3 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.pkiExtendedKeyUsage -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1' -and -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            $results += [PSCustomObject]@{
                Vulnerability = "ESC3"
                Template      = $tpl.Name
                Issue         = "Enrollment Agent template without Manager Approval (Condition 1)."
                Recommendation= "Enable Manager Approval."
            }
        }
        if (($tpl.'msPKI-RA-Signature' -eq 1) -and -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            $results += [PSCustomObject]@{
                Vulnerability = "ESC3"
                Template      = $tpl.Name
                Issue         = "RA Signature enabled without approval (Condition 2)."
                Recommendation= "Review and enable Manager Approval if necessary."
            }
        }
    }
    return $results
}

function Find-ESC4 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.nTSecurityDescriptor -and $tpl.nTSecurityDescriptor.Access) {
            foreach ($ace in $tpl.nTSecurityDescriptor.Access) {
                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                    $results += [PSCustomObject]@{
                        Vulnerability = "ESC4"
                        Template      = $tpl.Name
                        Issue         = "ACL with GenericAll granted to $($ace.IdentityReference)."
                        Recommendation= "Review the ACL and restrict these permissions."
                    }
                }
            }
        }
    }
    return $results
}

function Find-ESC5 {
    $results = @()
    try {
        $configNC = (Get-ADRootDSE).ConfigurationNamingContext
        $searchBase = "CN=Public Key Services,CN=Services,$configNC"
        $ntAuth = Get-ADObject -Filter { Name -like 'NTAuthCertificates*' } -SearchBase $searchBase -Properties nTSecurityDescriptor | Select-Object -First 1
        if ($ntAuth) {
            foreach ($ace in $ntAuth.nTSecurityDescriptor.Access) {
                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                    $results += [PSCustomObject]@{
                        Vulnerability = "ESC5"
                        Object        = $ntAuth.Name
                        Issue         = "NTAuthCertificates has GenericAll permissions granted to $($ace.IdentityReference)."
                        Recommendation= "Restrict permissions on NTAuthCertificates."
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve NTAuthCertificates."
    }
    return $results
}

function Find-ESC6 {
    $results = @()
    $caConfig = @{ Name = "CA01"; EDITF_ATTRIBUTESUBJECTALTNAME2 = $true }
    if ($caConfig.EDITF_ATTRIBUTESUBJECTALTNAME2) {
        $results += [PSCustomObject]@{
            Vulnerability = "ESC6"
            CA            = $caConfig.Name
            Issue         = "EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled."
            Recommendation= "Disable this flag on the CA."
        }
    }
    return $results
}

function Find-ESC8 {
    $results = @()
    try {
        $configNC = (Get-ADRootDSE).ConfigurationNamingContext
        $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $ca = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } -SearchBase $searchBase -Properties * | Select-Object -First 1
        if ($ca -and ($ca.PSObject.Properties.Name -contains 'CAEnrollmentEndpoint')) {
            if ($ca.CAEnrollmentEndpoint -match '^http:') {
                $results += [PSCustomObject]@{
                    Vulnerability = "ESC8"
                    CA            = $ca.Name
                    Issue         = "HTTP enrollment endpoint detected: $($ca.CAEnrollmentEndpoint)."
                    Recommendation= "Configure the endpoint to use HTTPS."
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve the CA or its CAEnrollmentEndpoint property."
    }
    return $results
}

function Find-ESC11 {
    $results = @()
    try {
        $configNC = (Get-ADRootDSE).ConfigurationNamingContext
        $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $ca = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } -SearchBase $searchBase -Properties * | Select-Object -First 1
        if ($ca -and ($ca.PSObject.Properties.Name -contains 'InterfaceFlag')) {
            if ($ca.InterfaceFlag -ne 'Yes') {
                $results += [PSCustomObject]@{
                    Vulnerability = "ESC11"
                    CA            = $ca.Name
                    Issue         = "IF_ENFORCEENCRYPTICERTREQUEST is disabled."
                    Recommendation= "Enable IF_ENFORCEENCRYPTICERTREQUEST on the CA."
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve the CA or its InterfaceFlag property."
    }
    return $results
}

function Find-ESC13 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.PSObject.Properties.Name -contains 'msDS-OIDToGroupLink') {
            if ($tpl.'msDS-OIDToGroupLink') {
                $results += [PSCustomObject]@{
                    Vulnerability = "ESC13"
                    Template      = $tpl.Name
                    Issue         = "Template linked to group $($tpl.'msDS-OIDToGroupLink') without proper controls."
                    Recommendation= "Review the linkage and enforce controls (e.g., Manager Approval)."
                }
            }
        }
    }
    return $results
}

function Find-ESC15 {
    param([array]$Templates)
    $results = @()
    foreach ($tpl in $Templates) {
        if ($tpl.'msPKI-Template-Schema-Version' -eq 1) {
            $results += [PSCustomObject]@{
                Vulnerability = "ESC15"
                Template      = $tpl.Name
                Issue         = "Template uses schema version 1 (EKUwu)."
                Recommendation= "Upgrade to schema v2 or restrict permissions."
            }
        }
    }
    return $results
}

function Invoke-PKIScanAdvanced {
    Write-Host "Starting AD CS vulnerability scan (Enterprise CA)..." -ForegroundColor Cyan

    $cas = Test-CAExistenceInAD
    if (-not $cas) {
        Write-Host "Exiting: AD CS scan will not be executed." -ForegroundColor Red
        return
    }

    $templates = Get-ADCSCertificateTemplates

    $results_ESC1  = Find-ESC1 -Templates $templates
    $results_ESC2  = Find-ESC2 -Templates $templates
    $results_ESC3  = Find-ESC3 -Templates $templates
    $results_ESC4  = Find-ESC4 -Templates $templates
    $results_ESC5  = Find-ESC5
    $results_ESC6  = Find-ESC6
    $results_ESC8  = Find-ESC8
    $results_ESC11 = Find-ESC11
    $results_ESC13 = Find-ESC13 -Templates $templates
    $results_ESC15 = Find-ESC15 -Templates $templates

    $allResults = $results_ESC1 + $results_ESC2 + $results_ESC3 + $results_ESC4 + `
                  $results_ESC5 + $results_ESC6 + $results_ESC8 + $results_ESC11 + `
                  $results_ESC13 + $results_ESC15

    if ($allResults.Count -eq 0) {
        Write-Host "No vulnerabilities were detected in AD CS." -ForegroundColor Green
    }
    else {
        Write-Host "The following vulnerabilities were detected:" -ForegroundColor Yellow
        $allResults | Format-Table -AutoSize
    }

    $csvPath = Join-Path -Path $PWD -ChildPath "PKI_Vulnerabilities_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Results exported to $csvPath" -ForegroundColor Magenta
}

Invoke-PKIScanAdvanced

Write-Host "`nPress any key to return to the menu..."
[System.Console]::ReadKey($true) | Out-Null
'@

$PKITemplateReport = @'
<# =======================================================================
  AD CS / Certificate Templates – Advanced Audit      (version 2025-06-13)
  • Always audits templates, whether or not an Enterprise CA exists.
  • Normalises nTSecurityDescriptor (byte[], SDDL string, or security
    objects) to avoid RawSecurityDescriptor errors.
  • Only runs checks that require a CA when at least one CA is detected.
  • Always exports findings to CSV (same folder, timestamped filename).
  ======================================================================= #>

Import-Module ActiveDirectory -ErrorAction Stop   # Requires RSAT-AD-PowerShell

#----------------------------------------------------
#  Helper: normalise a security descriptor
#----------------------------------------------------
function Get-RawDescriptor {
    param($Descriptor)

    switch ($Descriptor.GetType().FullName) {
        'System.Byte[]' {
            return [System.Security.AccessControl.RawSecurityDescriptor]::new($Descriptor,0)
        }
        'System.String' {
            return [System.Security.AccessControl.RawSecurityDescriptor]::new($Descriptor)
        }
        { $_ -like 'System.*Security.*Descriptor*' } {
            $bytes = New-Object byte[] $Descriptor.BinaryLength
            $Descriptor.GetBinaryForm($bytes,0)
            return [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes,0)
        }
        default { return $null }
    }
}

#----------------------------------------------------
#  Detect CAs and enumerate templates
#----------------------------------------------------
function Test-CAExistenceInAD {
    try {
        $cfgNC  = (Get-ADRootDSE).ConfigurationNamingContext
        $base   = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNC"
        $cas = Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" `
                             -SearchBase $base -Properties Name,dNSHostName,DisplayName
        if ($cas) {
            Write-Host "[+] Enterprise CA(s) detected:" -ForegroundColor Green
            $cas | ForEach-Object {
                Write-Host "   - $($_.DisplayName) ($($_.dNSHostName))" -ForegroundColor Cyan
            }
        } else {
            Write-Warning "[-] No Enterprise CA (pKIEnrollmentService) found."
        }
        return $cas
    } catch {
        Write-Error "Error while checking CAs in AD: $_"
        return @()
    }
}

function Get-ADCSCertificateTemplates {
    $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext
    $base  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfgNC"
    Get-ADObject -Filter "objectClass -eq 'pKICertificateTemplate'" `
                 -SearchBase $base -Properties *
}

#----------------------------------------------------
#  ESCx checks
#----------------------------------------------------
function Find-ESC1 { param($Templates)
    foreach ($tpl in $Templates) {
        if ($tpl.pKIExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2' -and
            -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            [PSCustomObject]@{
                Vulnerability = 'ESC1'
                Template      = $tpl.Name
                Issue         = 'SAN allowed without manager approval'
                Recommendation= 'Enable manager approval (bit 2).'
            }
        }
    }
}

function Find-ESC2 { param($Templates)
    foreach ($tpl in $Templates) {
        if ($tpl.pKIExtendedKeyUsage -match '2\.5\.29\.37\.0' -and
            -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            [PSCustomObject]@{
                Vulnerability = 'ESC2'
                Template      = $tpl.Name
                Issue         = 'High-privilege EKU without approval'
                Recommendation= 'Enable manager approval or restrict the EKU set.'
            }
        }
    }
}

function Find-ESC3 { param($Templates)
    foreach ($tpl in $Templates) {
        if ($tpl.pKIExtendedKeyUsage -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.1' -and
            -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            [PSCustomObject]@{
                Vulnerability = 'ESC3'
                Template      = $tpl.Name
                Issue         = 'Enrollment Agent template without approval (condition 1)'
                Recommendation= 'Enable manager approval.'
            }
        }
        if (($tpl.'msPKI-RA-Signature' -eq 1) -and
            -not ($tpl.'msPKI-Enrollment-Flag' -band 2)) {
            [PSCustomObject]@{
                Vulnerability = 'ESC3'
                Template      = $tpl.Name
                Issue         = 'RA Signature enabled without approval (condition 2)'
                Recommendation= 'Review and enable manager approval.'
            }
        }
    }
}

function Find-ESC4 { param($Templates)
    foreach ($tpl in $Templates) {
        $sd = Get-RawDescriptor $tpl.nTSecurityDescriptor
        if ($sd) {
            foreach ($ace in $sd.DiscretionaryAcl) {
                if ($ace.AccessMask -band 0x10000000) {   # GenericAll
                    [PSCustomObject]@{
                        Vulnerability = 'ESC4'
                        Template      = $tpl.Name
                        Issue         = "GenericAll granted to $($ace.SecurityIdentifier)"
                        Recommendation= 'Harden the DACL (remove GenericAll).'
                    }
                }
            }
        }
    }
}

function Find-ESC5 {
    $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext
    $base  = "CN=Public Key Services,CN=Services,$cfgNC"
    $ntAuth = Get-ADObject -Filter "Name -eq 'NTAuthCertificates'" `
                           -SearchBase $base -Properties nTSecurityDescriptor
    if ($ntAuth) {
        $sd = Get-RawDescriptor $ntAuth.nTSecurityDescriptor
        if ($sd) {
            foreach ($ace in $sd.DiscretionaryAcl) {
                if ($ace.AccessMask -band 0x10000000) {
                    [PSCustomObject]@{
                        Vulnerability = 'ESC5'
                        Object        = $ntAuth.Name
                        Issue         = "GenericAll granted to $($ace.SecurityIdentifier)"
                        Recommendation= 'Restrict permissions on NTAuthCertificates.'
                    }
                }
            }
        }
    }
}

function Find-ESC6 {   # Requires CA
    $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext
    $base  = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNC"
    foreach ($ca in Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" `
                                 -SearchBase $base -Properties EditFlags,DisplayName) {
        if ($ca.EditFlags -band 0x20) {  # EDITF_ATTRIBUTESUBJECTALTNAME2
            [PSCustomObject]@{
                Vulnerability = 'ESC6'
                CA            = $ca.DisplayName
                Issue         = 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled'
                Recommendation= 'Disable this CA flag.'
            }
        }
    }
}

function Find-ESC8 {   # Requires CA
    $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext
    $base  = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNC"
    foreach ($ca in Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" `
                                 -SearchBase $base -Properties CAEnrollmentEndpoint,DisplayName) {
        if ($ca.CAEnrollmentEndpoint -match '^http:' ) {
            [PSCustomObject]@{
                Vulnerability = 'ESC8'
                CA            = $ca.DisplayName
                Issue         = "HTTP enrollment endpoint detected: $($ca.CAEnrollmentEndpoint)"
                Recommendation= 'Configure the endpoint to use HTTPS.'
            }
        }
    }
}

function Find-ESC11 {  # Requires CA
    $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext
    $base  = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfgNC"
    foreach ($ca in Get-ADObject -Filter "objectClass -eq 'pKIEnrollmentService'" `
                                 -SearchBase $base -Properties InterfaceFlags,DisplayName) {
        if (-not ($ca.InterfaceFlags -band 0x80)) {  # IF_ENFORCEENCRYPTICERTREQUEST
            [PSCustomObject]@{
                Vulnerability = 'ESC11'
                CA            = $ca.DisplayName
                Issue         = 'IF_ENFORCEENCRYPTICERTREQUEST is disabled'
                Recommendation= 'Enable this flag on the CA.'
            }
        }
    }
}

function Find-ESC13 { param($Templates)
    foreach ($tpl in $Templates) {
        if ($tpl.'msDS-OIDToGroupLink') {
            [PSCustomObject]@{
                Vulnerability = 'ESC13'
                Template      = $tpl.Name
                Issue         = "Template linked to group $($tpl.'msDS-OIDToGroupLink')"
                Recommendation= 'Review the link and require approval.'
            }
        }
    }
}

function Find-ESC15 { param($Templates)
    foreach ($tpl in $Templates) {
        if ($tpl.'msPKI-Template-Schema-Version' -eq 1) {
            [PSCustomObject]@{
                Vulnerability = 'ESC15'
                Template      = $tpl.Name
                Issue         = 'Schema version 1 (legacy)'
                Recommendation= 'Upgrade to v2/v3 or tighten permissions.'
            }
        }
    }
}

#----------------------------------------------------
#  Main execution
#----------------------------------------------------
function Invoke-PKIAudit {

    $CsvPath = Join-Path $PWD "PKI_Vulnerabilities_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"

    Write-Host "`n=== AD CS / Template audit started ===" -ForegroundColor Cyan

    $cas       = Test-CAExistenceInAD
    $templates = Get-ADCSCertificateTemplates
    if (!$templates) { Write-Error "No certificate templates retrieved."; return }

    $result  =  Find-ESC1  $templates
    $result +=  Find-ESC2  $templates
    $result +=  Find-ESC3  $templates
    $result +=  Find-ESC4  $templates
    $result +=  Find-ESC5
    $result +=  Find-ESC13 $templates
    $result +=  Find-ESC15 $templates

    if ($cas.Count) {
        $result += Find-ESC6
        $result += Find-ESC8
        $result += Find-ESC11
    } else {
        Write-Host "Skipping ESC6/8/11 (require a CA)..." -ForegroundColor DarkYellow
    }

    if ($result.Count) {
        Write-Host "`nVulnerabilities detected:" -ForegroundColor Yellow
        $result | Sort-Object Vulnerability | Format-Table -AutoSize
    } else {
        Write-Host "✔ No vulnerabilities found." -ForegroundColor Green
    }

    # ----------- Always export to CSV -----------------------------------
    try {
        $result | Export-Csv -Path $CsvPath -NoTypeInformation -Force
        Write-Host "`n[+] Findings exported to: $CsvPath" -ForegroundColor Magenta
    } catch {
        Write-Error "Failed to export CSV: $_"
    }

    Write-Host "=== Audit completed ===`n"
}

#----------------------------------------------------
#  Direct run
#----------------------------------------------------
Invoke-PKIAudit

# Ask for a key only if running in an interactive console
try {
    if ($host.Name -eq 'ConsoleHost') {
        Write-Host "Press any key to exit..."
        [Console]::ReadKey($true) | Out-Null
    }
} catch { }
'@


#endregion pki report

#region main



###############################################################################
# AD VULNBUSTER GUI - Menú 
###############################################################################
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
##############################################################################


$colorList = @(
    [System.Drawing.Color]::Red,
    [System.Drawing.Color]::Yellow,
    [System.Drawing.Color]::Cyan,
    [System.Drawing.Color]::Magenta,
    [System.Drawing.Color]::Green,
    [System.Drawing.Color]::Blue
)

$randomColor = $colorList | Get-Random

# ------------------------------------------------------------------------------------
# ASCII Title (Color Cyan).
# ------------------------------------------------------------------------------------
$TitleAscii = @"
 █████  ██████      ██    ██ ██    ██ ██      ███    ██ ██████  ██    ██ ███████ ████████ ███████ ██████  
██   ██ ██   ██     ██    ██ ██    ██ ██      ████   ██ ██   ██ ██    ██ ██         ██    ██      ██   ██ 
███████ ██   ██     ██    ██ ██    ██ ██      ██ ██  ██ ██████  ██    ██ ███████    ██    █████   ██████  
██   ██ ██   ██      ██  ██  ██    ██ ██      ██  ██ ██ ██   ██ ██    ██      ██    ██    ██      ██   ██ 
██   ██ ██████        ████    ██████  ███████ ██   ████ ██████   ██████  ███████    ██    ███████ ██   ██ 

                                                                                                          
                                                                                                          
"@

# ------------------------------------------------------------------------------------
# ASCII logo "GHOST" (red).
# ------------------------------------------------------------------------------------
$GhostAscii = @"
                                       =@@*                                         
                                 #@@@@@@@@@@@%:                                     
                                *@@@@@@@@@@@@@* .=-:.                                
                             ...#@@%+:..    ..=: =++***++-.                           
                         .=***.-*       .:=*##*%---.    :****:                       
                      .=*****+ =-:+%@@@@@@@@@@@@@@@@@@@@. *****+-                    
                    :+***+-. :=#@@@@@@@@@@@@@@@@@@@@@@%= :********=.                 
                  -****+. =#@@@@@%#+====--:::-=- :%%=. :+***********+.              
                :**-**- -@@@@@@+ :-+=@@=+-#-+-#@:@=      =************+              
               =++****+ .#%%%%@@+=@++:*-%*=@#=-.:@#.       .=***********:           
             .*=:+******-     :@@=-+:::%@@#---:+@%:           -**********=          
            :*:-******=.       :%@@@@@@@@@@@@@@@@@%.            -*********+.        
           -*#*******-         *@@@@@@@@@@@@@@@@@@@@:-#-        -***********        
          :+:+******.      .%.#@@@@@@@@@@@@@@@@@@@@@@+-@@@+   +**************       
         .*++*****+       *#.%@@@@@@@@@@@@@@@@@@@@@@@@=-#- .+****************+      
         +*******+.      -::@@@@@@%+%@@@@@@@@@*:=@@@@@+  -********************=     
        =********:     :@@#.*@@@@@%-  .+%@%=.   #@@- .+************: =********.     
       .+*******-     +@@@@@=.%@@@@*    +@@.    @#. -************=  ++ +*******-    
       -*******+.    +@@@@@@%=.*@@@%:   +@@*     .=***********+- :#@@@:.*******+*#= 
  .--: =*******=   -%@@@@@%: #@@@@@@=    #@    :+***********=. =%@@@@@@.********#-  
  -*%@@#*******- .#@@@@@@@@@*.#@@@@@%.  .#+ .=************- .*@@@@@@@@%*********:   
     *@#*******-+@@@@@@@@@@@@%.-%@@@@-    .+************: .%@@@@@@@@@@@@#*******-   
   :@@@#*******#@@@@@@@@@@@@: %@@@@@@*  -************+. =@@%-.+%@@@@@@@@#*******=.  
  =%%###*******#@@@@@@@@@@@@%=-%@@%+ .=***********+- :*@@@@@@% =@@@@@@@@********%@@*.
     .##*******#@@@@@@@@%- -#@+-*: :+***********+. =%@#+%@@@%.*@@@@@@@@@********.... 
    .@@#********%@@@@@+  =@@@@+  =************=  +@@#.+@@@@@# -#*=.    -*******#+    
        +*******#@%::  *@@@%: .+************:   *@@@@@+ .@@@@@%#%@@@@= ********==:   
        :********%@     +*: :************=. .   @@@@@@*.#@@@@@@@@@@@+ =*******+.     
         +********-      .=************- :*@+  :@@@@@%:+@@@@@@@@@@@* -********-      
          *********.   :+***********+.   #@@*  +@@@@@:=@@@@@@@@@@@= :********=       
          .*********--************=  *@: *@@#. %@@@@:-@@@@@@@@@@@- -********+        
           :+******************+: .#@@@*.#@@#..@@@@-:@@@@@@@@@@%-.+********+         
            .+***************=..+@=-@@@%-#@@%-=@@@+:@@@@@@@@@@= :+********=          
              +************- .#@@@@==@@@= %@= *@@#:#@@@@@@@@= .+*********=           
               :***********. :@@@@@@=+@@#. = .#@%-#@@@@@@%  -***********.            
                .=***********+. .*#@@++@@:   -@@+*@@%#+. :+***********-              
                  .+************+-:.  .-=:   :+=-:  :-=*************-.               
                    .=****************++========++****************-                   
                       :***************************************+.                    
                          :+********************************=.                       
                             .:=+**********************+-:.                           
                                  ..:--=++***++==--:.        
"@

# ------------------------------------------------------------------------------------
# Main menu
# ------------------------------------------------------------------------------------
function Show-MainMenu {
    # Ventana Principal recortada
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "AD VulnBuster - Main Menu"
    $Form.StartPosition = "CenterScreen"
    $Form.BackColor = [System.Drawing.Color]::Black
    $Form.Size = New-Object System.Drawing.Size(900,850)
    $Form.FormBorderStyle = 'FixedSingle'

    # Título (Cyan)
    $labelTitle = New-Object System.Windows.Forms.Label
    $labelTitle.AutoSize = $true
    $labelTitle.ForeColor = [System.Drawing.Color]::Cyan
    $labelTitle.Font = New-Object System.Drawing.Font("Lucida Console",10)
    $labelTitle.BackColor = [System.Drawing.Color]::Black
    $labelTitle.Text = $TitleAscii
    $labelTitle.Location = New-Object System.Drawing.Point(10,10)
    $Form.Controls.Add($labelTitle)

    # Logo (Rojo) con fuente 6 (original)
    $labelLogo = New-Object System.Windows.Forms.Label
    $labelLogo.AutoSize = $true
    #$labelLogo.ForeColor = [System.Drawing.Color]::Red
    $labelLogo.ForeColor = $randomColor
    $labelLogo.Font = New-Object System.Drawing.Font("Lucida Console",6,[System.Drawing.FontStyle]::Regular)
    $labelLogo.BackColor = [System.Drawing.Color]::Black
    $labelLogo.Text = $GhostAscii
    $labelLogo.Location = New-Object System.Drawing.Point(210,130)
    $Form.Controls.Add($labelLogo)

    # Versión
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Text = "MENU"
    $versionLabel.ForeColor = [System.Drawing.Color]::Cyan
    $versionLabel.Font = New-Object System.Drawing.Font("Lucida Console",12,[System.Drawing.FontStyle]::Bold)
    $versionLabel.BackColor = [System.Drawing.Color]::Black
    $versionLabel.AutoSize = $true
    $versionLabel.Location = New-Object System.Drawing.Point(10, 480)
    $Form.Controls.Add($versionLabel)

  
    $SubMenuPanel = New-Object System.Windows.Forms.Panel
    #$SubMenuPanel.Location = New-Object System.Drawing.Point(520,140)
    $SubMenuPanel.Location = New-Object System.Drawing.Point(200,470)
    #$SubMenuPanel.Size = New-Object System.Drawing.Size(340,550)
    $SubMenuPanel.Size = New-Object System.Drawing.Size(500,200)
    $SubMenuPanel.BackColor = [System.Drawing.Color]::Black
    $Form.Controls.Add($SubMenuPanel)

    # Botón DCSync
    $btnDCSync = New-Object System.Windows.Forms.Button
    $btnDCSync.Text = "DCSync"
    $btnDCSync.ForeColor = [System.Drawing.Color]::Cyan
    $btnDCSync.BackColor = [System.Drawing.Color]::Black
    $btnDCSync.FlatStyle = "Flat"
    $btnDCSync.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnDCSync.Location = New-Object System.Drawing.Point(10, 520)
    $btnDCSync.Width = 120
    $btnDCSync.Add_Click({
        $SubMenuPanel.Controls.Clear()
        $labelLogo.ForeColor = [System.Drawing.Color]::Cyan
        Show-DCSyncMenu -SubMenuPanel $SubMenuPanel
    })
    $Form.Controls.Add($btnDCSync)

    # Botón Kerberos
    $btnKerberos = New-Object System.Windows.Forms.Button
    $btnKerberos.Text = "Kerberos"
    $btnKerberos.ForeColor = [System.Drawing.Color]::Lime
    $btnKerberos.BackColor = [System.Drawing.Color]::Black
    $btnKerberos.FlatStyle = "Flat"
    $btnKerberos.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnKerberos.Location = New-Object System.Drawing.Point(10, 560)
    $btnKerberos.Width = 120
    $btnKerberos.Add_Click({
        $SubMenuPanel.Controls.Clear()
        $labelLogo.ForeColor = [System.Drawing.Color]::Lime
        Show-KerberosMenu -SubMenuPanel $SubMenuPanel
    })
    $Form.Controls.Add($btnKerberos)

    # Botón Audit
    $btnAudit = New-Object System.Windows.Forms.Button
    $btnAudit.Text = "Audit Tools"
    $btnAudit.ForeColor = [System.Drawing.Color]::Magenta
    $btnAudit.BackColor = [System.Drawing.Color]::Black
    $btnAudit.FlatStyle = "Flat"
    $btnAudit.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnAudit.Location = New-Object System.Drawing.Point(10, 600)
    $btnAudit.Width = 120
    $btnAudit.Add_Click({
        $SubMenuPanel.Controls.Clear()
        $labelLogo.ForeColor = [System.Drawing.Color]::Magenta
        Show-OtherToolsMenu -SubMenuPanel $SubMenuPanel
    })
    $Form.Controls.Add($btnAudit)

    # Botón Exit
    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "Exit"
    $btnExit.ForeColor = [System.Drawing.Color]::Yellow
    $btnExit.BackColor = [System.Drawing.Color]::Black
    $btnExit.FlatStyle = "Flat"
    $btnExit.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnExit.Location = New-Object System.Drawing.Point(10, 640)
    $btnExit.Width = 120
    $btnExit.Add_Click({ $Form.Close() })
    $Form.Controls.Add($btnExit)

    # Barra BBS (multilínea)
    $bbsLabel = New-Object System.Windows.Forms.Label
    $bbsLabel.Text = @"
=====================================================================================
    Registered | AD-VULNBUSTER AUDIT TOOL V.5.6 | 38400 N81 FDX | Online 00:01 
=====================================================================================
"@
    $bbsLabel.ForeColor = [System.Drawing.Color]::Yellow
    $bbsLabel.BackColor = [System.Drawing.Color]::DarkRed
    $bbsLabel.Font = New-Object System.Drawing.Font("Lucida Console", 12)
    $bbsLabel.AutoSize = $true
    $bbsLabel.Location = New-Object System.Drawing.Point(10, 690)
    $Form.Controls.Add($bbsLabel)

    # Frase adicional debajo del BBS
$jocaroloLabel = New-Object System.Windows.Forms.Label
$jocaroloLabel.Text = "Jocarolo Technologies 2025."
$jocaroloLabel.ForeColor = [System.Drawing.Color]::Cyan
$jocaroloLabel.BackColor = [System.Drawing.Color]::Black
$jocaroloLabel.Font = New-Object System.Drawing.Font("Lucida Console", 10,[System.Drawing.FontStyle]::Bold)
$jocaroloLabel.AutoSize = $true


$jocaroloLabel.Location = New-Object System.Drawing.Point(300, 770)
$Form.Controls.Add($jocaroloLabel)

    # Mostrar la ventana principal
    $Form.ShowDialog()

   
}

# ------------------------------------------------------------------------------------
# (4) Submenú DCSync
# ------------------------------------------------------------------------------------
function Show-DCSyncMenu {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Panel]$SubMenuPanel
    )

    # Título
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "DCSync Menu"
    $label.ForeColor = [System.Drawing.Color]::Cyan
    $label.Font = New-Object System.Drawing.Font("Lucida Console",14,[System.Drawing.FontStyle]::Bold)
    $label.BackColor = [System.Drawing.Color]::Black
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(10,10)
    $SubMenuPanel.Controls.Add($label)

    # Check DCSync
    $btnCheck = New-Object System.Windows.Forms.Button
    $btnCheck.Text = "Check DCSync Rights"
    $btnCheck.ForeColor = [System.Drawing.Color]::Cyan
    $btnCheck.BackColor = [System.Drawing.Color]::Black
    $btnCheck.FlatStyle = "Flat"
    $btnCheck.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnCheck.Location = New-Object System.Drawing.Point(10,50)
    $btnCheck.Width = 180
    $btnCheck.Add_Click({
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($checkDcsyncScript)
        $encodedScript = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe -ArgumentList '-NoExit', '-EncodedCommand', $encodedScript
    })
    $SubMenuPanel.Controls.Add($btnCheck)

    # Remove DCSync
    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Text = "Remove DCSync Rights"
    $btnRemove.ForeColor = [System.Drawing.Color]::Cyan
    $btnRemove.BackColor = [System.Drawing.Color]::Black
    $btnRemove.FlatStyle = "Flat"
    $btnRemove.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnRemove.Location = New-Object System.Drawing.Point(10,90)
    $btnRemove.Width = 180
    $btnRemove.Add_Click({
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($removeDcsyncScript)
        $encodedScript = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe -ArgumentList '-NoExit', '-EncodedCommand', $encodedScript
    })
    $SubMenuPanel.Controls.Add($btnRemove)

    # Restore DCSync
    $btnRestore = New-Object System.Windows.Forms.Button
    $btnRestore.Text = "Restore DCsync Rights"
    $btnRestore.ForeColor = [System.Drawing.Color]::Cyan
    $btnRestore.BackColor = [System.Drawing.Color]::Black
    $btnRestore.FlatStyle = "Flat"
    $btnRestore.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnRestore.Location = New-Object System.Drawing.Point(10,130)
    $btnRestore.Width = 180
    $btnRestore.Add_Click({
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($restoreDcsyncScript)
    $encodedScript = [Convert]::ToBase64String($bytes)
     Start-Process powershell.exe -ArgumentList '-NoExit', '-EncodedCommand', $encodedScript
    })
    $SubMenuPanel.Controls.Add($btnRestore)

    # Botón Back
    $btnBack = New-Object System.Windows.Forms.Button
    $btnBack.Text = "Back"
    $btnBack.ForeColor = [System.Drawing.Color]::Yellow
    $btnBack.BackColor = [System.Drawing.Color]::Black
    $btnBack.FlatStyle = "Flat"
    $btnBack.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnBack.Location = New-Object System.Drawing.Point(10,170)
    $btnBack.Width = 180
    $btnBack.Add_Click({
        $SubMenuPanel.Controls.Clear()
    })
    $SubMenuPanel.Controls.Add($btnBack)
}

# ------------------------------------------------------------------------------------
# (5) Submenú Kerberos
# ------------------------------------------------------------------------------------
function Show-KerberosMenu {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Panel]$SubMenuPanel
    )

    # Título
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Kerberos Menu"
    $label.ForeColor = [System.Drawing.Color]::Lime
    $label.Font = New-Object System.Drawing.Font("Lucida Console",14,[System.Drawing.FontStyle]::Bold)
    $label.BackColor = [System.Drawing.Color]::Black
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(10,10)
    $SubMenuPanel.Controls.Add($label)

    # GoldenTicket
    $btn1 = New-Object System.Windows.Forms.Button
    $btn1.Text = "GoldenTicket Detect"
    $btn1.ForeColor = [System.Drawing.Color]::Lime
    $btn1.BackColor = [System.Drawing.Color]::Black
    $btn1.FlatStyle = "Flat"
    $btn1.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn1.Location = New-Object System.Drawing.Point(10,50)
    $btn1.Width = 180
    $btn1.Add_Click({
        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "temp_detectGoldenTicket.ps1")
        Set-Content -Path $tempPath -Value $detectGoldenTicketScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempPath
    })
    $SubMenuPanel.Controls.Add($btn1)

    # SilverTicket
    $btn2 = New-Object System.Windows.Forms.Button
    $btn2.Text = "SilverTicket Detect"
    $btn2.ForeColor = [System.Drawing.Color]::Lime
    $btn2.BackColor = [System.Drawing.Color]::Black
    $btn2.FlatStyle = "Flat"
    $btn2.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn2.Location = New-Object System.Drawing.Point(10,90)
    $btn2.Width = 180
    $btn2.Add_Click({
        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "temp_detectSilverTicket.ps1")
        Set-Content -Path $tempPath -Value $detectSilverTicketScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempPath
    })
    $SubMenuPanel.Controls.Add($btn2)

    # DiamondTicket
    $btn3 = New-Object System.Windows.Forms.Button
    $btn3.Text = "DiamondTicket Detect"
    $btn3.ForeColor = [System.Drawing.Color]::Lime
    $btn3.BackColor = [System.Drawing.Color]::Black
    $btn3.FlatStyle = "Flat"
    $btn3.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn3.Location = New-Object System.Drawing.Point(10,130)
    $btn3.Width = 180
    $btn3.Add_Click({
        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "temp_detectDiamondTicket.ps1")
        Set-Content -Path $tempPath -Value $detectDiamondTicketScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempPath
    })
    $SubMenuPanel.Controls.Add($btn3)

    # Botón Back
    $btnBack = New-Object System.Windows.Forms.Button
    $btnBack.Text = "Back"
    $btnBack.ForeColor = [System.Drawing.Color]::Yellow
    $btnBack.BackColor = [System.Drawing.Color]::Black
    $btnBack.FlatStyle = "Flat"
    $btnBack.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnBack.Location = New-Object System.Drawing.Point(10,170)
    $btnBack.Width = 180
    $btnBack.Add_Click({
        $SubMenuPanel.Controls.Clear()
    })
    $SubMenuPanel.Controls.Add($btnBack)
}

# ------------------------------------------------------------------------------------
# (6) Submenú: Audit Tools
# ------------------------------------------------------------------------------------
function Show-OtherToolsMenu {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Panel]$SubMenuPanel
    )

    # Título
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Audit Tools"
    $label.ForeColor = [System.Drawing.Color]::Magenta
    $label.Font = New-Object System.Drawing.Font("Lucida Console",14,[System.Drawing.FontStyle]::Bold)
    $label.BackColor = [System.Drawing.Color]::Black
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(10,10)
    $SubMenuPanel.Controls.Add($label)

    # ACL Report
    $btn1 = New-Object System.Windows.Forms.Button
    $btn1.Text = "ACL Report"
    $btn1.ForeColor = [System.Drawing.Color]::Magenta
    $btn1.BackColor = [System.Drawing.Color]::Black
    $btn1.FlatStyle = "Flat"
    $btn1.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn1.Location = New-Object System.Drawing.Point(10,50)
    $btn1.Width = 220
    $btn1.Add_Click({
        $tempFileName  = "temp_acl_{0}.ps1" -f (Get-Random)
        $tempScriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tempFileName)
        Set-Content -Path $tempScriptPath -Value $aclScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempScriptPath
    })
    $SubMenuPanel.Controls.Add($btn1)

    # PKI Audit Reports
    $btn2 = New-Object System.Windows.Forms.Button
    $btn2.Text = "PKI Audit Report"
    $btn2.ForeColor = [System.Drawing.Color]::Magenta
    $btn2.BackColor = [System.Drawing.Color]::Black
    $btn2.FlatStyle = "Flat"
    $btn2.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn2.Location = New-Object System.Drawing.Point(10,90)
    $btn2.Width = 220
    $btn2.Add_Click({
        $tempFileName  = "temp_pkiReport_{0}.ps1" -f (Get-Random)
        $tempScriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tempFileName)
        Set-Content -Path $tempScriptPath -Value $pkiReportScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempScriptPath
    })
    $SubMenuPanel.Controls.Add($btn2)

     # PKI Audit Template Reports
    $btn5 = New-Object System.Windows.Forms.Button
    $btn5.Text = "PKI Audit Template"
    $btn5.ForeColor = [System.Drawing.Color]::Magenta
    $btn5.BackColor = [System.Drawing.Color]::Black
    $btn5.FlatStyle = "Flat"
    $btn5.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn5.Location = New-Object System.Drawing.Point(240,50)
    $btn5.Width = 220
    $btn5.Add_Click({
        $tempFileName  = "temp_pkiReport_{0}.ps1" -f (Get-Random)
        $tempScriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tempFileName)
        Set-Content -Path $tempScriptPath -Value $PKITemplateReport -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempScriptPath
    })
    $SubMenuPanel.Controls.Add($btn5)

    # AD VulnBuster Report
    $btn3 = New-Object System.Windows.Forms.Button
    $btn3.Text = "AD VulnBuster Report"
    $btn3.ForeColor = [System.Drawing.Color]::Magenta
    $btn3.BackColor = [System.Drawing.Color]::Black
    $btn3.FlatStyle = "Flat"
    $btn3.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn3.Location = New-Object System.Drawing.Point(10,130)
    $btn3.Width = 220
    $btn3.Add_Click({
        $tempScriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "temp_reporte.ps1")
        Set-Content -Path $tempScriptPath -Value ($reporteScript + "`nreporte") -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempScriptPath
    })
    $SubMenuPanel.Controls.Add($btn3)

    # Escalation Paths Full
    $btn4 = New-Object System.Windows.Forms.Button
    $btn4.Text = "Escalation Paths Full"
    $btn4.ForeColor = [System.Drawing.Color]::Magenta
    $btn4.BackColor = [System.Drawing.Color]::Black
    $btn4.FlatStyle = "Flat"
    $btn4.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btn4.Location = New-Object System.Drawing.Point(10,170)
    $btn4.Width = 220
    $btn4.Add_Click({
        $tempScriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "temp_escalationPathFull.ps1")
        Set-Content -Path $tempScriptPath -Value $escalationPathFullScript -Encoding UTF8
        Start-Process powershell.exe -ArgumentList '-NoExit', '-File', $tempScriptPath
    })
    $SubMenuPanel.Controls.Add($btn4)

   

     # Botón Back
    $btnBack = New-Object System.Windows.Forms.Button
    $btnBack.Text = "Back"
    $btnBack.ForeColor = [System.Drawing.Color]::Yellow
    $btnBack.BackColor = [System.Drawing.Color]::Black
    $btnBack.FlatStyle = "Flat"
    $btnBack.Font = New-Object System.Drawing.Font("Lucida Console", 10)
    $btnBack.Location = New-Object System.Drawing.Point(240,90)
    $btnBack.Width = 220
    $btnBack.Add_Click({
        $SubMenuPanel.Controls.Clear()
    })
    $SubMenuPanel.Controls.Add($btnBack)
}

# ------------------------------------------------------------------------------------
# (7) Ejecutar el Menú Principal
# ------------------------------------------------------------------------------------
Show-MainMenu

Write-Host "Cerrando la aplicación, borrando archivos temporales..."
Get-ChildItem -Path $env:TEMP -Filter "temp_*.ps1" | ForEach-Object {
    Write-Host "Borrando archivo: $($_.FullName)"
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
}


#endregion main

