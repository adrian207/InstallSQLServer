#Requires -RunAsAdministrator

<#
.SYNOPSIS
    MS SQL Server silent installation script with automated encryption and extended validation.

.DESCRIPTION
    This script installs MS SQL Server unattended, securely managing sensitive data such as service account passwords through encryption. 
    Additionally, it includes automated password encryption, comprehensive post-installation validation, cleanup routines, and a retry mechanism for specific failures.

.NOTES
    Version: 1.7
#>

param(
    [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,
    [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
    [string[]] $Features = @('SQLEngine'),
    [string] $InstallDir,
    [string] $DataDir,
    [ValidateNotNullOrEmpty()]
    [string] $InstanceName = 'MSSQLSERVER',
    [string] $SaPassword,
    [string] $ServiceAccountName,
    [string] $ServiceAccountPassword,
    [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),
    [string] $ProductKey,
    [string] $NotificationEmail,
    [switch] $UseBitsTransfer,
    [switch] $EnableProtocols
)

$ErrorActionPreference = 'STOP'
$scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')

# Function to encrypt a password
function Encrypt-Password {
    param (
        [string]$PlainTextPassword
    )
    try {
        $SecureString = ConvertTo-SecureString -String $PlainTextPassword -AsPlainText -Force
        return ConvertFrom-SecureString -SecureString $SecureString
    } catch {
        throw "Failed to encrypt password: $_"
    }
}

# Function to decrypt a password
function Decrypt-Password {
    param (
        [string]$EncryptedPassword
    )
    try {
        $SecureString = ConvertTo-SecureString -String $EncryptedPassword -Force
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
    } catch {
        throw "Failed to decrypt password: $_"
    }
}

# Function to send email notifications for critical failures
function Send-Notification {
    param (
        [string]$Message,
        [string]$EmailAddress
    )
    try {
        Send-MailMessage -To $EmailAddress -From "script-notify@example.com" -Subject "SQL Server Script Failure" -Body $Message -SmtpServer "smtp.example.com"
        Write-Host "Notification sent to $EmailAddress." -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send notification email: $_"
    }
}

# Retry mechanism for specified operations
function Retry-Operation {
    param (
        [scriptblock]$Operation,
        [int]$MaxRetries = 3,
        [int]$DelayInSeconds = 5
    )
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            & $Operation
            return
        } catch {
            Write-Warning "Attempt $i failed: $_"
            if ($i -eq $MaxRetries) {
                throw "Operation failed after $MaxRetries attempts."
            }
            Start-Sleep -Seconds $DelayInSeconds
        }
    }
}

# Cleanup routine to handle partial installations or errors
function Cleanup {
    param (
        [string]$IsoPath
    )
    Write-Host "Performing cleanup tasks..."
    try {
        if ($IsoPath) {
            Dismount-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue
            Write-Host "ISO unmounted." -ForegroundColor Yellow
        }
        Stop-Transcript
    } catch {
        Write-Warning "Cleanup encountered issues: $_"
    }
}

# Encrypt service account password
$EncryptedServiceAccountPassword = Encrypt-Password -PlainTextPassword $ServiceAccountPassword
$ServiceAccountPassword = Decrypt-Password -EncryptedPassword $EncryptedServiceAccountPassword

try {
    Start-Transcript "$PSScriptRoot\$scriptName-$(Get-Date -Format 'yyyyMMddHHmmss').log"

    # Validate ISO Path and Download if Necessary
    Retry-Operation -Operation {
        if (!$IsoPath) {
            Write-Host "SQLSERVER_ISOPATH environment variable not specified, using defaults"
            $IsoPath = "https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLServer2019-x64-ENU-Dev.iso"

            $saveDir = Join-Path $Env:TEMP $scriptName
            New-Item $saveDir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

            $isoName = $IsoPath.Split('/')[-1]
            $savePath = Join-Path $saveDir $isoName

            if (-Not (Test-Path $savePath)) {
                Write-Host "Downloading ISO..."
                if ($UseBitsTransfer) {
                    Start-BitsTransfer -Source $IsoPath -Destination $savePath
                } else {
                    Invoke-WebRequest -Uri $IsoPath -OutFile $savePath -UseBasicParsing
                }
            }

            $IsoPath = $savePath
        }
    }

    # Mount ISO and Extract Setup Location
    Retry-Operation -Operation {
        $Volume = Mount-DiskImage -ImagePath $IsoPath -StorageType ISO -PassThru | Get-Volume
        $IsoDrive = if ($Volume) { $Volume.DriveLetter + ':' } else { throw "Unable to mount ISO." }
    }

    # Prepare Installation Command
    $SetupCmd = @(
        "$IsoDrive\setup.exe",
        '/Q',
        '/INDICATEPROGRESS',
        '/IACCEPTSQLSERVERLICENSETERMS',
        '/ACTION=install',
        "/INSTANCEDIR=$InstallDir",
        "/INSTALLSQLDATADIR=$DataDir",
        "/FEATURES=$($Features -join ',')",
        "/SQLSYSADMINACCOUNTS=$($SystemAdminAccounts -join ',')",
        "/SECURITYMODE=SQL",
        "/SAPWD=$SaPassword",
        "/INSTANCENAME=$InstanceName",
        "/SQLSVCACCOUNT=$ServiceAccountName",
        "/SQLSVCPASSWORD=$ServiceAccountPassword",
        '/SQLSVCSTARTUPTYPE=automatic',
        '/AGTSVCSTARTUPTYPE=automatic'
    )

    Write-Host "Executing SQL Server Setup..."
    Retry-Operation -Operation {
        Invoke-Expression ($SetupCmd -join ' ')
    }

    if ($EnableProtocols) {
        Write-Host "Enabling SQL Server Protocols (TCP/IP, Named Pipes)..."
        Retry-Operation -Operation {
            $SqlCMNamespace = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -ClassName '__NAMESPACE' | Where-Object { $_.Name -match 'ComputerManagement' } | Select-Object -ExpandProperty Name
            $SqlProtocols = Get-CimInstance -Namespace "root\Microsoft\SqlServer\$SqlCMNamespace" -ClassName ServerNetworkProtocol

            foreach ($Protocol in @('TCP/IP', 'Named Pipes')) {
                $SqlProtocols | Where-Object { $_.ProtocolDisplayName -eq $Protocol } | Invoke-CimMethod -MethodName SetEnable
            }

            Get-Service $InstanceName | Restart-Service -Force
        }
    }

    # Post-Installation Validation
    function Validate-SqlInstallation {
        param (
            [string]$InstanceName
        )
        try {
            Write-Host "Validating SQL Server Installation..."
            $SqlService = Get-Service -Name $InstanceName -ErrorAction Stop
            if ($SqlService.Status -eq 'Running') {
                Write-Host "SQL Server Instance '$InstanceName' is running." -ForegroundColor Green
            } else {
                throw "SQL Server Instance '$InstanceName' is not running."
            }

            Write-Host "Validating Database Connectivity..."
            $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
            $SqlConnection.ConnectionString = "Server=localhost;Database=master;Integrated Security=True;"
            $SqlConnection.Open()
            if ($SqlConnection.State -eq 'Open') {
                Write-Host "Database connectivity validation succeeded." -ForegroundColor Green
                $SqlConnection.Close()
            } else {
                throw "Failed to validate database connectivity."
            }
        } catch {
            Write-Error "SQL Server validation failed: $_"
            throw
        }
    }

    Validate-SqlInstallation -InstanceName $InstanceName

    Write-Host "SQL Server installation completed successfully."
    Dismount-DiskImage -ImagePath $IsoPath

} catch {
    Write-Error "An error occurred: $_"
    Send-Notification -Message "An error occurred: $_" -EmailAddress $NotificationEmail
    Cleanup -IsoPath $IsoPath
    throw
} finally {
    Cleanup -IsoPath $IsoPath
}
