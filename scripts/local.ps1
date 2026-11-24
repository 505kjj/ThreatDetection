#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Setup', 'Start', 'Stop', 'Status', 'CopyToken', 'Rotate')]
    [string] $Action,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,47}$')]
    [string] $Profile = 'default',
    [string] $ExtensionId,
    [ValidateRange(1024, 65535)]
    [int] $Port = 8081,
    [ValidateRange(1, 90)]
    [int] $RetentionDays = 14,
    [ValidateSet('Browser', 'Admin')]
    [string] $Role,
    [switch] $Synthetic,
    [string] $SnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Local setup requires Windows and DPAPI.' }
if ($Action -eq 'Setup' -and $ExtensionId -cnotmatch '^[a-p]{32}$') {
    throw 'Enter the 32-character extension ID displayed in chrome://extensions (letters a through p).'
}
if ($Action -in @('CopyToken', 'Rotate') -and -not $Role) { throw 'Choose -Role Browser or -Role Admin.' }

$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if (-not $localData) { throw 'The Windows local application data directory could not be resolved.' }
$root = Join-Path $localData 'ThreatDetection-local'
$directory = Join-Path $root $Profile
$configFile = Join-Path $directory 'configuration.json'
$processFile = Join-Path $directory 'backend-process.json'
$lockFile = Join-Path $directory 'profile.lock'
$database = Join-Path $directory 'monitoring'
$logFile = Join-Path $directory 'backend.log'
$launchOutput = Join-Path $directory 'launcher-output.log'
$launchErrors = Join-Path $directory 'launcher-error.log'
$repository = Split-Path $PSScriptRoot -Parent
$jar = Join-Path $repository 'backend\target\threat-detection-0.0.1-SNAPSHOT.jar'
if ($root.StartsWith($repository.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The local profile must live outside this repository.'
}

function Assert-PrivateItem([string] $Path, [bool] $IsDirectory) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $IsDirectory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A local profile path is not a plain file or directory.'
    }
    $acl = Get-Acl -LiteralPath $Path
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($userSid) -or
        ($IsDirectory -and -not $acl.AreAccessRulesProtected) -or $rules.Count -eq 0 -or
        @($rules | Where-Object { -not $_.IdentityReference.Equals($userSid) }).Count -ne 0) {
        throw 'A local profile path has unexpected permissions. Use a new profile or restore its user-only ACL.'
    }
}

function Initialize-PrivateDirectory([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($userSid)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($userSid, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    Assert-PrivateItem $Path $true
}

function Save-PrivateJson([string] $Path, [object] $Value) {
    $temporary = Join-Path $directory ([guid]::NewGuid().ToString() + '.tmp')
    $backup = $temporary + '.bak'
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 10 -Compress),
            [Text.UTF8Encoding]::new($false))
        Assert-PrivateItem $temporary $false
        if (Test-Path -LiteralPath $Path) {
            Assert-PrivateItem $Path $false
            [IO.File]::Replace($temporary, $Path, $backup)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        foreach ($file in @($temporary, $backup)) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
        }
    }
}

function Read-PrivateJson([string] $Path) {
    Assert-PrivateItem $Path $false
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function New-Credential {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $rng.GetBytes($bytes)
        $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $secret = ConvertTo-SecureString -String $token -AsPlainText -Force
        $ascii = [Text.Encoding]::ASCII.GetBytes($token)
        try {
            $digest = [BitConverter]::ToString($sha.ComputeHash($ascii)).Replace('-', '').ToLowerInvariant()
            @{ encrypted = ConvertFrom-SecureString -SecureString $secret; digest = $digest }
        } finally {
            [Array]::Clear($ascii, 0, $ascii.Length)
            $secret.Dispose()
        }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $rng.Dispose()
        $sha.Dispose()
    }
}

function Get-ManagedProcess {
    if (-not (Test-Path -LiteralPath $processFile)) { return }
    $record = Read-PrivateJson $processFile
    if ($record.id -isnot [int] -and $record.id -isnot [long]) { throw 'Invalid backend process record.' }
    $process = Get-Process -Id $record.id -ErrorAction SilentlyContinue
    if ($process -and -not $process.HasExited -and
        $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $record.startedAt -and
        $process.Path -ieq $record.java) {
        return $process
    }
    if ($process) { $process.Dispose() }
}

function Confirm-BackendReady([Diagnostics.Process] $Process, [int] $ListenPort) {
    $listeners = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $ListenPort -State Listen -OwningProcess $Process.Id -ErrorAction SilentlyContinue
    if (-not $listeners) { return $false }
    try {
        $request = [Net.WebRequest]::Create("http://127.0.0.1:$ListenPort/api/health")
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.Timeout = 1000
        $response = $request.GetResponse()
        try { return [int] $response.StatusCode -eq 200 }
        finally { $response.Dispose() }
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $_.Exception.Response.Dispose() }
        return $false
    }
}

function Get-Java21 {
    $launcher = (Get-Command java.exe -CommandType Application | Select-Object -First 1).Source
    $probe = [Diagnostics.ProcessStartInfo]::new($launcher, '-XshowSettings:properties -version')
    $probe.UseShellExecute = $false
    $probe.RedirectStandardError = $true
    $probe.CreateNoWindow = $true
    foreach ($name in @('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')) {
        $probe.EnvironmentVariables.Remove($name)
    }
    $java = [Diagnostics.Process]::Start($probe)
    try {
        $properties = $java.StandardError.ReadToEnd()
        $java.WaitForExit()
        $resolvedJdk = [regex]::Match($properties, '(?m)^\s*java\.home = ([^\r\n]+)').Groups[1].Value.Trim()
        if ($java.ExitCode -ne 0 -or $properties -notmatch '(?m)^\s*java\.version = 21(?:[.\r\n]|$)' -or -not $resolvedJdk) {
            throw 'Install Java 21 and place its launcher on PATH.'
        }
        Join-Path $resolvedJdk 'bin\java.exe'
    } finally {
        $java.Dispose()
    }
}

function Start-LocalBackend($Configuration) {
    if (-not (Test-Path -LiteralPath $jar -PathType Leaf)) {
        throw 'Build the backend from backend/ with .\mvnw.cmd verify first.'
    }
    $port = $Configuration.port
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw 'The configured port is already in use. Choose another local profile and port or stop its owner.'
    }
    foreach ($path in @($database + '.mv.db', $database + '.trace.db', $logFile, $launchOutput, $launchErrors)) {
        if (Test-Path -LiteralPath $path) { Assert-PrivateItem $path $false }
    }
    $javaPath = Get-Java21
    $origin = "http://127.0.0.1:$port"
    $browserId = if ($Configuration.synthetic) { 'local-fixture' } else { 'local-browser' }
    $scope = if ($Configuration.synthetic) { 'synthetic' } else { 'live' }
    $snapshot = $Configuration.snapshotPath
    if ($Configuration.synthetic -and -not $snapshot) {
        $now = [DateTime]::UtcNow
        $snapshot = Join-Path $directory 'demo-reputation.json'
        Save-PrivateJson $snapshot @{
            generatedAt = $now.AddSeconds(-1).ToString('o')
            expiresAt = $now.AddHours(2).ToString('o')
            entries = @(@{ kind = 'URL_PATH'; value = "$origin/phase4b-demo-phishing"; threat = 'PHISHING' })
        }
    }

    $clients = @{ 'local-admin' = @{ role = 'ADMIN'; 'token-sha256' = $Configuration.admin.digest } }
    $clients[$browserId] = @{ role = 'BROWSER'; 'token-sha256' = $Configuration.browser.digest }
    $monitoring = @{ 'store-path' = $database; 'retention-days' = $Configuration.retentionDays }
    if ($Configuration.synthetic) { $monitoring['synthetic-clients'] = @($browserId) }
    $serverConfiguration = @{
        server = @{ address = '127.0.0.1'; port = $port }
        threat = @{
            monitoring = $monitoring
            security = @{ clients = $clients; 'allowed-origins' = @("chrome-extension://$($Configuration.extensionId)") }
            reputation = @{ 'snapshot-path' = [string] $snapshot }
        }
        logging = @{ file = @{ name = $logFile } }
    } | ConvertTo-Json -Depth 10 -Compress

    $inherited = @(Get-ChildItem Env: | Where-Object {
        $_.Name -match '^(SPRING_|SERVER_|THREAT_|LOGGING_|JDK_JAVA_OPTIONS$|JAVA_TOOL_OPTIONS$|_JAVA_OPTIONS$)'
    })
    $launch = @{
        FilePath = $javaPath; ArgumentList = ('-jar "' + $jar + '"'); WorkingDirectory = $directory
        WindowStyle = 'Hidden'; PassThru = $true
        RedirectStandardOutput = $launchOutput; RedirectStandardError = $launchErrors
    }
    try {
        foreach ($variable in $inherited) { Remove-Item -LiteralPath ('Env:' + $variable.Name) }
        $env:SPRING_APPLICATION_JSON = $serverConfiguration
        $server = Start-Process @launch
    } finally {
        Remove-Item -LiteralPath Env:SPRING_APPLICATION_JSON -ErrorAction SilentlyContinue
        foreach ($variable in $inherited) { Set-Item -LiteralPath ('Env:' + $variable.Name) -Value $variable.Value }
    }
    try {
        Save-PrivateJson $processFile @{
            id = $server.Id; startedAt = $server.StartTime.ToUniversalTime().Ticks.ToString(); java = $javaPath
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            if ($server.HasExited) { throw 'Backend startup failed. Inspect backend.log in the private profile.' }
            if (Confirm-BackendReady $server $port) {
                Write-Output "Backend running at $origin (PID $($server.Id)). Reporting scope is $scope."
                Write-Output "Dashboard $origin/monitor"
                return
            }
            Start-Sleep -Milliseconds 350
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'Backend startup timed out. Inspect backend.log in the private profile.'
    } catch {
        if (-not $server.HasExited) { $server.Kill(); [void] $server.WaitForExit(5000) }
        if ($server.HasExited -and (Test-Path -LiteralPath $processFile)) { Remove-Item -LiteralPath $processFile }
        throw
    } finally {
        $server.Dispose()
    }
}

if ($Action -eq 'Setup') {
    Initialize-PrivateDirectory $root
    Initialize-PrivateDirectory $directory
} elseif (-not (Test-Path -LiteralPath $directory)) {
    if ($Action -in @('Status', 'Stop')) { Write-Output 'Backend stopped. No local profile has been set up.'; return }
    throw 'Run Setup for this profile first.'
} else {
    Assert-PrivateItem $root $true
    Assert-PrivateItem $directory $true
}

if (Test-Path -LiteralPath $lockFile) { Assert-PrivateItem $lockFile $false }
$lock = [IO.File]::Open($lockFile, 'OpenOrCreate', 'ReadWrite', 'None')
$managed = $null
try {
    if ($Action -eq 'Setup') {
        if (Test-Path -LiteralPath $configFile) { throw 'This profile is already set up. Use Rotate to replace credentials.' }
        if ($SnapshotPath) {
            $snapshot = Get-Item -LiteralPath $SnapshotPath
            if ($snapshot.PSIsContainer) { throw 'SnapshotPath must point to a snapshot file.' }
            $SnapshotPath = $snapshot.FullName
        }
        Save-PrivateJson $configFile @{
            version = 1; extensionId = $ExtensionId; port = $Port; synthetic = [bool] $Synthetic
            retentionDays = $RetentionDays
            snapshotPath = $SnapshotPath; browser = (New-Credential); admin = (New-Credential)
        }
        Write-Output "Profile '$Profile' is ready. Start it, then use CopyToken for each role."
        return
    }

    if (-not (Test-Path -LiteralPath $configFile)) { throw 'Run Setup for this profile first.' }
    $config = Read-PrivateJson $configFile
    if ($config.version -ne 1 -or $config.extensionId -cnotmatch '^[a-p]{32}$' -or
        $config.port -lt 1024 -or $config.port -gt 65535 -or $config.synthetic -isnot [bool] -or
        $config.retentionDays -lt 1 -or $config.retentionDays -gt 90 -or
        $config.browser.digest -cnotmatch '^[0-9a-f]{64}$' -or $config.admin.digest -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The local configuration is invalid. Use a new profile or restore a private backup.'
    }
    $managed = Get-ManagedProcess
    $origin = "http://127.0.0.1:$($config.port)"
    switch ($Action) {
        'Status' {
            if (-not $managed) { Write-Output "Backend stopped for '$Profile'." }
            elseif (Confirm-BackendReady $managed $config.port) { Write-Output "Backend running at $origin (PID $($managed.Id))." }
            else { Write-Output "Backend process exists (PID $($managed.Id)), but its HTTP health check did not succeed." }
        }
        'Start' {
            if (-not $managed) { Start-LocalBackend $config; break }
            if (Confirm-BackendReady $managed $config.port) {
                Write-Output "Backend running at $origin (PID $($managed.Id))."
            } else {
                throw 'A backend process already exists for this profile. Check Status or run Stop.'
            }
        }
        'Stop' {
            if ($managed) {
                $managed.Kill()
                if (-not $managed.WaitForExit(10000)) { throw 'Backend did not stop. Run Status before retrying.' }
            }
            if (Test-Path -LiteralPath $processFile) { Remove-Item -LiteralPath $processFile }
            Write-Output "Backend stopped for '$Profile'."
        }
        'Rotate' {
            if ($managed) { throw 'Stop the backend before rotating credentials.' }
            if ($Role -eq 'Browser') { $config.browser = New-Credential }
            else { $config.admin = New-Credential }
            Save-PrivateJson $configFile $config
            Write-Output "$Role credential rotated. Start the backend and use CopyToken to apply it."
        }
        'CopyToken' {
            $credential = if ($Role -eq 'Browser') { $config.browser } else { $config.admin }
            $secret = ConvertTo-SecureString -String $credential.encrypted
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            try {
                Set-Clipboard -Value ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
                Write-Output "$Role token copied. Paste it into the $Role client and clear the clipboard."
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
                $secret.Dispose()
            }
        }
    }
} finally {
    if ($managed) { $managed.Dispose() }
    $lock.Dispose()
}
