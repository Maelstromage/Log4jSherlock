Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')
$global:Errors = @()
$global:vulnerabilityresults = @()
$global:debuglog = @()
$global:color = 'Magenta'
$global:csv = @()


# CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI Score: 10.0 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
# CVE-2021-45046 Apache Log4j 2.15.0 Score: 9.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
# CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

function display-logo{
    $logo = " ██▓     ▒█████    ▄████       ▄▄▄  ▄▄▄██▀▀▀██████  ██░ ██ ▓█████  ██▀███   ██▓     ▒█████   ▄████▄   ██ ▄█▀`r`n▓██▒    ▒██▒  ██▒ ██▒ ▀█▒    ▄████▒   ▒██ ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▓██▒    ▒██▒  ██▒▒██▀ ▀█   ██▄█▒ `r`n▒██░    ▒██░  ██▒▒██░▄▄▄░  ▄█▀  ██▒   ░██ ░ ▓██▄   ▒██▀▀██░▒███   ▓██ ░▄█ ▒▒██░    ▒██░  ██▒▒▓█    ▄ ▓███▄░ `r`n▒██░    ▒██   ██░░▓█  ██▓ ██▄▄▄▄██░▓██▄██▓  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  ▒██░    ▒██   ██░▒▓▓▄ ▄██▒▓██ █▄ `r`n░██████▒░ ████▓▒░░▒▓███▀▒▒▓▓▓   ██  ▓███▒ ▒██████▒▒░▓█▒░██▓░▒████▒░██▓ ▒██▒░██████▒░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄`r`n░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░░▒▓   █▓  ▒▓▒▒░ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▓  ░░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒`r`n░ ░ ▒  ░  ░ ▒ ▒░   ░   ░ ░ ▒▒   ▒   ▒ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░░ ░ ▒  ░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░`r`n  ░ ░   ░ ░ ░ ▒  ░ ░   ░    ▒   ░   ░ ░ ░ ░  ░  ░   ░  ░░ ░   ░     ░░   ░   ░ ░   ░ ░ ░ ▒  ░        ░ ░░ ░ `r`n    ░  ░    ░ ░        ░ ░  ░       ░   ░       ░   ░  ░  ░   ░  ░   ░         ░  ░    ░ ░  ░ ░      ░  ░   `r`n                                                                                  ░               `r`n"
    write-host $logo -foreground $global:color
    write-host "Version: 0.85.2021.12.18"
    write-host "Written by Maelstromage"
    write-host "https://github.com/Maelstromage/Log4jSherlock`r`n"

}
function Check-Version{
    param($version,$hasJNDI)
    
    $CVE = 'CVE-2021-44228'
    $CVSSScore = '10.0'
    $FixedVersion = $false
    if($hasJNDI -eq $false){$CVE = $null; $CVSSScore = $null; $FixedVersion = $false}
    if($version -eq 'version=2.15.0'){$CVE = 'CVE-2021-45046'; $CVSSScore = '9.0'; $FixedVersion = $false}
    if($version -eq 'version=2.16.0'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $true}
    if($version -eq 'version=2.17.0'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}
    if($version -eq 'version=2.12.2'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $true}
    $return = @{CVE = $CVE; CVSSScore = $CVSSScore; fixedversion = $fixedversion} 
    
    return $return
}

function write-console{
    param($CVE,$path,$version)
    $color = $global:color
    write-host "┌[$CVE] Version: $version" -ForegroundColor $color
    write-host "└─[" -ForegroundColor $color -NoNewline
    write-host " Located: $path"
    $global:vulnerabilityresults += "┌[$CVE] Version: $version`r`n└─[ Located: $path"
}

function Scan-File{
    param($path)
    $path = $path.fullname
    $hasJNDI = $false
    try{
        $nestedfiles = ([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries | where {$_.name -eq 'jndiLookup.class'}
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path}
    }
    foreach($nestedfile in $nestedfiles) {
        if ($nestedfile.name -eq 'JndiLookup.class'){
            $hasJNDI = $true
            $JNDIfile = $nestedfile.fullname
        }
    }
    try{
        $zip = [io.compression.zipfile]::OpenRead($path)
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path}
    }
    $file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}
    if($file -ne $null){
        $stream = $file.Open()
        $reader = New-Object IO.StreamReader($stream)
        $text = $reader.ReadToEnd()
        $version = -split $text | select-string -Pattern "Version"
        $reader.Close()
        $stream.Close()
        $zip.Dispose()
    }
    $versionCVE = (Check-Version -version $version.line -hasJNDI $hasJNDI)
    
    if ($hasJNDI -and !($versionCVE.fixedversion)){
        $vuln = $true
        write-console -CVE $versionCVE.CVE -path $path -version $version

    }else{$vuln = $false}
    $return = @{
        path = $path;
            version = $version.line;
            text=$text;
            pomLocation=$file.FullName;
            hasJNDI=$hasJNDI;
            JNDILocation=$JNDIfile
            CVE = $versionCVE.CVE
            CVSSScore = $versionCVE.CVSSScore
            FixedVersion = $versionCVE.fixedversion
            Vulnerable = $vuln
    }
    return $return
}

function Scan-System{
    param($filetypes)
    $scannedfiles =@()
    $DriveErrors = @()
    $Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$_.DisplayRoot -eq $null}).root
    #$drives = @('c:\test','g:\test\')
    foreach ($Drive in $Drives) {
        $searchingmessage = "Searching Drive $drive on host $env:ComputerName..."
        write-host $searchingmessage -ForegroundColor Cyan
        $global:vulnerabilityresults += $searchingmessage
        $javaFiles = Get-ChildItem $Drive -Recurse -ErrorVariable DriveError -include $filetypes -ErrorAction SilentlyContinue #| out-null
        foreach ($javaFile in $javaFiles){
            $scannedfiles += [pscustomobject](Scan-File $javaFile)
        }
    }
    $global:csv = $Scannedfiles
    $global:Errors += @{Error=$DriveError.exception.message}
    $scannedfiles += $global:Errors
    $scannedfiles = convertto-json $scannedfiles
    return $scannedfiles
}



display-logo
If(!(Test-Path "$env:SystemDrive\Log4jSherlock")) { New-Item -ItemType Directory "$env:SystemDrive\Log4jSherlock" -Force }
$date = get-date -Format "yyyy-MM-dd_hh-mm-ss"
$results = Scan-System -filetypes $filetypes
Write-Host $global:Errors


$jsonpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.json"
$resultpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.txt"
$csvpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.csv"
write-host "`r`nWriting Json to $jsonpath..."
set-content -path $jsonpath -value $results
write-host "`r`nWriting log to $resultpath..."
Set-Content -path $resultpath -Value $global:vulnerabilityresults
write-host "`r`nWriting CSV to $csvpath..."
$global:csv | export-csv $csvpath -NoTypeInformation


