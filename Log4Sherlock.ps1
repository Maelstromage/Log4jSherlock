Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')
$global:Errors = @()
$global:vulnerabilityresults = @()
$global:debuglog = @()


# CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI Score: 10.0 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
# CVE-2021-45046 Apache Log4j 2.15.0 Score: 9.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
# CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

function Check-Version{
    param($version)
    
    $CVE = 'CVE-2021-44228'
    $CVSSScore = '10.0'
    $FixedVersion = $false
    if($version -eq 'version=2.15.0'){$CVE = 'CVE-2021-45046'; $CVSSScore = '9.0'; $FixedVersion = $false}
    if($version -eq 'version=2.16.0'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $true}
    if($version -eq 'version=2.17.0'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}
    if($version -eq 'version=2.12.2'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $true}
    $return = @{CVE = $CVE; CVSSScore = $CVSSScore; fixedversion = $fixedversion} 
    
    return $return
}


function Scan-File{
    param($path)
    $path = $path.fullname
    $hasJNDI = $false
    try{
        #$nestedfiles = ([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries.name
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
        $zip = [io.compression.zipfile]::OpenRead($path) #| out-null
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path}
    }
    #$file = $zip.Entries | where-object { $_.FullName -eq "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"}
    $file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}
    #global:debuglog = $zip
    if($file -ne $null){
        
        $stream = $file.Open()
        $reader = New-Object IO.StreamReader($stream)
        $text = $reader.ReadToEnd()
        
        $version = -split $text | select-string -Pattern "Version"
        
        #$version = $version.ToString()
        $reader.Close()
        $stream.Close()
        $zip.Dispose()
    }
    $versionCVE = (Check-Version -version $version.line)
    
    if ($hasJNDI -and !($versionCVE.fixedversion)){
        $vuln = $true
        $foundMessage = "Found Vulnerability in $path log4j $version"
        write-host -ForegroundColor red $foundMessage
        $global:vulnerabilityresults += $foundMessage
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

    }
    #if ($hasJNDI -and $version -ne 'version=2.16.0'){}
    
    return $return
}

function Scan-System{
    param($filetypes)
    $scannedfiles =@()
    $DriveErrors = @()
    $Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$_.DisplayRoot -eq $null}).root
    $drives = @('c:\test','g:\test')
    foreach ($Drive in $Drives) {
        $searchingmessage = "Searching Drive $drive on host $env:ComputerName..."
        write-host $searchingmessage
        #$global:vulnerabilityresults += $searchingmessage
        $javaFiles = Get-ChildItem $Drive -Recurse -ErrorVariable DriveError -include $filetypes -ErrorAction SilentlyContinue #| out-null
        foreach ($javaFile in $javaFiles){
            $scannedfiles += Scan-File $javaFile
        }
    }
    $scannedfiles += @{Error=$DriveError.exception.message}
    $scannedfiles += $global:Errors
    $scannedfiles = convertto-json $scannedfiles
    return $scannedfiles
}

If(!(Test-Path "$env:SystemDrive\Log4jSherlock")) { New-Item -ItemType Directory "$env:SystemDrive\Log4jSherlock" -Force }
$date = get-date -Format "yyyy-MM-dd_hh-mm-ss"
$results = Scan-System -filetypes $filetypes
$jsonpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.json"
$resultpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.txt"
set-content -path $jsonpath -value $results
Set-Content -path $resultpath -Value $global:vulnerabilityresults










#Select-String -Path 'c:\jars log4j\vuln\*.*' -pattern '2.13.1' 

#Select-string -InputObject $file -Pattern '2.16.0'

<#

$List = [System.Collections.ArrayList]::new()
$TotalResults = [System.Collections.ArrayList]::new()
$Drives = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }).Root


get-childitem -path 'c:\jars log4j\log4j-core-2.16.0\' -Recurse | select-string -pattern '2.13.1'
get-childitem -path 'C:\test\test2\mysuper' -Recurse | select-string -pattern '2.13.1'

# JAR, WAR, EAR, JPI, HPI
#>


#([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead("C:\jars log4j\vuln.jar"))).Entries 
#pause
<#
$path = "C:\jars log4j\log4j-core-2.16.0.jar"
$path = "C:\jars log4j\MySuper2.jar"
$excludedversion = "2.16.0"
$hasJNDI = $false
$version = ''
$text = ''
$reader = ''
$stream = ''
$zip = ''
#>
