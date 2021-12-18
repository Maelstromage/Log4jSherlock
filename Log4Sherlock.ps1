Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')
$global:Errors = @()

function Scan-File{
    param($path)
    $hasJNDI = $false
    try{
        $nestedfiles = ([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries.name
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path.fullname}
    }
    foreach($nestedfile in $nestedfiles) {
        if ($nestedfile -eq 'JndiLookup.class'){
            $hasJNDI = $true
        }
    }
    try{
        $zip = [io.compression.zipfile]::OpenRead($path) | out-null
    }catch{
        $global:Errors += @{Error=$_.exception.Message;path=$path.fullname}
    }
    #$file = $zip.Entries | where-object { $_.FullName -eq "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"}
    $file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}
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
    if ($hasJNDI -and $version -ne 'version=2.16.0'){
        $vuln = $true
    }else{$vuln = $false}
    $return = @{path = $path.fullname;version = $version.line;text=$text;classLocation=$file.FullName;hasJNDI=$hasJNDI}
    if ($hasJNDI -and $version -ne 'version=2.16.0'){write-host -ForegroundColor red "Found Vulnerability in $path log4j $version"}
    return $return
}

function Scan-System{
    param($filetypes)
    $scannedfiles =@()
    $DriveErrors = @()
    $Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$_.DisplayRoot -eq $null}).root
    $drives = 'c:\test'
    foreach ($Drive in $Drives) {
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
$date = get-date -Format "yyyy-MM-dd hh:mm:ss"

$results = Scan-System -filetypes $filetypes

set-content "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.json" $results










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
