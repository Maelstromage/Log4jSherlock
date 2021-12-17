#Select-String -Path 'c:\jars log4j\vuln\*.*' -pattern '2.13.1' 

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

#([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead("C:\jars log4j\vuln.jar"))).Entries 
#pause
$path = "C:\jars log4j\log4j-core-2.16.0.jar"
$path = "C:\jars log4j\MySuper2.jar"
$excludedversion = "2.16.0"
$hasJNDI = $false
$version = ''
$text = ''
$reader = ''
$stream = ''
$zip = ''

([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries.name | 
    foreach {
        if ($_ -eq 'JndiLookup.class'){
            write-host 'found'
            $hasJNDI = $true
        }
    }
$zip = [io.compression.zipfile]::OpenRead($path)
#$file = $zip.Entries | where-object { $_.FullName -eq "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"}
$file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}

$stream = $file.Open()

$reader = New-Object IO.StreamReader($stream)
$text = $reader.ReadToEnd()
$text
$version = -split $text | select-string -Pattern "Version"


$reader.Close()
$stream.Close()
$zip.Dispose()


if ($hasJNDI -and $version -notmatch 'version=2.16.0'){write-host -ForegroundColor red "Found Vulnerability log4j $version"}






#Select-string -InputObject $file -Pattern '2.16.0'

<#

$List = [System.Collections.ArrayList]::new()
$TotalResults = [System.Collections.ArrayList]::new()
$Drives = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }).Root


get-childitem -path 'c:\jars log4j\log4j-core-2.16.0\' -Recurse | select-string -pattern '2.13.1'
get-childitem -path 'C:\test\test2\mysuper' -Recurse | select-string -pattern '2.13.1'

# JAR, WAR, EAR, JPI, HPI
#>
