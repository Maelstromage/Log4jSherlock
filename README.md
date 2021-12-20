# Log4jSherlock
Version 1.0.2021.12.19


---------------------
# Overview

Log4j Scanner coded in Powershell, so you can run it in windows! This tool scans for JAR, WAR, EAR, JPI, HPI that contain the effected JndiLookup.class even in nested files.
Scans nested files searches for the effected JNDI class. pulls version and reports in CSV, JSON, and txt log. reports error i.e. access issues to folders where files could be missed.

# CVE Detection

Scans for the following CVEs
- CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI 
- CVE-2021-45046 Apache Log4j 2.15.0 
- CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0


# Usage
1. Download the ps1 file https://raw.githubusercontent.com/Maelstromage/Log4jSherlock/main/Log4Sherlock.ps1
2. Create the file computers.txt
3. Fill computers.txt with hostnames
4. Run ps1

# How this Script works

1. Scans all local drives on a system it is run on
2. Grabs pom.properties inside one of the above filetypes even in nested files (to obtain the version number)
3. Searches within the jar file for JndiLookup.class even in nested files
4. Files containing JndiLookup.class with vulnerable versions are marked with appropriate CVE
5. Saves logs to C:\Log4jSherlock on the SystemDrive

# Summary
This script starts scanning drives, once it comes upon one of the above file types it checks for file names inside the file. The first file it looks for is jndiLookup.class. This file is inside every version of log4j starting from 2.0-beta9. It reads the pom.properties file to get the file version so that it may exclude version 2.16.0, 2.17.0, and 2.12.2. It collects any Errors so that you know what has not been scanned i.e. access issues to files or folders. Creates a CSV file so you can open it up in excel and filter it. For greater detail a json file is created.


# Features
I do realize that there are a lot of scanners out there. So I will be brief and explain the core value of this scanner.

1. Scans Multiple computers remotely
2. Uses remote systems resources to make scanning fast
3. Does not hash the jar as it could be nested or edited
4. Identifies the following vulnerabilities CVE-2021-44228, CVE-2021-45046, CVE-2021-45105
5. Searches all drives on system excluding mapped drives
6. Creates CSV list of affected files and locations
7. Creates JSON file with all information including errors like access issues to folders (so you know spots that might have been missed)
8. Scans JAR, WAR, EAR, JPI, HPI
9. Checks nested files
10. Does not unzip files, just loads them into memory and checks them making the scanner fast and accurate
11. Identifies through pom.properties version number and if JNDI Class is present.


[https://github.com/Maelstromage/Log4jSherlock](https://github.com/Maelstromage/Log4jSherlock)

# Comments
I decided to write this because I have noticed a lot of other scanners did not consider some important points that would let some of these vulnerable files through the cracks. Like:
1. Scanner for files with Log4j in it instead of the JNDI Class
2. Only scanning for JAR files
3. Scanning for hashed jar files which doesn't account for nested files.


# Thank you
Thank you for taking the time to read. This was a fun weekend project. Hope this helps someone, enjoy!

# Author
- Harley Schaeffer



