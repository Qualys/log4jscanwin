THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS

# Description
The Log4jScanner.exe utility helps to detect CVE-2021-44228 and CVE-2021-45046 vulnerabilities.
The utility will scan the entire hard drive(s) including archives (and nested JARs) for the Java class that indicates the Java application contains a vulnerable log4j library. The utility will output its results to a console.

Qualys has added a new QID (376160) that is designed to look for the results of this scan and mark the asset as vulnerable if the vulnerable log4j library was found.

Qualys customers should use the following to run the tool on any asset they want to scan:
 Log4jScanner.exe /scan /report_sig

# Usage

/scan
  Scan local drives for vulnerable JAR, WAR, EAR, and ZIP files used by various Java applications.
/scan_directory "C:\Some\Path"
  Scan a specific directory for vulnerable JAR, WAR, EAR, and ZIP files used by various Java applications.
/scan_file "C:\Some\Path\Some.jar"
  Scan a specific file for CVE-2021-44228 and CVE-2021-45046.
/report
  Generate a JSON report of possible detections of CVE-2021-44228 and CVE-2021-45046.
/report_pretty
  Generate a human-readable JSON report of possible detections of CVE-2021-44228 and CVE-2021-45046.
/report_sig
  Generate a signature report of possible detections of CVE-2021-44228 and CVE-2021-45046.

Sample Usage - The following command helps you scan local drives for vulnerable JAR, WAR, EAR, and ZIP.
Log4jScanner.exe /scan

Sample Usage - The following command helps you scan local drives for vulnerable files and writes a signature report to C:\ProgramData\Qualys
Log4jScanner.exe /scan /report_sig

# Output - The following output shows detection
```
Qualys Log4j Vulnerability Scanner (CVE-2021-44228/CVE-2021-45046) 1.2.16
https://www.qualys.com/

Scanning 'D:\temp\'...
Log4j Found: 'D:\temp\log4j-api-2.16.0.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.16.0, JNDI Class: NOT Found, Log4j Vendor: log4j-api, Log4j Version: 2.16.0, CVE Status: Mitigated )
Log4j Found: 'D:\temp\log4j-core-2.11.1.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.11.1, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.11.1, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found ) )
Log4j Found: 'D:\temp\log4j-core-2.14.0.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.14.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.14.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found ) )
Log4j Found: 'D:\temp\log4j-core-2.15.0.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.15.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.15.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: NOT Found CVE-2021-45046: Found ) )
Log4j Found: 'D:\temp\log4j-core-2.16.0.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.16.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.16.0, CVE Status: Mitigated )
Log4j Found: 'D:\temp\log4j-iostreams-2.15.0.jar' ( Manifest Vendor: org.apache.logging.log4j, Manifest Version: 2.15.0, JNDI Class: NOT Found, Log4j Vendor: log4j-iostreams, Log4j Version: 2.15.0, CVE Status: Mitigated )
Log4j Found: 'D:\temp\org.apache.log4j_1.2.15.v201012070815.jar' ( Manifest Vendor: %PLUGIN_PROVIDER, Manifest Version: 1.2.15.v201012070815, JNDI Class: NOT Found, Log4j Vendor: Unknown, Log4j Version: Unknown, CVE Status: N/A )

Scan Summary:
        Scan Date:               2021-12-15T08:55:32-0800
        Scan Duration:           8 Seconds
        Files Scanned:           67
        Directories Scanned:     6
        JAR(s) Scanned:          10
        WAR(s) Scanned:          0
        EAR(s) Scanned:          0
        ZIP(s) Scanned:          3
        Vulnerabilities Found:   3
```
