# IOC Query Generator

## About
This script automates the generation of queries for Microsoft Defender for Endpoint (MDE), CrowdStrike, and SentinelOne based on various Indicators of Compromise (IOCs) such as hashes, domains, URLs, and IP addresses extracted from an Excel file. It processes the IOCs, defangs them where necessary, and formats them into specific queries for each security platform.

## Features
- Loads IOCs from an Excel file with separate columns for MD5, SHA1, SHA256, Domain, URL, and IP Address.
- Generates queries for:
  - Microsoft Defender for Endpoint (MDE)
  - CrowdStrike
  - SentinelOne
- Defangs URLs and IPs for safe processing.
- Outputs results into a new Excel file with organized query data.

## How to Use
1. **Prepare your input Excel file**: Create an Excel file named `input.xlsx` with the following columns: MD5, SHA1, SHA256, Domain, URL, and IP Address.
2. **Run the script**: Execute the script using Python. Ensure you have the necessary dependencies installed (e.g., `pandas`).
3. **Check the output**: The script generates an output Excel file named `output_queries.xlsx`, containing the formatted queries and all indicators.

## Script Overview
The script processes the input Excel file to:
- Load IOCs from the specified columns.
- Defang domains and IPs for security purposes.
- Generate MDE, CrowdStrike, and SentinelOne queries based on the provided IOCs.
- Save the generated queries into an output Excel file.

## Example Input
| MD5                                      | SHA1                                     | SHA256                                                           | Domain                  | URL                                         | IP Address    |
|------------------------------------------|------------------------------------------|------------------------------------------------------------------|-------------------------|---------------------------------------------|---------------|
| b106e2a8e2537327e2dd7896a3b9b70457efca19 | b106e2a8e2537327e2dd7896a3b9b70457efca19 | 2dd1e4249e674efe23712fddeb5ec5bf4d86430a9cbdbe732c1baa6df1cd95b8 | kmsupdateservice.com.br | http://47.76.156.133:8888/supershell/login/ | 149.104.28.67 |

## Example Output Queries

### MDE Queries
```plaintext
let Hash1=dynamic(["b106e2a8e2537327e2dd7896a3b9b70457efca19"]);
find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)
where SHA1 has_any (Hash1) or InitiatingProcessSHA1 has_any(Hash1)

let Hash256=dynamic(["2dd1e4249e674efe23712fddeb5ec5bf4d86430a9cbdbe732c1baa6df1cd95b8"]);
find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)
| where SHA256 has_any (Hash256) or InitiatingProcessSHA256 has_any(Hash256)

let HashMD5=dynamic(["b106e2a8e2537327e2dd7896a3b9b70457efca19"]);
find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)
| where MD5 has_any (HashMD5) or InitiatingProcessMD5 has_any(HashMD5)

DeviceNetworkEvents
| where RemoteUrl has_any ("kmsupdateservice.com.br")
| summarize count() by RemoteUrl, InitiatingProcessFileName, DeviceName

DeviceNetworkEvents
| where RemoteUrl has_any ("http://47.76.156.133:8888/supershell/login/")
| summarize count() by RemoteUrl, InitiatingProcessFileName, DeviceName

let IPAddressIOCs=dynamic(["149.104.28.67"]);
DeviceNetworkEvents | where RemoteIP has_any (IPAddressIOCs)
| summarize count() by InitiatingProcessFileName
```

### CrowdStrike Query
```plaintext
((RemoteAddressIP4="149.104.28.67") OR (HttpUrl="http://47.76.156.133:8888/supershell/login/") OR (DomainName="kmsupdateservice.com.br") OR (MD5HashData="b106e2a8e2537327e2dd7896a3b9b70457efca19") OR (SHA1HashData="b106e2a8e2537327e2dd7896a3b9b70457efca19") OR (SHA256HashData="2dd1e4249e674efe23712fddeb5ec5bf4d86430a9cbdbe732c1baa6df1cd95b8"))
```

### SentinelOne Query
```plaintext
tgt.file.sha256 in ("2dd1e4249e674efe23712fddeb5ec5bf4d86430a9cbdbe732c1baa6df1cd95b8") OR src.process.image.sha256 in ("2dd1e4249e674efe23712fddeb5ec5bf4d86430a9cbdbe732c1baa6df1cd95b8") OR tgt.file.sha1 in ("b106e2a8e2537327e2dd7896a3b9b70457efca19") OR src.process.image.sha1 in ("b106e2a8e2537327e2dd7896a3b9b70457efca19") OR tgt.file.md5 in ("b106e2a8e2537327e2dd7896a3b9b70457efca19") OR src.process.image.md5 in ("b106e2a8e2537327e2dd7896a3b9b70457efca19") OR src.ip.address contains ("149.104.28.67") OR dst.ip.address contains ("149.104.28.67") OR event.dns.request in ("kmsupdateservice.com.br") OR url.address in ("kmsupdateservice.com.br") OR event.dns.request in ("http://47.76.156.133:8888/supershell/login/") OR url.address in ("http://47.76.156.133:8888/supershell/login/")
```

## Notes
- Ensure you have the necessary permissions to access the data you are querying.
- Modify the script as needed to fit your specific security needs or environments.
```
