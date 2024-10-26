import pandas as pd

# Load the input Excel file
input_file_path = 'input.xlsx'  # Ensure this matches your input file name
df = pd.read_excel(input_file_path)

# Initialize lists to store queries
mde_sha1_queries = []
mde_sha256_queries = []
mde_md5_queries = []
mde_domain_queries = []
mde_url_queries = []
mde_ip_queries = []
crowdstrike_queries = []
sentinelone_queries = []

# To store defanged hashes, domains, IPs, and URLs
defanged_combined = []
all_indicators = []  # To store all indicators in a single column

# Function to process and defang IOCs based on column data
def process_iocs(df):
    # Read columns for each type of IOC, handle any non-string values, and remove spaces
    sha1_hashes = df['SHA1'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()
    sha256_hashes = df['SHA256'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()
    md5_hashes = df['MD5'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()
    domains = df['Domain'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()
    urls = df['URL'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()
    ips = df['IP Address'].dropna().astype(str).str.replace(' ', '').str.lower().tolist()

    # Defang domains and IPs
    for item in domains + ips:
        defanged_item = item.replace('.', '[.]')
        defanged_combined.append(defanged_item)
        all_indicators.append(defanged_item)  # Store defanged items

    # Defang URLs as specified
    defanged_urls = [
        url.replace("http", "hxxp").replace("https", "hxxps").replace(":", "[:]")
        for url in urls
    ]
    defanged_combined.extend(defanged_urls)
    all_indicators.extend(defanged_urls)  # Store defanged URLs

    # Add hashes to all indicators
    all_indicators.extend(sha1_hashes)
    all_indicators.extend(sha256_hashes)
    all_indicators.extend(md5_hashes)

    return sha1_hashes, sha256_hashes, md5_hashes, domains, urls, ips

# Process the IOCs from the columns
sha1_hashes, sha256_hashes, md5_hashes, domains, urls, ips = process_iocs(df)

# Generate MDE Queries
if sha1_hashes:
    mde_sha1_query = (
        "let Hash1=dynamic([{}]);\n"
        "find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)\n"
        "where SHA1 has_any (Hash1) or InitiatingProcessSHA1 has_any(Hash1)"
    ).format(', '.join(f'"{hash}"' for hash in sha1_hashes))
    mde_sha1_queries.append(mde_sha1_query)

if sha256_hashes:
    mde_sha256_query = (
        "let Hash256=dynamic([{}]);\n"
        "find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)\n"
        "where SHA256 has_any (Hash256) or InitiatingProcessSHA256 has_any(Hash256)"
    ).format(', '.join(f'"{hash}"' for hash in sha256_hashes))
    mde_sha256_queries.append(mde_sha256_query)

if md5_hashes:
    mde_md5_query = (
        "let HashMD5=dynamic([{}]);\n"
        "find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)\n"
        "where MD5 has_any (HashMD5) or InitiatingProcessMD5 has_any(HashMD5)"
    ).format(', '.join(f'"{hash}"' for hash in md5_hashes))
    mde_md5_queries.append(mde_md5_query)

if domains:
    mde_domain_query = (
        "DeviceNetworkEvents\n"
        "| where RemoteUrl has_any ({})\n"
        "| summarize count() by RemoteUrl, InitiatingProcessFileName, DeviceName"
    ).format(', '.join(f'"{domain}"' for domain in domains))
    mde_domain_queries.append(mde_domain_query)

if urls:
    mde_url_query = (
        "DeviceNetworkEvents\n"
        "| where RemoteUrl has_any ({})\n"
        "| summarize count() by RemoteUrl, InitiatingProcessFileName, DeviceName"
    ).format(', '.join(f'"{url}"' for url in urls))
    mde_url_queries.append(mde_url_query)

if ips:
    mde_ip_query = (
        "let IPAddressIOCs=dynamic([{}]);\n"
        "find in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents)\n"
        "where RemoteIP has_any (IPAddressIOCs)\n"
        "| summarize count() by InitiatingProcessFileName"
    ).format(', '.join(f'"{ip}"' for ip in ips))
    mde_ip_queries.append(mde_ip_query)

# Generate CrowdStrike Queries
crowdstrike_conditions = []

if ips:
    crowdstrike_conditions.append(" OR ".join(f'RemoteAddressIP4="{ip}"' for ip in ips))
if urls:
    crowdstrike_conditions.append(" OR ".join(f'HttpUrl="{url}"' for url in urls))
if domains:
    crowdstrike_conditions.append(" OR ".join(f'DomainName="{domain}"' for domain in domains))
if md5_hashes:
    crowdstrike_conditions.append(" OR ".join(f'MD5HashData="{hash}"' for hash in md5_hashes))
if sha1_hashes:
    crowdstrike_conditions.append(" OR ".join(f'SHA1HashData="{hash}"' for hash in sha1_hashes))
if sha256_hashes:
    crowdstrike_conditions.append(" OR ".join(f'SHA256HashData="{hash}"' for hash in sha256_hashes))

if crowdstrike_conditions:
    crowdstrike_query = "(({}))".format(") OR (".join(crowdstrike_conditions))
    crowdstrike_queries.append(crowdstrike_query)

# Generate SentinelOne Queries
sentinelone_conditions = []

if sha256_hashes:
    sentinelone_conditions.append(
        "tgt.file.sha256 in ({}) OR src.process.image.sha256 in ({})".format(
            ', '.join(f'"{hash}"' for hash in sha256_hashes),
            ', '.join(f'"{hash}"' for hash in sha256_hashes)
        )
    )
if sha1_hashes:
    sentinelone_conditions.append(
        "tgt.file.sha1 in ({}) OR src.process.image.sha1 in ({})".format(
            ', '.join(f'"{hash}"' for hash in sha1_hashes),
            ', '.join(f'"{hash}"' for hash in sha1_hashes)
        )
    )
if md5_hashes:
    sentinelone_conditions.append(
        "tgt.file.md5 in ({}) OR src.process.image.md5 in ({})".format(
            ', '.join(f'"{hash}"' for hash in md5_hashes),
            ', '.join(f'"{hash}"' for hash in md5_hashes)
        )
    )
if ips:
    sentinelone_conditions.append(
        "src.ip.address contains ({}) OR dst.ip.address contains ({})".format(
            ', '.join(f'"{ip}"' for ip in ips),
            ', '.join(f'"{ip}"' for ip in ips)
        )
    )
if urls:
    sentinelone_conditions.append(
        "event.dns.request in ({}) OR url.address in ({})".format(
            ', '.join(f'"{url}"' for url in urls),
            ', '.join(f'"{url}"' for url in urls)
        )
    )
if domains:
    sentinelone_conditions.append(
        "event.dns.request in ({}) OR url.address in ({})".format(
            ', '.join(f'"{domain}"' for domain in domains),
            ', '.join(f'"{domain}"' for domain in domains)
        )
    )

if sentinelone_conditions:
    sentinelone_query = " OR ".join(sentinelone_conditions)
    sentinelone_queries.append(sentinelone_query)

# Combine all MDE queries into a single formatted query string
mde_combined_query = "\n\n".join(
    mde_sha1_queries + mde_sha256_queries + mde_md5_queries + mde_domain_queries + mde_url_queries + mde_ip_queries
)

# Combine all indicators into a single DataFrame column
output_data = {
    'MDE Query': [mde_combined_query],  # Single cell for all MDE queries formatted
    'CrowdStrike Query': crowdstrike_queries,
    'SentinelOne Query': sentinelone_queries,
    'All Indicators': all_indicators,  # All indicators in one column
}

# Create a DataFrame to save results
output_df = pd.DataFrame(dict([(k, pd.Series(v, dtype='object')) for k, v in output_data.items()]))
output_df.to_excel('output_queries.xlsx', index=False)  # Save output to an Excel file
