# 🔍 IOC Reputation Checker

A Python tool for Security Operations Centers (SOC) to automate IOC reputation checking across multiple threat intelligence platforms.

## ✨ Features

- **Multi-Platform Checking**: Query VirusTotal, AbuseIPDB, AlienVault OTX & ThreatFox simultaneously
- **Smart IOC Detection**: Automatically identifies IPs, domains, MD5, SHA1, and SHA256 hashes
- **Comprehensive Reporting**: Generate detailed CSV reports with risk scoring and blocking recommendations
- **SOC-Ready**: Built for real-world security operations and client reporting

# Check single IOC
python ioc_reputation_checker.py --ioc "malicious-domain.com"

# Bulk check from file
python ioc_reputation_checker.py --file iocs.csv --output report.csv
📋 Supported IOC Types
IP Addresses: IPv4 addresses

Domains: All TLDs (.com, .xyz, .top, .shop, etc.)

Hashes: MD5, SHA1, SHA256

⚙️ Configuration
Get API keys from:

VirusTotal

AbuseIPDB

AlienVault OTX

Copy config.example.py to config.py and add your API keys

📊 Sample Output
IOC	Type	VirusTotal_Threat_Score	Overall_Risk	Recommendation
malicious.xyz	domain	85.5	HIGH	BLOCK
8.8.8.8	ipv4	2.1	LOW	ALLOW
🛠️ Usage Examples
bash
# Single IOC check
python ioc_reputation_checker.py --ioc "8.8.8.8"

# Bulk analysis with custom output
python ioc_reputation_checker.py --file client_iocs.txt --output client_report.csv
