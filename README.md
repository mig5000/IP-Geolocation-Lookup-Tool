🌍 IP Geolocation Lookup Tool
A powerful command-line tool for retrieving detailed geolocation information about IP addresses using multiple APIs with automatic fallback.

✨ Features
Feature	Description
🔌 Multi-API Support	Uses ip-api.com, ipapi.co, and ipwhois.io with intelligent fallback
✅ Smart IP Validation	Automatically detects private and reserved IP ranges
⚡ Batch Processing	Process multiple IPs simultaneously with threading
📊 Multiple Output Formats	Pretty console display, JSON, and CSV
🔍 Reverse DNS Lookup	Retrieves hostnames for IP addresses
💾 LRU Caching	Caches results for repeated queries
🎮 Interactive Mode	User-friendly command interface
📁 File Operations	Read IPs from text files and save results automatically
🎮 Interactive Mode Commands
Command	Description
me	Lookup your own IP address
batch	Enter multiple IPs interactively
file [path]	Read IPs from file
format	Change output format (pretty/json/csv)
save	Toggle auto-save feature
clear	Clear screen
help	Show command help
exit	Exit program
📋 Information Retrieved
📍 Location: Country, region, and city

🌐 Coordinates: Geographic latitude and longitude

🏢 Organization: ISP and organization information

⏰ Time: Timezone and ZIP code

🔗 Network: ASN and reverse DNS

🛡️ Security: IP type detection (public/private/reserved)

📊 API Limits
Service	Free Tier Limits
ip-api.com	45 requests per minute
ipapi.co	30,000 requests per month
ipwhois.io	No strict limits
⚙️ Requirements
Python 3.7+

Requests library

📝 Notes
🔒 Private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x) are detected locally

💾 Results are cached to respect API rate limits

🔐 All API communication uses HTTPS where available

🏷️ User agent is set to identify tool for API providers

🛠️ Compilation
bash
pyinstaller --onefile --clean --name GeoIP GeoIP.py

✨ Perfect for network administrators, cybersecurity professionals, and developers!

