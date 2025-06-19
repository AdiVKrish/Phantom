# 🕷️ Phantom - Advanced Domain Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Phantom** is a comprehensive OSINT (Open Source Intelligence) framework designed for authorized domain reconnaissance and security assessment. This tool provides cybersecurity professionals with advanced capabilities for gathering intelligence about target domains through multiple reconnaissance techniques.

## ✨ Key Features

### 🎨 **Neon Aesthetics**
- **Custom neon color scheme** (pink, cyan, green, yellow, purple)
- **Stylized ASCII art banner** with professional presentation
- **Professional section headers** with borders and visual separation
- **Color-coded result categories** for easy identification

### 📧 **Advanced Email Harvesting**
- **Pattern-based email extraction** from web content
- **WHOIS email extraction** from domain registration data
- **Educational institution email generation** (admin@, info@, etc.)
- **Multiple email pattern recognition** including obfuscated formats

### 🔍 **Enhanced Intelligence Gathering**
- **TheHarvester-style functionality** for comprehensive data collection
- **Multi-threaded subdomain discovery** with customizable wordlists
- **Technology stack detection** (Apache, Nginx, PHP, WordPress, etc.)
- **Port reconnaissance** for service identification
- **Web service analysis** with detailed response parsing

### 📊 **Real-time Output**
- **Live results display** (no JSON files required)
- **Nmap-style output format** for familiar presentation
- **Progress indicators and status updates** for long-running scans
- **Comprehensive summary section** with detailed statistics

### ⚡ **Performance Features**
- **Multi-threaded scanning** (customizable thread count)
- **Concurrent DNS queries** for faster resolution
- **Parallel port scanning** for efficient service discovery
- **Optimized subdomain discovery** with intelligent filtering

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Quick Setup
```bash
#Create venv in your environment 
python -m venv cybersec-env (for windows)
cybersec-env\Scripts\Activate  (to activate)

# Clone the repository
git clone https://github.com/AdiVKrish/phantom.git
cd phantom

# Install required dependencies
pip install -r requirements.txt

# Make the script executable (Linux/macOS)
chmod +x phantom.py
```

### Dependencies
```bash
pip install requests beautifulsoup4 pandas colorama argparse python-nmap dnspython                                                                                             
```

## 🛠️ Usage

### Basic Usage
```bash
# Basic reconnaissance scan
python phantom.py example.com

# Scan with custom thread count
python phantom.py example.com -t 100

# Help and options
python phantom.py --help
```

### Command Line Options
```
usage: phantom.py [-h] [-t THREADS] target

Phantom - Advanced Domain Reconnaissance & OSINT Framework

positional arguments:
  target                Target domain to reconnaissance

optional arguments:
  -h, --help           show this help message and exit
  -t THREADS, --threads THREADS
                       Number of threads for scanning (default: 50)
```

### Example Output Preview
```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗             ║
║  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║             ║
║  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║             ║
║  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║             ║
║  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║             ║
║  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝             ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] A Record: 93.184.216.34
[+] MX Record: mail.example.com
[+] Subdomain: www.example.com
[+] Email: contact@example.com
[+] Technology: Apache detected
[+] Port 80: HTTP - OPEN
```

## 🔧 Technical Features

### DNS Reconnaissance
- **Comprehensive record enumeration**: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
- **Advanced DNS resolution** with timeout handling
- **Multiple DNS server queries** for comprehensive coverage

### Subdomain Discovery
- **Extended wordlist**: 70+ common subdomains
- **Educational institution focused**: student, faculty, admin, library
- **Multi-threaded discovery**: Customizable thread count for performance
- **DNS resolution verification**: Only reports confirmed subdomains

### Email Harvesting
- **Multiple extraction patterns**: Standard, obfuscated, spaced formats
- **WHOIS data mining**: Automated email extraction from registration data
- **Educational domain intelligence**: Automatic generation of common edu emails
- **Content scraping**: Web page analysis for embedded email addresses

### Technology Detection
- **Header analysis**: Server, X-Powered-By, X-AspNet-Version detection
- **Content fingerprinting**: jQuery, WordPress, Drupal, Joomla identification
- **Web server identification**: Apache, Nginx, IIS detection
- **Framework detection**: PHP, ASP.NET, and other backend technologies

### Port Scanning
- **Common service ports**: 15 most important ports (21, 22, 25, 80, 443, etc.)
- **Service identification**: Automatic service name resolution
- **Parallel scanning**: Multi-threaded for faster results
- **Connection timeout**: 3-second timeout for responsiveness

## 📋 Reconnaissance Modules

| Module | Description | Features |
|--------|-------------|----------|
| **DNS Intelligence** | Comprehensive DNS enumeration | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records |
| **WHOIS Analysis** | Domain registration intelligence | Registrar, dates, contacts, name servers |
| **Web Services** | HTTP/HTTPS service analysis | Status codes, titles, headers, content |
| **Subdomain Discovery** | Multi-threaded subdomain enumeration | 70+ wordlist, DNS verification |
| **Email Harvesting** | Advanced email collection | Pattern matching, WHOIS extraction, edu generation |
| **Port Reconnaissance** | Service discovery scanning | 15 common ports, service identification |
| **Technology Detection** | Web stack fingerprinting | Servers, frameworks, CMS platforms |

## ⚙️ Configuration

### Thread Optimization
```python
# Adjust thread count based on your system and target
python phantom.py example.com -t 25   # Conservative
python phantom.py example.com -t 50   # Default
python phantom.py example.com -t 100  # Aggressive
```

### Subdomain Wordlist Customization
The tool includes an extensive subdomain wordlist optimized for:
- General web services (www, api, cdn, static)
- Email services (mail, smtp, webmail, exchange)
- Development environments (dev, test, staging, beta)
- Educational institutions (student, faculty, library, research)
- Administrative interfaces (admin, cpanel, dashboard)

## 🔒 Ethical Usage Guidelines

### ⚠️ **IMPORTANT DISCLAIMER**
This tool is designed for **authorized security testing only**. Users must:

- **Obtain explicit written permission** before scanning any domain
- **Comply with all applicable laws** and regulations
- **Respect robots.txt** and terms of service
- **Use responsibly** for legitimate security research
- **Avoid aggressive scanning** that could impact services

### Authorized Use Cases
- ✅ **Penetration testing** with signed agreements
- ✅ **Bug bounty programs** within scope
- ✅ **Your own domains** and infrastructure
- ✅ **Educational research** in controlled environments
- ✅ **Security audits** with proper authorization

### Prohibited Use Cases
- ❌ **Unauthorized reconnaissance** of third-party domains
- ❌ **Harassment** or malicious information gathering
- ❌ **Corporate espionage** or competitive intelligence
- ❌ **Privacy violations** or stalking activities

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Ways to Contribute
- 🐛 **Bug reports** and issue identification
- 💡 **Feature suggestions** and enhancements
- 🔧 **Code improvements** and optimizations
- 📚 **Documentation** updates and examples
- 🎨 **UI/UX improvements** for better user experience

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/AdiVKrish/phantom.git

# Create a feature branch
git checkout -b feature/new-feature

# Make your changes and test thoroughly
python phantom.py test-domain.com

# Submit a pull request
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- **TheHarvester**: Email harvesting tool
- **Sublist3r**: Subdomain enumeration tool
- **Amass**: Network mapping and asset discovery
- **Nmap**: Network discovery and security auditing

## 📧 Contact & Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/AdiVKrish/phantom/issues)
- **Email**: adikrishrightnow@gmail.com
- **LinkedIn**: [Your Professional Profile](https://www.linkedin.com/in/aditya-v-krishnan-4a3061256/)

## 🌟 Acknowledgments

- Thanks to the cybersecurity community for inspiration
- Special recognition to OSINT framework developers
- Appreciation for ethical hacking education resources

---

**⚡ Stay in the shadows... 👻**

*Phantom - Advanced Domain Reconnaissance & OSINT Framework*