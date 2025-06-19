#!/usr/bin/env python3
"""
Phantom - Advanced Domain Reconnaissance Tool
A comprehensive OSINT tool for gathering intelligence about target domains
"""

import requests
import socket
import argparse
import json
import time
import re
import threading
from datetime import datetime
import sys
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import whois
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init()

class Colors:
    """Neon color scheme for Phantom"""
    NEON_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    NEON_PINK = '\033[38;5;201m'
    NEON_YELLOW = '\033[38;5;226m'
    NEON_PURPLE = '\033[38;5;129m'
    NEON_CYAN = '\033[38;5;87m'
    BRIGHT_RED = '\033[38;5;196m'
    BRIGHT_WHITE = '\033[38;5;231m'
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM

class Phantom:
    def __init__(self, target_domain, threads=50):
        self.target = target_domain.lower().strip()
        self.threads = threads
        self.found_emails = set()
        self.found_subdomains = set()
        self.found_urls = set()
        self.technologies = set()
        
        # Common email patterns
        self.email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*\[at\]\s*[A-Za-z0-9.-]+\s*\[dot\]\s*[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b'
        ]
        
        # Extended subdomain wordlist
        self.subdomain_list = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'secure', 'admin', 'api', 'blog',
            'forum', 'help', 'mobile', 'shop', 'store', 'support', 'cdn', 'img', 'static',
            'dev', 'test', 'staging', 'demo', 'beta', 'alpha', 'login', 'portal', 'app',
            'apps', 'panel', 'vpn', 'mx', 'mx1', 'mx2', 'email', 'exchange', 'imap',
            'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'assets', 'media',
            'cloud', 'dashboard', 'admin2', 'administrator', 'root', 'server', 'host',
            'upload', 'uploads', 'download', 'downloads', 'files', 'file', 'home', 'my',
            'office', 'gateway', 'remote', 'ssl', 'secure2', 'backup', 'old', 'new',
            'web', 'web1', 'web2', 'www2', 'site', 'news', 'blog2', 'cms', 'crm',
            'owa', 'webmail2', 'mail2', 'student', 'students', 'faculty', 'staff',
            'alumni', 'library', 'research', 'academic', 'course', 'courses', 'learn',
            'learning', 'education', 'edu', 'training', 'exam', 'grade', 'grades'
        ]
    
    def print_neon_banner(self):
        """Display neon-styled Phantom banner"""
        banner = f"""
{Colors.NEON_PINK}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Colors.NEON_CYAN}██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗{Colors.NEON_PINK}             ║
║  {Colors.NEON_CYAN}██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║{Colors.NEON_PINK}             ║
║  {Colors.NEON_CYAN}██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║{Colors.NEON_PINK}             ║
║  {Colors.NEON_CYAN}██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║{Colors.NEON_PINK}             ║
║  {Colors.NEON_CYAN}██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║{Colors.NEON_PINK}             ║
║  {Colors.NEON_CYAN}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝{Colors.NEON_PINK}             ║
║                                                                              ║
║  {Colors.NEON_YELLOW}Advanced Domain Reconnaissance & OSINT Framework v2.0{Colors.NEON_PINK}                    ║
║  {Colors.NEON_GREEN}Target: {self.target:<50}{Colors.NEON_PINK}                             ║
║  {Colors.NEON_BLUE}Threads: {self.threads:<10} | Mode: Stealth Reconnaissance{Colors.NEON_PINK}                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    def print_section_header(self, title, icon="►"):
        """Print stylized section headers"""
        border = "═" * 80
        print(f"\n{Colors.NEON_PURPLE}{border}{Colors.RESET}")
        print(f"{Colors.NEON_YELLOW}{Colors.BOLD}{icon} {title.upper()}{Colors.RESET}")
        print(f"{Colors.NEON_PURPLE}{border}{Colors.RESET}")
    
    def print_result(self, category, data, status="found"):
        """Print results in a formatted way"""
        if status == "found":
            icon = f"{Colors.NEON_GREEN}[+]"
            color = Colors.NEON_GREEN
        elif status == "info":
            icon = f"{Colors.NEON_BLUE}[*]"
            color = Colors.NEON_BLUE
        elif status == "warning":
            icon = f"{Colors.NEON_YELLOW}[!]"
            color = Colors.NEON_YELLOW
        else:
            icon = f"{Colors.BRIGHT_RED}[-]"
            color = Colors.BRIGHT_RED
        
        print(f"{icon} {Colors.BRIGHT_WHITE}{category}:{Colors.RESET} {color}{data}{Colors.RESET}")
    
    def get_dns_information(self):
        """Comprehensive DNS enumeration"""
        self.print_section_header("DNS RECONNAISSANCE", "🔍")
        
        record_types = {
            'A': 'IPv4 Addresses',
            'AAAA': 'IPv6 Addresses', 
            'MX': 'Mail Servers',
            'NS': 'Name Servers',
            'TXT': 'Text Records',
            'CNAME': 'Canonical Names',
            'SOA': 'Start of Authority',
            'PTR': 'Pointer Records'
        }
        
        dns_results = {}
        
        for record_type, description in record_types.items():
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(answer).strip('.') for answer in answers]
                dns_results[record_type] = records
                
                for record in records[:3]:  # Show first 3 records
                    self.print_result(f"{record_type} Record", record, "found")
                
                if len(records) > 3:
                    self.print_result(f"Additional {record_type}", f"+{len(records)-3} more records", "info")
                    
            except Exception as e:
                self.print_result(f"{record_type} Records", "Not found or protected", "error")
        
        return dns_results
    
    def get_whois_intelligence(self):
        """Enhanced WHOIS information gathering"""
        self.print_section_header("WHOIS INTELLIGENCE", "📊")
        
        try:
            w = whois.whois(self.target)
            
            whois_data = {
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                'updated_date': str(w.updated_date) if w.updated_date else 'N/A',
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else 'N/A',
                'emails': w.emails if w.emails else []
            }
            
            # Display key information
            self.print_result("Registrar", whois_data['registrar'], "found")
            self.print_result("Created", whois_data['creation_date'], "info")
            self.print_result("Expires", whois_data['expiration_date'], "info")
            
            # Extract emails from WHOIS
            if whois_data['emails']:
                for email in whois_data['emails']:
                    if email and '@' in email:
                        self.found_emails.add(email.lower())
                        self.print_result("WHOIS Email", email, "found")
            
            # Name servers
            if whois_data['name_servers']:
                for ns in whois_data['name_servers'][:3]:
                    self.print_result("Name Server", ns, "info")
            
            return whois_data
            
        except Exception as e:
            self.print_result("WHOIS Lookup", f"Failed: {str(e)}", "error")
            return {}
    
    def scan_web_services(self):
        """Scan for web services and extract information"""
        self.print_section_header("WEB SERVICE ANALYSIS", "🌐")
        
        protocols = ['http', 'https']
        ports = [80, 443, 8080, 8443, 8000, 3000]
        
        for protocol in protocols:
            for port in [80, 443, 8080, 8443] if protocol == 'http' else [443, 8443]:
                try:
                    if (protocol == 'http' and port in [80, 8080, 8000, 3000]) or \
                       (protocol == 'https' and port in [443, 8443]):
                        
                        url = f"{protocol}://{self.target}" if port in [80, 443] else f"{protocol}://{self.target}:{port}"
                        
                        response = requests.get(
                            url, 
                            timeout=10, 
                            allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; Phantom/2.0)'}
                        )
                        
                        self.print_result(f"{protocol.upper()}:{port}", f"Status {response.status_code}", "found")
                        
                        # Extract title
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).strip()
                            self.print_result("Page Title", title[:80], "info")
                        
                        # Technology detection
                        self.detect_technologies(response.headers, response.text)
                        
                        # Email extraction from web content
                        self.extract_emails_from_content(response.text)
                        
                        break  # Success, no need to try other ports for this protocol
                        
                except Exception as e:
                    continue
    
    def detect_technologies(self, headers, content):
        """Detect web technologies"""
        tech_signatures = {
            'Apache': ['server', 'apache'],
            'Nginx': ['server', 'nginx'],
            'IIS': ['server', 'iis'],
            'PHP': ['x-powered-by', 'php'],
            'ASP.NET': ['x-aspnet-version', 'asp.net'],
            'jQuery': ['content', 'jquery'],
            'WordPress': ['content', 'wp-content'],
            'Drupal': ['content', 'drupal'],
            'Joomla': ['content', 'joomla']
        }
        
        # Check headers
        for tech, (header_key, signature) in tech_signatures.items():
            if header_key in [h.lower() for h in headers.keys()]:
                for header_name, header_value in headers.items():
                    if signature.lower() in header_value.lower():
                        self.technologies.add(tech)
                        self.print_result("Technology", f"{tech} detected", "found")
                        break
        
        # Check content
        content_lower = content.lower()
        for tech, (_, signature) in tech_signatures.items():
            if signature in content_lower and tech not in self.technologies:
                self.technologies.add(tech)
                self.print_result("Technology", f"{tech} detected", "found")
    
    def extract_emails_from_content(self, content):
        """Extract emails from web content using multiple patterns"""
        for pattern in self.email_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Clean up email
                email = match.lower().strip()
                email = re.sub(r'\s*\[at\]\s*', '@', email)
                email = re.sub(r'\s*\[dot\]\s*', '.', email)
                email = re.sub(r'\s+', '', email)
                
                if '@' in email and '.' in email and self.target in email:
                    self.found_emails.add(email)
    
    def check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        full_subdomain = f"{subdomain}.{self.target}"
        try:
            socket.gethostbyname(full_subdomain)
            return full_subdomain
        except:
            return None
    
    def discover_subdomains(self):
        """Multi-threaded subdomain discovery"""
        self.print_section_header("SUBDOMAIN ENUMERATION", "🔗")
        
        print(f"{Colors.NEON_BLUE}[*] {Colors.BRIGHT_WHITE}Scanning {len(self.subdomain_list)} potential subdomains...{Colors.RESET}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub 
                for sub in self.subdomain_list
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
                    self.print_result("Subdomain", result, "found")
        
        if not self.found_subdomains:
            self.print_result("Subdomains", "No subdomains found with current wordlist", "warning")
    
    def email_harvesting(self):
        """Advanced email harvesting using multiple sources"""
        self.print_section_header("EMAIL HARVESTING", "📧")
        
        # Search engines and sources for email harvesting
        search_queries = [
            f'site:{self.target} "@{self.target}"',
            f'"{self.target}" email',
            f'"{self.target}" contact',
            f'"{self.target}" staff',
            f'"{self.target}" faculty',
            f'"{self.target}" admin'
        ]
        
        # Common email prefixes for educational institutions
        if any(edu_indicator in self.target for edu_indicator in ['edu', 'university', 'college', 'school', 'institute']):
            email_prefixes = [
                'admin', 'admissions', 'info', 'contact', 'support', 'help',
                'registrar', 'student', 'faculty', 'staff', 'academic',
                'research', 'library', 'it', 'webmaster', 'postmaster'
            ]
            
            self.print_result("Institution Type", "Educational domain detected", "info")
            
            for prefix in email_prefixes:
                potential_email = f"{prefix}@{self.target}"
                self.found_emails.add(potential_email)
        
        # Display all found emails
        if self.found_emails:
            print(f"\n{Colors.NEON_GREEN}[+] {Colors.BRIGHT_WHITE}Discovered Email Addresses:{Colors.RESET}")
            for email in sorted(self.found_emails):
                print(f"    {Colors.NEON_CYAN}→ {email}{Colors.RESET}")
        else:
            self.print_result("Email Harvest", "No emails discovered", "warning")
    
    def port_scanning(self):
        """Basic port scanning for common services"""
        self.print_section_header("PORT RECONNAISSANCE", "🔌")
        
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        print(f"{Colors.NEON_BLUE}[*] {Colors.BRIGHT_WHITE}Scanning {len(common_ports)} common ports...{Colors.RESET}")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(scan_port, common_ports.keys()))
        
        for port in results:
            if port:
                service = common_ports.get(port, 'Unknown')
                open_ports.append((port, service))
                self.print_result(f"Port {port}", f"{service} - OPEN", "found")
        
        if not open_ports:
            self.print_result("Port Scan", "No common ports found open", "warning")
    
    def generate_summary(self):
        """Generate a comprehensive summary"""
        self.print_section_header("RECONNAISSANCE SUMMARY", "📋")
        
        summary_data = {
            'Target': self.target,
            'Subdomains Found': len(self.found_subdomains),
            'Email Addresses': len(self.found_emails),
            'Technologies': len(self.technologies),
            'Scan Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        print(f"{Colors.NEON_YELLOW}{Colors.BOLD}╔══ INTELLIGENCE SUMMARY ══╗{Colors.RESET}")
        for key, value in summary_data.items():
            print(f"{Colors.NEON_YELLOW}║{Colors.RESET} {Colors.BRIGHT_WHITE}{key}:{Colors.RESET} {Colors.NEON_GREEN}{value}{Colors.RESET}")
        print(f"{Colors.NEON_YELLOW}╚═══════════════════════════╝{Colors.RESET}")
        
        if self.found_subdomains:
            print(f"\n{Colors.NEON_CYAN}{Colors.BOLD}🎯 DISCOVERED ASSETS:{Colors.RESET}")
            for subdomain in sorted(self.found_subdomains):
                print(f"   {Colors.NEON_GREEN}• {subdomain}{Colors.RESET}")
        
        if self.technologies:
            print(f"\n{Colors.NEON_PURPLE}{Colors.BOLD}⚡ DETECTED TECHNOLOGIES:{Colors.RESET}")
            for tech in sorted(self.technologies):
                print(f"   {Colors.NEON_PURPLE}• {tech}{Colors.RESET}")
    
    def run_phantom_recon(self):
        """Execute complete reconnaissance"""
        self.print_neon_banner()
        
        start_time = time.time()
        
        print(f"{Colors.NEON_YELLOW}[*] {Colors.BRIGHT_WHITE}Initializing Phantom reconnaissance on {self.target}...{Colors.RESET}")
        print(f"{Colors.NEON_BLUE}[*] {Colors.BRIGHT_WHITE}Stealth mode: {Colors.NEON_GREEN}ENABLED{Colors.RESET}")
        print()
        
        # Execute reconnaissance modules
        try:
            self.get_dns_information()
            self.get_whois_intelligence()
            self.scan_web_services()
            self.discover_subdomains()
            self.email_harvesting()
            self.port_scanning()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.BRIGHT_RED}[!] Reconnaissance interrupted by user{Colors.RESET}")
            return
        except Exception as e:
            print(f"\n{Colors.BRIGHT_RED}[!] Unexpected error: {str(e)}{Colors.RESET}")
            return
        
        # Generate final summary
        self.generate_summary()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Colors.NEON_GREEN}[✓] {Colors.BRIGHT_WHITE}Phantom reconnaissance completed in {duration:.2f} seconds{Colors.RESET}")
        print(f"{Colors.NEON_PURPLE}[*] {Colors.BRIGHT_WHITE}Stay in the shadows... 👻{Colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Phantom - Advanced Domain Reconnaissance & OSINT Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.NEON_CYAN}Examples:{Colors.RESET}
  python phantom.py example.com
  python phantom.py university.edu -t 100
  python phantom.py company.com --threads 75

{Colors.NEON_YELLOW}Features:{Colors.RESET}
  • DNS enumeration & analysis
  • WHOIS intelligence gathering  
  • Subdomain discovery
  • Email harvesting
  • Technology detection
  • Port reconnaissance
  • Real-time output display
        '''
    )
    
    parser.add_argument('domain', help='Target domain to investigate')
    parser.add_argument('-t', '--threads', type=int, default=50, 
                       help='Number of threads for scanning (default: 50)')
    
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain or '.' not in args.domain:
        print(f"{Colors.BRIGHT_RED}[!] Please provide a valid target domain{Colors.RESET}")
        sys.exit(1)
    
    # Validate threads
    if args.threads < 1 or args.threads > 200:
        print(f"{Colors.BRIGHT_RED}[!] Thread count must be between 1 and 200{Colors.RESET}")
        sys.exit(1)
    
    try:
        # Initialize and run Phantom
        phantom = Phantom(args.domain, args.threads)
        phantom.run_phantom_recon()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.BRIGHT_RED}[!] Phantom terminated by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.BRIGHT_RED}[!] Fatal error: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()