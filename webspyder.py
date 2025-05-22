
# webspyder.py

import socket
import whois
import requests
import re
import json
import dns.resolver
import ssl
import pyfiglet
import time
from Wappalyzer import Wappalyzer, WebPage
from OpenSSL import crypto
from tqdm import tqdm
from bs4 import BeautifulSoup
import webbrowser

def slow_type(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def print_banner():
    ascii_banner = pyfiglet.figlet_format("WEBSPYDER")
    slow_type(ascii_banner, delay=0.001)
    print("=" * 60)
    print("Github: https://www.github.com/hackwithyash")
    print("=" * 60)
    print("🕵️‍♂️ WebSpyder - A powerful Website OSINT CLI tool by Hack With Yash")
    print("=" * 60)
    telegram_channel_url = "https://t.me/hack_with_yash"
    webbrowser.open(telegram_channel_url)

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error: {e}"

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error: {e}"

def get_dns_records(domain):
    try:
        records = {}
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
            records[qtype] = [r.to_text() for r in answers]
        return records
    except Exception as e:
        return f"Error: {e}"

def get_emails(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text)
        return list(set(emails))
    except Exception as e:
        return f"Error: {e}"

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
        return cert
    except Exception as e:
        return f"Error: {e}"

def detect_cms(domain):
    try:
        url = f"http://{domain}"
        webpage = WebPage.new_from_url(url, timeout=10)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        cms_list = ['WordPress', 'Drupal', 'Joomla', 'Shopify', 'Magento', 'Blogger', 'Wix', 'Squarespace']
        detected_cms = [tech for tech in technologies if tech in cms_list]
        return ", ".join(detected_cms) if detected_cms else "CMS not detected"
    except Exception as e:
        return f"Error detecting CMS: {str(e)}"

def get_subdomains(domain):
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        json_data = json.loads(response.text)
        subdomains = set(entry['name_value'] for entry in json_data)
        return list(subdomains)
    except Exception as e:
        return f"Error: {e}"

def get_robots_sitemap(domain):
    results = {}
    for path in ["robots.txt", "sitemap.xml"]:
        try:
            url = f"http://{domain}/{path}"
            response = requests.get(url, timeout=5)
            results[path] = response.text if response.status_code == 200 else "Not Found"
        except:
            results[path] = "Error"
    return results

def check_security_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        headers = response.headers
        security_headers = [
            'Content-Security-Policy', 'Strict-Transport-Security',
            'X-Content-Type-Options', 'X-Frame-Options',
            'X-XSS-Protection', 'Referrer-Policy'
        ]
        return {h: headers.get(h, "Not Set") for h in security_headers}
    except Exception as e:
        return f"Error: {e}"

def extract_social_links(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        social = [link for link in links if any(x in link for x in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube'])]
        return social
    except Exception as e:
        return f"Error: {e}"

def scan_ports(domain, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]):
    open_ports = []
    ip = get_ip(domain)
    for port in tqdm(ports, desc="🔎 Scanning Ports"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            continue
    return open_ports

def main():
    print_banner()
    domain = input("🔍 Enter target domain (e.g. example.com): ").strip()
    slow_type(f"\n🔧 Gathering OSINT data for: {domain}\n", delay=0.02)

    print("🌐 IP Address:", get_ip(domain))
    print("\n📜 WHOIS Info:")
    print(get_whois(domain))
    print("\n🧾 DNS Records:")
    print(json.dumps(get_dns_records(domain), indent=2))
    print("\n📧 Emails Found:", get_emails(domain))
    print("\n🔐 SSL Certificate Info:")
    print(get_ssl_info(domain))
    print("\n🧠 CMS Detection:", detect_cms(domain))
    print("\n🌍 Subdomains Found:")
    subs = get_subdomains(domain)
    print("\n".join([" - " + s for s in subs]) if isinstance(subs, list) else subs)
    print("\n📁 Robots.txt & Sitemap.xml:")
    print(json.dumps(get_robots_sitemap(domain), indent=2))
    print("\n🛡 Security Headers:")
    print(json.dumps(check_security_headers(domain), indent=2))
    print("\n🔗 Social Media Links:")
    social = extract_social_links(domain)
    print("\n".join([" - " + s for s in social]) if isinstance(social, list) else social)
    print("\n🔓 Open Ports:")
    ports = scan_ports(domain)
    print(", ".join(map(str, ports)) if ports else "No common ports open")

    slow_type("\n✅ OSINT scan completed.\n", delay=0.02)

if __name__ == "__main__":
    main()
