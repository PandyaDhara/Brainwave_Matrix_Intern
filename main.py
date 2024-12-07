import re
import requests
from urllib.parse import urlparse
import ssl
import socket
import whois
from datetime import datetime
import dns.resolver


def check_url_length(url):
    return len(url) > 75


def check_shortening_services(url):
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly"]
    return any(service in url for service in shortening_services)


def check_at_symbol(url):
    return '@' in url


def check_ip_address(url):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return bool(re.search(pattern, url))


def check_double_slash_redirect(url):
    return '//' in urlparse(url).path


def check_prefix_suffix(domain):
    return '-' in domain


def check_subdomains(url):
    return urlparse(url).netloc.count('.') > 2


def check_https(url):
    return urlparse(url).scheme == 'https'


def check_domain_expiration(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w.expiration_date, list):
            expiration_date = w.expiration_date[0]
        else:
            expiration_date = w.expiration_date
        if expiration_date:
            days_until_expiration = (expiration_date - datetime.now()).days
            return days_until_expiration < 365, expiration_date
        else:
            return False, None
    except:
        return False, None


def check_ssl_cert(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock,
                                     server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return subject['commonName'] != hostname, cert['notAfter']
    except:
        return True, None


def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def get_dns_info(domain):
    dns_info = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_info[record_type] = [str(rdata) for rdata in answers]
        except:
            dns_info[record_type] = []
    return dns_info


def is_phishing(url):
    domain = urlparse(url).netloc
    checks = [
        check_url_length(url),
        check_shortening_services(url),
        check_at_symbol(url),
        check_ip_address(url),
        check_double_slash_redirect(url),
        check_prefix_suffix(domain),
        check_subdomains(url), not check_https(url)
    ]
    domain_exp_check, domain_expiration = check_domain_expiration(domain)
    ssl_check, ssl_not_after = check_ssl_cert(url)

    checks.append(domain_exp_check)
    checks.append(ssl_check)

    return sum(checks) >= 3, domain_expiration, ssl_not_after


def scan_url(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            is_phishing_result, domain_expiration, ssl_not_after = is_phishing(
                url)
            domain = urlparse(url).netloc
            subdomain_count = domain.count('.') - 1
            https_status = check_https(url)
            ip_address = get_ip_address(domain)
            dns_info = get_dns_info(domain)

            result = {
                "URL":
                url,
                "Safe or Malicious":
                "Malicious" if is_phishing_result else "Safe",
                "Domain":
                domain,
                "IP Address":
                ip_address if ip_address else "N/A",
                "Subdomain Count":
                subdomain_count,
                "HTTPS":
                "Yes" if https_status else "No",
                "Domain Expiration Date":
                domain_expiration if domain_expiration else "N/A",
                "SSL Certificate Valid Until":
                ssl_not_after if ssl_not_after else "N/A",
                "DNS Information":
                dns_info
            }
            return result
        else:
            return f"Unable to access URL. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"Error accessing URL: {str(e)}"


# Example usage
if __name__ == "__main__":
    while True:
        url = input("Enter a URL to scan (or 'quit' to exit): ")
        if url.lower() == 'quit':
            break
        result = scan_url(url)
        if isinstance(result, dict):
            for key, value in result.items():
                if key == "DNS Information":
                    print(f"{key}:")
                    for record_type, records in value.items():
                        print(
                            f"  {record_type}: {', '.join(records) if records else 'Not found'}"
                        )
                else:
                    print(f"{key}: {value}")
        else:
            print(result)
        print("-" * 50)
