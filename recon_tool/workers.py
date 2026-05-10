import contextlib
import io
import asyncio
import ipaddress
import json
import re
import shutil
import ssl
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver
import whois
try:
    import builtwith
except ImportError:
    builtwith = None
try:
    import nvdlib
except ImportError:
    nvdlib = None
try:
    from OpenSSL import crypto
except ImportError:
    crypto = None
from cryptography import x509
from cryptography.hazmat.backends import default_backend
try:
    import nmap
except ImportError:
    nmap = None
from PyQt6.QtCore import QObject, pyqtSignal

from .utils import is_cloudflare_ip

class DNSLookupWorker(QObject):
    """DNS so'rovlarni UI threaddan tashqarida bajaradi."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, domain, record_types):
        super().__init__()
        self.domain = domain
        self.record_types = record_types

    def run(self):
        try:
            self.finished.emit(self.get_records())
        except dns.resolver.NXDOMAIN:
            self.error.emit("Domen topilmadi")
        except dns.exception.Timeout:
            self.error.emit("DNS so'rov vaqti tugadi")
        except dns.exception.DNSException as e:
            self.error.emit(f"DNS xatosi: {e}")
        except Exception as e:
            self.error.emit(str(e))

    def get_records(self):
        dns_info = {}
        for rtype in self.record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                ttl = answers.rrset.ttl if answers.rrset is not None else '?'
                dns_info[rtype] = [
                    {
                        'value': str(answer).rstrip('.'),
                        'ttl': ttl,
                        **({'preference': answer.preference} if rtype == 'MX' and hasattr(answer, 'preference') else {})
                    }
                    for answer in answers
                ]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                dns_info[rtype] = []
            except dns.exception.Timeout:
                dns_info[rtype] = []
        return dns_info


class ReconWorker(QObject):
    """Reconnaissance ishchi thread - TO'LIQ TO'G'RILANGAN"""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    
    def run(self):
        """Reconnaissance ishni bajarish"""
        try:
            results = asyncio.run(self.run_async())
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))

    async def run_async(self):
        """Mustaqil recon ishlarini parallel bajarish."""
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=8) as executor:
            whois_future = loop.run_in_executor(executor, self.get_whois_info)
            dns_future = loop.run_in_executor(executor, self.get_dns_records)
            subdomain_future = loop.run_in_executor(executor, self.get_passive_subdomains)
            tls_future = loop.run_in_executor(executor, self.analyze_tls_certificate)
            tech_future = loop.run_in_executor(executor, self.detect_technologies)
            nmap_future = loop.run_in_executor(executor, self.scan_open_ports)

            initial_results = await asyncio.gather(
                whois_future,
                dns_future,
                subdomain_future,
                tls_future,
                tech_future,
                nmap_future,
                return_exceptions=True,
            )
            whois_result = self.safe_result(initial_results[0], ({'domain': self.domain}, ""))
            dns_data = self.safe_result(initial_results[1], {})
            subdomains = self.safe_result(initial_results[2], [])
            tls_data = self.safe_result(initial_results[3], self.default_status("tls", "TLS analysis failed"))
            tech_data = self.safe_result(initial_results[4], {"url": "", "sources": [], "headers": {}, "technologies": []})
            nmap_data = self.safe_result(initial_results[5], self.default_status("nmap", "Nmap scan failed", open_ports=[]))
            whois_data, raw_whois = whois_result

            osint_future = loop.run_in_executor(executor, self.get_passive_osint, raw_whois, subdomains)
            waf_future = loop.run_in_executor(executor, self.detect_waf_firewall, dns_data)
            cve_future = loop.run_in_executor(executor, self.find_cves, tech_data)
            attack_future = loop.run_in_executor(executor, self.analyze_attack_vectors, whois_data, dns_data)

            dependent_results = await asyncio.gather(
                osint_future,
                waf_future,
                cve_future,
                attack_future,
                return_exceptions=True,
            )
            osint_data = self.safe_result(dependent_results[0], self.default_osint())
            waf_data = self.safe_result(dependent_results[1], self.default_status("waf", "WAF detection failed", evidence=[], headers={}, notes=[]))
            cve_data = self.safe_result(dependent_results[2], {"status": "error", "items": [], "message": "CVE lookup failed"})
            attack_vectors = self.safe_result(dependent_results[3], [])

        return {
            'domain': self.domain,
            'whois': whois_data,
            'dns': dns_data,
            'subdomains': subdomains,
            'osint': osint_data,
            'waf': waf_data,
            'nmap': nmap_data,
            'technologies': tech_data,
            'cves': cve_data,
            'tls': tls_data,
            'attack_vectors': attack_vectors,
            'raw_whois': raw_whois
        }

    def safe_result(self, value, fallback):
        """Async task exception bo'lsa butun scan yiqilmasin."""
        if isinstance(value, Exception):
            if isinstance(fallback, dict):
                fallback = dict(fallback)
                fallback["status"] = fallback.get("status", "error")
                fallback["message"] = str(value)
            return fallback
        return value

    def default_status(self, status_name, message, **extra):
        data = {"status": "error", "name": status_name, "message": message}
        data.update(extra)
        return data

    def default_osint(self):
        return {
            "mode": "passive-only",
            "summary": {"subdomains": 0, "emails": 0, "urls": 0, "interesting_urls": 0, "takeover_hints": 0, "sources": 0},
            "sources": [],
            "emails": [],
            "urls": [],
            "interesting_urls": [],
            "infra": [],
            "takeover_hints": [],
        }
    
    def get_whois_info(self):
        """WHOIS ma'lumotlarini olish - 100% ishlaydigan versiya"""
        whois_info = {
            'domain': self.domain,
            'registrar': None,
            'registrar_url': None,
            'creation_date': None,
            'updated_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': [],
            'dnssec': 'unsigned',
            'abuse_email': None,
            'abuse_phone': None,
            'registrar_iana_id': None,
            'whois_server': None
        }
        
        raw_whois = ""
        
        try:
            # 1. python-whois orqali olish
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                w = whois.whois(self.domain)
            
            whois_info['registrar'] = w.registrar if hasattr(w, 'registrar') else None
            whois_info['registrar_url'] = w.registrar_url if hasattr(w, 'registrar_url') else None
            whois_info['creation_date'] = w.creation_date if hasattr(w, 'creation_date') else None
            whois_info['updated_date'] = w.updated_date if hasattr(w, 'updated_date') else None
            whois_info['expiration_date'] = w.expiration_date if hasattr(w, 'expiration_date') else None
            whois_info['name_servers'] = w.name_servers if hasattr(w, 'name_servers') else []
            whois_info['status'] = w.status if hasattr(w, 'status') else []
            whois_info['dnssec'] = w.dnssec if hasattr(w, 'dnssec') else 'unsigned'
            whois_info['whois_server'] = w.whois_server if hasattr(w, 'whois_server') else None
            
        except Exception:
            pass
        
        # 2. SOCKET orqali to'g'ridan-to'g'ri WHOIS so'rovi
        try:
            raw_whois = self.get_raw_whois_socket(self.domain)
            
            # Abuse Email
            email_match = re.search(r'Registrar Abuse Contact Email:\s*([^\s]+@[^\s]+)', raw_whois, re.IGNORECASE)
            if email_match:
                whois_info['abuse_email'] = email_match.group(1)
            
            # Abuse Phone
            phone_match = re.search(r'Registrar Abuse Contact Phone:\s*([+\d\s.-]+)', raw_whois, re.IGNORECASE)
            if phone_match:
                whois_info['abuse_phone'] = phone_match.group(1).strip()
            
            # Registrar IANA ID
            iana_match = re.search(r'Registrar IANA ID:\s*(\d+)', raw_whois, re.IGNORECASE)
            if iana_match:
                whois_info['registrar_iana_id'] = iana_match.group(1)
            
            # Domain Status (agar python-whois olmagan bo'lsa)
            if not whois_info['status']:
                status_matches = re.findall(r'Domain Status:\s*(.+?)(?:\n|$)', raw_whois, re.IGNORECASE)
                if status_matches:
                    whois_info['status'] = [s.strip() for s in status_matches if s.strip()]
            
            # Name Servers (agar python-whois olmagan bo'lsa)
            if not whois_info['name_servers']:
                ns_matches = re.findall(r'Name Server:\s*(.+?)(?:\n|$)', raw_whois, re.IGNORECASE)
                if ns_matches:
                    whois_info['name_servers'] = [ns.strip() for ns in ns_matches if ns.strip()]
            
            # DNSSEC
            dnssec_match = re.search(r'DNSSEC:\s*(\S+)', raw_whois, re.IGNORECASE)
            if dnssec_match:
                whois_info['dnssec'] = dnssec_match.group(1).lower()
            
        except Exception:
            pass
        
        return whois_info, raw_whois
    
    def get_raw_whois_socket(self, domain):
        """Socket orqali to'g'ridan-to'g'ri WHOIS so'rovi"""
        try:
            whois_server = self.get_whois_server(domain)
            if not whois_server:
                return ""

            return self.query_whois_server(whois_server, domain)
            
        except Exception:
            pass
            
            # Backup: whois komandasi (agar mavjud bo'lsa)
            try:
                result = subprocess.run(['whois', domain], 
                                      capture_output=True, text=True, timeout=5)
                return result.stdout
            except (OSError, subprocess.SubprocessError):
                return ""

    def get_whois_server(self, domain):
        """IANA referral orqali domen uchun mos WHOIS serverni topish."""
        tld = domain.rsplit(".", 1)[-1]
        response = self.query_whois_server("whois.iana.org", tld)
        refer_match = re.search(r"^refer:\s*(\S+)", response, re.IGNORECASE | re.MULTILINE)
        if refer_match:
            return refer_match.group(1).strip()
        whois_match = re.search(r"^whois:\s*(\S+)", response, re.IGNORECASE | re.MULTILINE)
        if whois_match:
            return whois_match.group(1).strip()
        return None

    def query_whois_server(self, whois_server, query):
        """Bitta WHOIS serverga so'rov yuborib raw javobni qaytarish."""
        with socket.create_connection((whois_server, 43), timeout=10) as sock:
            sock.sendall(f"{query}\r\n".encode("utf-8"))
            response = bytearray()
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response.extend(data)
        return response.decode("utf-8", errors="ignore")
    
    def get_dns_records(self):
        """Barcha DNS recordlarni olish"""
        dns_info = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = []
                ttl = answers.rrset.ttl if answers.rrset is not None else '?'
                
                for answer in answers:
                    record = {
                        'value': str(answer).rstrip('.'),
                        'ttl': ttl
                    }
                    
                    if rtype == 'MX' and hasattr(answer, 'preference'):
                        record['preference'] = answer.preference
                    
                    records.append(record)
                
                dns_info[rtype] = records
                
            except dns.resolver.NoAnswer:
                dns_info[rtype] = []
            except dns.resolver.NXDOMAIN:
                dns_info[rtype] = []
            except Exception:
                dns_info[rtype] = []
        
        return dns_info

    def get_passive_subdomains(self):
        """Subfinder uslubida bir nechta passive manbadan subdomain topish."""
        subdomains = set()
        self.passive_source_stats = []
        self.passive_source_errors = {}
        sources = [
            ("subfinder", self.fetch_subfinder_subdomains),
            ("crt.sh", self.fetch_crtsh_subdomains),
            ("CertSpotter", self.fetch_certspotter_subdomains),
            ("AlienVault OTX", self.fetch_alienvault_subdomains),
            ("HackerTarget", self.fetch_hackertarget_subdomains),
            ("URLScan", self.fetch_urlscan_subdomains),
            ("RapidDNS", self.fetch_rapiddns_subdomains),
            ("Wayback CDX", self.fetch_wayback_subdomains),
            ("BufferOver", self.fetch_bufferover_subdomains),
            ("ThreatMiner", self.fetch_threatminer_subdomains),
            ("AnubisDB", self.fetch_anubis_subdomains),
        ]

        with ThreadPoolExecutor(max_workers=min(8, len(sources))) as executor:
            future_map = {executor.submit(source_func): source_name for source_name, source_func in sources}
            for future in as_completed(future_map):
                source_name = future_map[future]
                try:
                    found = future.result()
                    subdomains.update(found)
                    status = self.passive_source_errors.get(source_name, "ok")
                    self.passive_source_stats.append({
                        "name": source_name,
                        "status": status,
                        "count": len(found),
                    })
                except Exception as e:
                    self.passive_source_stats.append({
                        "name": source_name,
                        "status": f"unavailable: {e}",
                        "count": 0,
                    })

        return sorted(subdomains)

    def note_passive_source_error(self, source_name, error):
        """Passive source xatosini konsolga chiqarmasdan status sifatida saqlash."""
        if not hasattr(self, "passive_source_errors"):
            self.passive_source_errors = {}
        self.passive_source_errors[source_name] = f"unavailable: {error}"

    def fetch_subfinder_subdomains(self):
        """Agar o'rnatilgan bo'lsa ProjectDiscovery subfinder natijasini qo'shish."""
        if not shutil.which("subfinder"):
            return set()

        result = subprocess.run(
            ["subfinder", "-silent", "-all", "-d", self.domain],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        return self.extract_subdomains(result.stdout)

    def fetch_crtsh_subdomains(self):
        """crt.sh certificate transparency loglaridan passive subdomain topish."""
        subdomains = set()
        entries = []
        for query_value in (f"%.{self.domain}", self.domain):
            query = urllib.parse.quote(query_value, safe="")
            url = f"https://crt.sh/?q={query}&output=json"
            try:
                payload = self.http_get(url, timeout=25)
                entries = json.loads(payload)
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
                self.note_passive_source_error("crt.sh", e)

        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in str(name_value).splitlines():
                subdomains.update(self.extract_subdomains(name))

        return subdomains

    def fetch_certspotter_subdomains(self):
        """CertSpotter public CT API orqali passive subdomain topish."""
        subdomains = set()
        query = urllib.parse.quote(f"*.{self.domain}")
        url = f"https://api.certspotter.com/v1/issuances?domain={query}&include_subdomains=true&expand=dns_names"
        try:
            payload = self.http_get(url, timeout=25)
            entries = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("CertSpotter", e)
            return set()

        for entry in entries:
            for dns_name in entry.get("dns_names", []):
                subdomains.update(self.extract_subdomains(dns_name))
        return subdomains

    def fetch_alienvault_subdomains(self):
        """AlienVault OTX passive DNS endpoint orqali subdomain topish."""
        encoded_domain = urllib.parse.quote(self.domain)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{encoded_domain}/passive_dns"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("AlienVault OTX", e)
            return set()

        for record in data.get("passive_dns", []):
            for key in ("hostname", "address"):
                subdomains.update(self.extract_subdomains(record.get(key, "")))
        return subdomains

    def fetch_hackertarget_subdomains(self):
        """HackerTarget hostsearch endpoint orqali passive subdomain topish."""
        encoded_domain = urllib.parse.quote(self.domain)
        url = f"https://api.hackertarget.com/hostsearch/?q={encoded_domain}"
        try:
            payload = self.http_get(url, timeout=25)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self.note_passive_source_error("HackerTarget", e)
            return set()

        return self.extract_subdomains(payload)

    def fetch_urlscan_subdomains(self):
        """URLScan public search natijalaridan subdomainlarni ajratish."""
        query = urllib.parse.quote(f"domain:{self.domain}")
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("URLScan", e)
            return set()

        subdomains = set()
        for result in data.get("results", []):
            page = result.get("page", {})
            task = result.get("task", {})
            for value in (page.get("domain", ""), page.get("url", ""), task.get("url", "")):
                subdomains.update(self.extract_subdomains(value))
        return subdomains

    def fetch_urlscan_urls(self):
        """URLScan public search orqali passive URLlarni olish."""
        query = urllib.parse.quote(f"domain:{self.domain}")
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=100"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("URLScan URLs", e)
            return []

        urls = []
        for result in data.get("results", []):
            page = result.get("page", {})
            task = result.get("task", {})
            for value in (page.get("url", ""), task.get("url", "")):
                if value:
                    urls.append(str(value))
        return sorted(set(urls))

    def fetch_rapiddns_subdomains(self):
        """RapidDNS HTML natijalaridan subdomainlarni ajratish."""
        encoded_domain = urllib.parse.quote(self.domain)
        url = f"https://rapiddns.io/subdomain/{encoded_domain}?full=1"
        try:
            payload = self.http_get(url, timeout=25)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self.note_passive_source_error("RapidDNS", e)
            return set()
        return self.extract_subdomains(payload)

    def fetch_wayback_subdomains(self):
        """Internet Archive CDX URL tarixidan subdomainlarni ajratish."""
        encoded_domain = urllib.parse.quote(f"*.{self.domain}/*")
        url = f"https://web.archive.org/cdx?url={encoded_domain}&output=json&fl=original&collapse=urlkey"
        try:
            payload = self.http_get(url, timeout=30)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self.note_passive_source_error("Wayback CDX", e)
            return set()
        return self.extract_subdomains(payload)

    def fetch_wayback_urls(self):
        """Internet Archive CDX orqali tarixiy URLlarni olish."""
        encoded_domain = urllib.parse.quote(f"*.{self.domain}/*")
        url = f"https://web.archive.org/cdx?url={encoded_domain}&output=json&fl=original&collapse=urlkey&limit=500"
        try:
            payload = self.http_get(url, timeout=30)
            rows = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("Wayback URLs", e)
            return []

        urls = []
        for row in rows[1:] if isinstance(rows, list) else []:
            if isinstance(row, list) and row:
                urls.append(str(row[0]))
        return sorted(set(urls))

    def fetch_bufferover_subdomains(self):
        """BufferOver DNS datasetidan subdomainlarni ajratish."""
        encoded_domain = urllib.parse.quote(f".{self.domain}")
        url = f"https://dns.bufferover.run/dns?q={encoded_domain}"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("BufferOver", e)
            return set()

        subdomains = set()
        for key in ("FDNS_A", "RDNS"):
            for row in data.get(key, []) or []:
                subdomains.update(self.extract_subdomains(row))
        return subdomains

    def fetch_threatminer_subdomains(self):
        """ThreatMiner domain API orqali passive subdomain topish."""
        encoded_domain = urllib.parse.quote(self.domain)
        url = f"https://api.threatminer.org/v2/domain.php?q={encoded_domain}&rt=5"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("ThreatMiner", e)
            return set()

        return self.extract_subdomains("\n".join(data.get("results", []) or []))

    def fetch_anubis_subdomains(self):
        """AnubisDB public endpoint orqali passive subdomain topish."""
        encoded_domain = urllib.parse.quote(self.domain)
        url = f"https://jldc.me/anubis/subdomains/{encoded_domain}"
        try:
            payload = self.http_get(url, timeout=25)
            data = json.loads(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.note_passive_source_error("AnubisDB", e)
            return set()

        return self.extract_subdomains("\n".join(data if isinstance(data, list) else []))

    def http_get(self, url, timeout=20):
        """Oddiy HTTP GET helper."""
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "PentestReconTool/3.1",
                "Accept": "application/json,text/plain,*/*",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")

    def extract_subdomains(self, text):
        """Matndan domen osti nomlarini regex orqali ajratish va tozalash."""
        candidates = re.findall(
            rf"(?:\*\.)?(?:[a-zA-Z0-9-]+\.)+{re.escape(self.domain)}",
            str(text),
            flags=re.IGNORECASE,
        )
        cleaned = set()
        for candidate in candidates:
            subdomain = self.clean_subdomain(candidate)
            if subdomain:
                cleaned.add(subdomain)
        return cleaned

    def clean_subdomain(self, value):
        """crt.sh qiymatini bitta valid subdomain nomiga aylantirish."""
        subdomain = str(value).strip().lower().lstrip("*.").rstrip(".")
        if not subdomain.endswith(f".{self.domain}"):
            return None
        if subdomain == self.domain:
            return None
        try:
            subdomain = subdomain.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+", subdomain):
            return subdomain
        return None

    def get_passive_osint(self, raw_whois, subdomains):
        """Faol probing qilmasdan OSINT artefaktlarini yig'ish."""
        with ThreadPoolExecutor(max_workers=2) as executor:
            wayback_future = executor.submit(self.fetch_wayback_urls)
            urlscan_future = executor.submit(self.fetch_urlscan_urls)
            urls = sorted(set(wayback_future.result(timeout=35) + urlscan_future.result(timeout=35)))
        emails = sorted(self.extract_emails("\n".join([raw_whois, "\n".join(urls)])))
        interesting_urls = self.find_interesting_urls(urls)
        infra = self.build_passive_infra(subdomains, urls)
        takeover_hints = self.find_takeover_hints(subdomains)

        return {
            "mode": "passive-only",
            "summary": {
                "subdomains": len(subdomains),
                "emails": len(emails),
                "urls": len(urls),
                "interesting_urls": len(interesting_urls),
                "takeover_hints": len(takeover_hints),
                "sources": len(getattr(self, "passive_source_stats", [])),
            },
            "sources": self.build_osint_source_status(),
            "emails": emails,
            "urls": urls,
            "interesting_urls": interesting_urls,
            "infra": infra,
            "takeover_hints": takeover_hints,
        }

    def build_osint_source_status(self):
        """Subdomain va URL passive source statuslarini bitta ro'yxatga jamlash."""
        stats = list(getattr(self, "passive_source_stats", []))
        known = {item.get("name") for item in stats}
        for name in ("Wayback URLs", "URLScan URLs"):
            if name in known:
                continue
            status = getattr(self, "passive_source_errors", {}).get(name, "ok")
            stats.append({"name": name, "status": status, "count": 0})
        return stats

    def extract_emails(self, text):
        """Passive matndan email manzillarni ajratish."""
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", str(text))
        return {
            email.strip(".,;:()[]{}<>\"'").lower()
            for email in emails
            if email.lower().endswith(f".{self.domain}") or email.lower().endswith(f"@{self.domain}")
        }

    def find_interesting_urls(self, urls):
        """Tarixiy/passive URLlar ichidan ehtimoliy qiziqarli fayl va endpointlarni ajratish."""
        patterns = (
            "admin", "login", "dashboard", "backup", "config", ".env", ".git",
            "swagger", "api-docs", "openapi", "debug", "test", "staging",
            "dev", "upload", "private", "secret", "token", "key=", "password",
            ".sql", ".bak", ".zip", ".tar", ".gz", ".7z", ".old", ".log",
        )
        interesting = []
        for url in urls:
            lowered = url.lower()
            if any(pattern in lowered for pattern in patterns):
                interesting.append(url)
        return sorted(set(interesting))

    def build_passive_infra(self, subdomains, urls):
        """Faqat passive manbalardan kelgan host/URL summary."""
        infra = []
        for host in subdomains[:300]:
            infra.append({
                "type": "HOST",
                "value": host,
                "source": "passive subdomain sources",
            })
        for url in urls[:100]:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc:
                infra.append({
                    "type": "URL_HOST",
                    "value": parsed.netloc.lower(),
                    "source": "Wayback/URLScan",
                })
        return infra

    def find_takeover_hints(self, subdomains):
        """Faqat passive nom patternlariga qarab ownership tekshiruviga arziydigan hostlarni ko'rsatish."""
        service_markers = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "azurewebsites.net": "Azure App Service",
            "cloudapp.net": "Azure CloudApp",
            "amazonaws.com": "AWS",
            "s3.amazonaws.com": "AWS S3",
            "pages.dev": "Cloudflare Pages",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
            "readme.io": "ReadMe",
            "zendesk.com": "Zendesk",
            "desk.com": "Desk",
            "helpscoutdocs.com": "HelpScout",
            "statuspage.io": "Atlassian Statuspage",
        }
        hints = []
        for host in subdomains[:500]:
            lowered = host.lower()
            for marker, service in service_markers.items():
                if marker in lowered:
                    hints.append({
                        "host": host,
                        "hint": f"{service} pattern topildi",
                        "source": "subdomain name",
                    })
        return hints

    def detect_waf_firewall(self, dns_data):
        """DNS va yengil HTTP header fingerprintlari asosida WAF/CDN aniqlash."""
        evidence = []
        notes = []
        headers = {}
        http_status = None
        checked_url = None

        dns_text = " ".join(
            str(record.get("value", ""))
            for records in dns_data.values()
            for record in records
        ).lower()

        for provider, markers in self.waf_dns_markers().items():
            for marker in markers:
                if marker in dns_text:
                    evidence.append({
                        "provider": provider,
                        "type": "DNS",
                        "value": marker,
                        "evidence": "DNS record marker",
                    })

        for record in dns_data.get("A", []):
            ip = str(record.get("value", ""))
            if is_cloudflare_ip(ip):
                evidence.append({
                    "provider": "Cloudflare",
                    "type": "IP",
                    "value": ip,
                    "evidence": "Cloudflare IPv4 range",
                })

        for scheme in ("https", "http"):
            url = f"{scheme}://{self.domain}/"
            try:
                http_status, headers, checked_url = self.fetch_http_fingerprint(url)
                break
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                notes.append(f"{url} header tekshiruv xatosi: {e}")

        header_blob = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
        for provider, markers in self.waf_header_markers().items():
            for marker in markers:
                if marker.lower() in header_blob:
                    evidence.append({
                        "provider": provider,
                        "type": "HTTP",
                        "value": marker,
                        "evidence": "Header/cookie/server fingerprint",
                    })

        provider_scores = {}
        for item in evidence:
            provider = item.get("provider", "Unknown")
            weight = 35 if item.get("type") == "HTTP" else 25
            provider_scores[provider] = provider_scores.get(provider, 0) + weight

        provider = None
        confidence = 0
        if provider_scores:
            provider, score = sorted(provider_scores.items(), key=lambda row: row[1], reverse=True)[0]
            confidence = min(95, score)

        if not evidence:
            notes.append("Tanilgan WAF/CDN fingerprint topilmadi; bu WAF yo'q degani emas.")

        return {
            "detected": bool(evidence),
            "provider": provider,
            "confidence": confidence,
            "http_status": http_status,
            "url": checked_url,
            "headers": headers,
            "evidence": evidence,
            "notes": notes,
        }

    def fetch_http_fingerprint(self, url):
        """Bitta yengil HTTP so'rov bilan header fingerprint olish."""
        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "Mozilla/5.0 PentestReconTool/3.1",
                "Accept": "*/*",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, dict(response.headers.items()), response.geturl()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()), url
        except urllib.error.URLError:
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0 PentestReconTool/3.1",
                    "Accept": "*/*",
                    "Range": "bytes=0-0",
                },
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, dict(response.headers.items()), response.geturl()

    def waf_dns_markers(self):
        """DNS/CDN markerlari."""
        return {
            "Cloudflare": ("cloudflare", "cdn.cloudflare.net"),
            "Akamai": ("akamai", "akadns", "edgesuite", "edgekey"),
            "AWS CloudFront / AWS WAF": ("cloudfront.net", "amazonaws.com", "awsglobalaccelerator"),
            "Fastly": ("fastly", "fastly.net"),
            "Imperva / Incapsula": ("incapsula", "impervadns", "imperva"),
            "Sucuri": ("sucuri", "sucuri.net"),
            "StackPath": ("stackpath", "hwcdn.net"),
            "Azure Front Door / App Gateway": ("azurefd.net", "trafficmanager.net", "azureedge.net"),
            "Google Cloud Armor": ("googlehosted", "googleusercontent", "ghs.googlehosted.com"),
            "DDoS-Guard": ("ddos-guard",),
            "BunnyCDN": ("bunnycdn", "b-cdn.net"),
        }

    def waf_header_markers(self):
        """HTTP header/cookie/server markerlari."""
        return {
            "Cloudflare": ("server: cloudflare", "cf-ray", "cf-cache-status", "__cf_bm", "cf-chl"),
            "Akamai": ("akamai", "x-akamai", "ak_bmsc", "bm_sz", "_abck"),
            "AWS CloudFront / AWS WAF": ("x-amz-cf-id", "x-amz-cf-pop", "x-amzn-waf", "cloudfront"),
            "Fastly": ("fastly", "x-served-by", "x-cache-hits", "x-timer"),
            "Imperva / Incapsula": ("x-iinfo", "incap_ses", "visid_incap", "imperva"),
            "Sucuri": ("x-sucuri-id", "x-sucuri-cache", "sucuri"),
            "F5 BIG-IP ASM": ("bigipserver", "f5", "x-waf-event-info"),
            "Barracuda": ("barra", "barracuda"),
            "StackPath": ("stackpath", "x-sp-url", "x-sp-cache"),
            "Azure Front Door / App Gateway": ("x-azure-ref", "azure", "arrAffinity"),
            "Google Cloud Armor": ("x-cloud-trace-context", "server: google frontend"),
            "DDoS-Guard": ("ddos-guard", "__ddg"),
            "BunnyCDN": ("bunnycdn", "server: bunnycdn"),
        }

    def detect_technologies(self):
        """BuiltWith/Wappalyzer uslubida web texnologiyalarni aniqlash."""
        url = f"https://{self.domain}"
        technologies = []
        sources = []
        headers = {}

        for candidate_url in (f"https://{self.domain}", f"http://{self.domain}"):
            try:
                status, headers, final_url = self.fetch_http_fingerprint(candidate_url)
                url = final_url or candidate_url
                sources.append({"name": "HTTP headers", "status": "ok", "status_code": status})
                break
            except Exception as e:
                sources.append({"name": candidate_url, "status": f"unavailable: {e}"})

        if builtwith is not None:
            try:
                parsed = builtwith.parse(url)
                for category, names in parsed.items():
                    for name in names:
                        technologies.append({
                            "name": name,
                            "category": category,
                            "source": "builtwith",
                        })
                sources.append({"name": "builtwith", "status": "ok", "count": len(technologies)})
            except Exception as e:
                sources.append({"name": "builtwith", "status": f"unavailable: {e}", "count": 0})
        else:
            sources.append({"name": "builtwith", "status": "library missing", "count": 0})

        header_techs = self.detect_technologies_from_headers(headers)
        technologies.extend(header_techs)

        unique = {}
        for tech in technologies:
            key = (tech.get("name", "").lower(), tech.get("category", ""))
            unique[key] = tech

        return {
            "url": url,
            "sources": sources,
            "headers": headers,
            "technologies": sorted(unique.values(), key=lambda item: (item.get("category", ""), item.get("name", ""))),
        }

    def detect_technologies_from_headers(self, headers):
        """Headerlardan oddiy texnologiya fingerprintlari."""
        blob = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
        markers = {
            "nginx": ("nginx", "Web Server"),
            "Apache": ("apache", "Web Server"),
            "Microsoft IIS": ("iis", "Web Server"),
            "OpenResty": ("openresty", "Web Server"),
            "PHP": ("x-powered-by: php", "Programming Language"),
            "ASP.NET": ("asp.net", "Framework"),
            "Express": ("express", "Framework"),
            "Next.js": ("next.js", "Framework"),
            "Vercel": ("vercel", "Hosting"),
            "Cloudflare": ("cloudflare", "CDN/WAF"),
            "WordPress": ("wordpress", "CMS"),
            "Shopify": ("shopify", "Ecommerce"),
        }
        found = []
        for name, (marker, category) in markers.items():
            if marker in blob:
                found.append({"name": name, "category": category, "source": "headers"})
        return found

    def find_cves(self, tech_data):
        """nvdlib orqali aniqlangan texnologiya nomlari bo'yicha CVE raqamlarini topish."""
        technologies = tech_data.get("technologies", []) if isinstance(tech_data, dict) else []
        result = {
            "status": "ok" if nvdlib is not None else "library missing",
            "items": [],
            "message": "",
        }
        if nvdlib is None:
            result["message"] = "nvdlib o'rnatilmagan"
            return result

        searched = set()
        for tech in technologies[:8]:
            keyword = str(tech.get("name", "")).strip()
            if len(keyword) < 3 or keyword.lower() in searched:
                continue
            searched.add(keyword.lower())
            try:
                cves = nvdlib.searchCVE(keywordSearch=keyword, limit=5)
            except Exception as e:
                result["items"].append({
                    "technology": keyword,
                    "status": f"unavailable: {e}",
                    "cves": [],
                })
                continue

            cve_items = []
            for cve in cves:
                score = None
                try:
                    score = cve.v31score
                except AttributeError:
                    try:
                        score = cve.v30score
                    except AttributeError:
                        score = None
                cve_items.append({
                    "id": getattr(cve, "id", ""),
                    "score": score,
                    "published": str(getattr(cve, "published", "")),
                    "summary": str(getattr(cve, "descriptions", "") or getattr(cve, "description", ""))[:240],
                })
            result["items"].append({
                "technology": keyword,
                "status": "ok",
                "cves": cve_items,
            })

        result["message"] = f"{sum(len(item.get('cves', [])) for item in result['items'])} CVE found"
        return result

    def analyze_tls_certificate(self):
        """pyOpenSSL/cryptography orqali sertifikat va cipher ma'lumotlarini olish."""
        result = {
            "status": "not_run",
            "host": self.domain,
            "port": 443,
            "certificate": {},
            "cipher": {},
            "issues": [],
            "message": "",
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    result["cipher"] = {
                        "name": ssock.cipher()[0] if ssock.cipher() else "",
                        "protocol": ssock.version(),
                        "bits": ssock.cipher()[2] if ssock.cipher() else "",
                    }
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            result["certificate"] = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "",
            }
            if crypto is not None:
                openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
                result["certificate"]["openssl_version"] = openssl_cert.get_version()
                result["certificate"]["openssl_not_after"] = openssl_cert.get_notAfter().decode("ascii", errors="ignore")
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                result["certificate"]["san"] = san.value.get_values_for_type(x509.DNSName)[:50]
            except x509.ExtensionNotFound:
                result["issues"].append("SAN extension topilmadi")

            if result["cipher"].get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
                result["issues"].append("Eski TLS/SSL protokoli ishlatilmoqda")

            result["status"] = "ok"
            result["message"] = "TLS certificate analyzed"
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)
        return result

    def scan_open_ports(self):
        """python-nmap orqali top 100 TCP portdan ochiqlarini aniqlash."""
        result = {
            "status": "not_run",
            "target": self.domain,
            "arguments": "-Pn -T3 --top-ports 100 --open",
            "open_ports": [],
            "message": "",
        }

        if nmap is None:
            result["status"] = "error"
            result["message"] = "python-nmap moduli o'rnatilmagan"
            return result

        try:
            scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            result["status"] = "error"
            result["message"] = f"nmap topilmadi yoki ishga tushmadi: {e}"
            return result
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)
            return result

        try:
            scanner.scan(hosts=self.domain, arguments=result["arguments"], timeout=60)
        except TypeError:
            try:
                scanner.scan(hosts=self.domain, arguments=result["arguments"])
            except Exception as e:
                result["status"] = "error"
                result["message"] = str(e)
                return result
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)
            return result

        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                ports = scanner[host][protocol].keys()
                for port in sorted(ports):
                    port_data = scanner[host][protocol][port]
                    if port_data.get("state") != "open":
                        continue
                    result["open_ports"].append({
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "state": port_data.get("state", ""),
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                    })

        result["status"] = "ok"
        result["message"] = f"{len(result['open_ports'])} open port found"
        return result
     
    def analyze_attack_vectors(self, whois_data, dns_data):
        """Hujum vektorlarini tahlil qilish"""
        vectors = []
        
        try:
            # 1. DNSSEC tekshirish
            dnssec_enabled = False
            try:
                ds_answers = dns.resolver.resolve(self.domain, 'DS')
                dnssec_enabled = bool(ds_answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                dnssec_enabled = str(whois_data.get('dnssec', '')).lower() not in ('', 'unsigned', 'no')

            if not dnssec_enabled:
                vectors.append("🟡 MEDIUM: DNSSEC yoqilmagan yoki tasdiqlanmadi")
            
            # 2. Transfer status
            status = whois_data.get('status', [])
            status_text = ''
            if isinstance(status, list):
                status_text = ' '.join([str(s).lower() for s in status if s])
            else:
                status_text = str(status).lower()
            
            if 'clienttransferprohibited' not in status_text:
                vectors.append("🟠 HIGH: Domain transfer himoyasi yo'q - domain hijacking mumkin")
            
            # 3. Cloudflare tekshirish
            ns_list = whois_data.get('name_servers', [])
            if isinstance(ns_list, str):
                ns_list = [ns_list]
            
            for ns in ns_list:
                if ns and 'cloudflare' in str(ns).lower():
                    vectors.append("🟡 MEDIUM: Cloudflare DNS aniqlangan - Origin IP topish imkoniyati")
                    break
            
            # 4. Registrar tekshirish
            registrar = whois_data.get('registrar', '')
            if registrar and ('openprovider' in str(registrar).lower() or 'registrar.eu' in str(registrar).lower()):
                vectors.append("🟡 MEDIUM: OpenProvider registrar - support phishing imkoniyati")
            
            # 5. Abuse contact mavjudligi
            if whois_data.get('abuse_email') or whois_data.get('abuse_phone'):
                vectors.append("🟢 INFO: Abuse contact mavjud - Social engineering imkoniyati")
            
            # 6. SPF tekshirish
            txt_records = dns_data.get('TXT', [])
            has_spf = False
            for txt in txt_records:
                txt_str = str(txt.get('value', '')).lower()
                if 'v=spf1' in txt_str:
                    has_spf = True
                    if '~all' in txt_str:
                        vectors.append("🟠 HIGH: SPF SoftFail (~all) - email spoofing imkoniyati")
                    elif '?all' in txt_str:
                        vectors.append("🟠 HIGH: SPF Neutral (?all) - email spoofing imkoniyati")
                    elif '-all' not in txt_str:
                        vectors.append("🟡 MEDIUM: SPF HardFail yo'q")
            
            if not has_spf:
                vectors.append("🔴 CRITICAL: SPF record yo'q - email spoofing mumkin")
            
            # 7. Origin IP ochiqligi
            a_records = dns_data.get('A', [])
            for a in a_records:
                ip = str(a.get('value', ''))
                if ip and not is_cloudflare_ip(ip):
                    vectors.append(f"🟡 MEDIUM: Origin IP ochiq - {ip}")
            
            # 8. DMARC tekshirish
            try:
                dmarc_domain = f"_dmarc.{self.domain}"
                dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                has_dmarc = False
                for answer in dmarc_answers:
                    if 'v=DMARC1' in str(answer):
                        has_dmarc = True
                        if 'p=reject' not in str(answer).lower():
                            vectors.append("🟡 MEDIUM: DMARC zaif sozlangan")
                if not has_dmarc:
                    vectors.append("🟡 MEDIUM: DMARC record yo'q")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                vectors.append("🟡 MEDIUM: DMARC record yo'q")
                
        except Exception as e:
            vectors.append(f"⚠️ Tahlil xatosi: {str(e)}")
        
        return vectors

