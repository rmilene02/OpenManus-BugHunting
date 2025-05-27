"""
Subdomain Enumeration Module

Provides comprehensive subdomain discovery capabilities using multiple techniques:
- DNS brute force
- Certificate transparency logs
- Search engine queries
- Third-party APIs
"""

import asyncio
import dns.resolver
import requests
import socket
import ssl
import json
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse
import concurrent.futures
from app.logger import logger


class SubdomainEnumerator:
    """Advanced subdomain enumeration with multiple discovery methods"""
    
    def __init__(self, target_domain: str, max_workers: int = 50):
        self.target_domain = target_domain.lower().strip()
        self.max_workers = max_workers
        self.discovered_subdomains: Set[str] = set()
        self.wordlist = self._load_default_wordlist()
        
    def _load_default_wordlist(self) -> List[str]:
        """Load default subdomain wordlist"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'test', 'staging',
            'dev', 'api', 'admin', 'blog', 'shop', 'forum', 'support', 'help', 'docs',
            'portal', 'app', 'mobile', 'm', 'secure', 'vpn', 'remote', 'demo', 'beta',
            'alpha', 'cdn', 'static', 'assets', 'img', 'images', 'css', 'js', 'media',
            'files', 'download', 'downloads', 'upload', 'uploads', 'backup', 'backups',
            'old', 'new', 'temp', 'tmp', 'archive', 'archives', 'git', 'svn', 'cvs',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'search',
            'log', 'logs', 'monitor', 'monitoring', 'stats', 'status', 'health', 'ping',
            'test1', 'test2', 'test3', 'dev1', 'dev2', 'staging1', 'staging2', 'prod',
            'production', 'live', 'www1', 'www2', 'web', 'web1', 'web2', 'server',
            'server1', 'server2', 'host', 'host1', 'host2', 'mx', 'mx1', 'mx2', 'email'
        ]
        return common_subdomains
    
    async def enumerate_all(self) -> Dict[str, List[str]]:
        """Run all enumeration methods and return comprehensive results"""
        logger.info(f"Starting comprehensive subdomain enumeration for {self.target_domain}")
        
        results = {
            'dns_bruteforce': [],
            'certificate_transparency': [],
            'search_engines': [],
            'zone_transfer': [],
            'all_discovered': []
        }
        
        # Run all enumeration methods
        tasks = [
            self._dns_bruteforce(),
            self._certificate_transparency(),
            self._search_engine_discovery(),
            self._zone_transfer_attempt()
        ]
        
        method_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        if not isinstance(method_results[0], Exception):
            results['dns_bruteforce'] = method_results[0]
        if not isinstance(method_results[1], Exception):
            results['certificate_transparency'] = method_results[1]
        if not isinstance(method_results[2], Exception):
            results['search_engines'] = method_results[2]
        if not isinstance(method_results[3], Exception):
            results['zone_transfer'] = method_results[3]
        
        # Combine all results
        all_subdomains = set()
        for method_subs in results.values():
            if isinstance(method_subs, list):
                all_subdomains.update(method_subs)
        
        results['all_discovered'] = sorted(list(all_subdomains))
        self.discovered_subdomains = all_subdomains
        
        logger.info(f"Discovered {len(all_subdomains)} unique subdomains for {self.target_domain}")
        return results
    
    async def _dns_bruteforce(self) -> List[str]:
        """Perform DNS brute force enumeration"""
        logger.info("Starting DNS brute force enumeration")
        discovered = []
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in self.wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered.append(result)
        
        logger.info(f"DNS brute force found {len(discovered)} subdomains")
        return discovered
    
    async def _certificate_transparency(self) -> List[str]:
        """Query certificate transparency logs"""
        logger.info("Querying certificate transparency logs")
        discovered = []
        
        try:
            # Query crt.sh
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip()
                        if domain.endswith(f".{self.target_domain}") and domain not in discovered:
                            discovered.append(domain)
        
        except Exception as e:
            logger.warning(f"Certificate transparency query failed: {e}")
        
        logger.info(f"Certificate transparency found {len(discovered)} subdomains")
        return discovered
    
    async def _search_engine_discovery(self) -> List[str]:
        """Use search engines to discover subdomains"""
        logger.info("Searching for subdomains via search engines")
        discovered = []
        
        try:
            # Google search
            query = f"site:*.{self.target_domain}"
            # Note: In a real implementation, you'd use proper search APIs
            # This is a simplified version for demonstration
            logger.info(f"Would search Google for: {query}")
            
            # Bing search
            query = f"site:*.{self.target_domain}"
            logger.info(f"Would search Bing for: {query}")
            
        except Exception as e:
            logger.warning(f"Search engine discovery failed: {e}")
        
        return discovered
    
    async def _zone_transfer_attempt(self) -> List[str]:
        """Attempt DNS zone transfer"""
        logger.info("Attempting DNS zone transfer")
        discovered = []
        
        try:
            # Get name servers
            ns_records = dns.resolver.resolve(self.target_domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target_domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.target_domain}"
                        if subdomain not in discovered:
                            discovered.append(subdomain)
                    logger.warning(f"Zone transfer successful from {ns} - This is a security issue!")
                except Exception:
                    # Zone transfer failed (expected)
                    pass
                    
        except Exception as e:
            logger.debug(f"Zone transfer attempt failed: {e}")
        
        return discovered
    
    def get_subdomain_info(self, subdomain: str) -> Dict:
        """Get detailed information about a subdomain"""
        info = {
            'subdomain': subdomain,
            'ip_addresses': [],
            'cname': None,
            'mx_records': [],
            'txt_records': [],
            'status_code': None,
            'title': None,
            'server': None
        }
        
        try:
            # DNS resolution
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                info['ip_addresses'] = [str(answer) for answer in answers]
            except:
                pass
            
            try:
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                info['cname'] = str(answers[0])
            except:
                pass
            
            try:
                answers = dns.resolver.resolve(subdomain, 'MX')
                info['mx_records'] = [str(answer) for answer in answers]
            except:
                pass
            
            try:
                answers = dns.resolver.resolve(subdomain, 'TXT')
                info['txt_records'] = [str(answer) for answer in answers]
            except:
                pass
            
            # HTTP probe
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                    info['status_code'] = response.status_code
                    info['server'] = response.headers.get('Server')
                    
                    # Extract title
                    if 'text/html' in response.headers.get('content-type', ''):
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            info['title'] = title_tag.get_text().strip()
                    break
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error getting info for {subdomain}: {e}")
        
        return info