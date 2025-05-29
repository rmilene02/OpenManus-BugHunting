"""
Active Reconnaissance Module - Enhanced Deep Asset Discovery

This module implements advanced active reconnaissance techniques that go beyond
simple subdomain enumeration. It validates assets, performs detailed fingerprinting,
and creates a comprehensive understanding of the target infrastructure.

Features:
- Active asset validation and live host detection
- Comprehensive port scanning with service detection
- Detailed technology fingerprinting
- API discovery and analysis
- Feedback loop integration with AI for dynamic planning
"""

import asyncio
import json
import subprocess
import socket
import requests
import re
import dns.resolver
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.logger import logger
from app.reconnaissance.kali_tools import KaliToolsManager


class ActiveReconEngine:
    """Enhanced active reconnaissance engine with deep asset analysis"""
    
    def __init__(self, target: str, output_dir: str = None, llm_client=None):
        self.target = target
        self.output_dir = output_dir or f"/tmp/active_recon_{target.replace('.', '_')}"
        self.llm_client = llm_client
        self.kali_tools = KaliToolsManager()
        
        # Asset tracking
        self.discovered_assets = {
            'subdomains': set(),
            'live_hosts': set(),
            'open_ports': {},
            'technologies': {},
            'apis': set(),
            'endpoints': set(),
            'certificates': {},
            'dns_records': {}
        }
        
        # Configuration
        self.max_threads = 50
        self.timeout = 10
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        self.web_ports = [80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000]
        
        logger.info(f"Active Reconnaissance Engine initialized for {target}")

    async def comprehensive_active_recon(self, 
                                       passive_subdomains: List[str] = None,
                                       deep_scan: bool = False,
                                       stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive active reconnaissance
        
        Args:
            passive_subdomains: List of subdomains from passive reconnaissance
            deep_scan: Enable deep scanning (more ports, detailed fingerprinting)
            stealth_mode: Use stealth techniques to avoid detection
        """
        logger.info("Starting comprehensive active reconnaissance")
        
        results = {
            'target': self.target,
            'asset_validation': {},
            'live_host_analysis': {},
            'port_scanning': {},
            'technology_fingerprinting': {},
            'api_discovery': {},
            'certificate_analysis': {},
            'dns_analysis': {},
            'ai_feedback': {},
            'summary': {}
        }
        
        # Phase 1: Asset Validation and Live Host Detection
        logger.info("Phase 1: Asset validation and live host detection")
        if passive_subdomains:
            self.discovered_assets['subdomains'].update(passive_subdomains)
        
        # Add main target
        self.discovered_assets['subdomains'].add(self.target)
        
        # Validate and identify live hosts
        results['asset_validation'] = await self._validate_assets(stealth_mode)
        results['live_host_analysis'] = await self._analyze_live_hosts()
        
        # Phase 2: Port Scanning and Service Detection
        logger.info("Phase 2: Port scanning and service detection")
        results['port_scanning'] = await self._comprehensive_port_scan(deep_scan, stealth_mode)
        
        # Phase 3: Technology Fingerprinting
        logger.info("Phase 3: Technology fingerprinting")
        results['technology_fingerprinting'] = await self._detailed_tech_fingerprinting()
        
        # Phase 4: API Discovery
        logger.info("Phase 4: API discovery and analysis")
        results['api_discovery'] = await self._discover_apis()
        
        # Phase 5: Certificate and DNS Analysis
        logger.info("Phase 5: Certificate and DNS analysis")
        results['certificate_analysis'] = await self._analyze_certificates()
        results['dns_analysis'] = await self._comprehensive_dns_analysis()
        
        # Phase 6: AI Feedback Loop
        if self.llm_client:
            logger.info("Phase 6: AI feedback and dynamic planning")
            results['ai_feedback'] = await self._ai_feedback_loop(results)
        
        # Generate summary
        results['summary'] = self._generate_recon_summary(results)
        
        logger.info(f"Active reconnaissance completed. Found {len(self.discovered_assets['live_hosts'])} live hosts")
        return results

    async def _validate_assets(self, stealth_mode: bool = False) -> Dict[str, Any]:
        """Validate discovered assets and identify live hosts"""
        logger.info(f"Validating {len(self.discovered_assets['subdomains'])} discovered assets")
        
        validation_results = {
            'total_subdomains': len(self.discovered_assets['subdomains']),
            'live_hosts': [],
            'dead_hosts': [],
            'resolution_errors': [],
            'validation_methods': []
        }
        
        # Use multiple validation methods
        validation_methods = [
            self._dns_resolution_check,
            self._http_connectivity_check,
            self._ping_check if not stealth_mode else None
        ]
        
        validation_methods = [method for method in validation_methods if method is not None]
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            tasks = []
            for subdomain in self.discovered_assets['subdomains']:
                for method in validation_methods:
                    tasks.append(executor.submit(method, subdomain))
            
            for future in as_completed(tasks):
                try:
                    result = future.result()
                    if result and result.get('is_live'):
                        host = result['host']
                        if host not in [h['host'] for h in validation_results['live_hosts']]:
                            validation_results['live_hosts'].append(result)
                            self.discovered_assets['live_hosts'].add(host)
                except Exception as e:
                    logger.debug(f"Validation error: {e}")
        
        # Identify dead hosts
        live_host_names = {h['host'] for h in validation_results['live_hosts']}
        validation_results['dead_hosts'] = list(self.discovered_assets['subdomains'] - live_host_names)
        
        logger.info(f"Asset validation complete: {len(validation_results['live_hosts'])} live, {len(validation_results['dead_hosts'])} dead")
        return validation_results

    def _dns_resolution_check(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Check if hostname resolves via DNS"""
        try:
            result = socket.gethostbyname(hostname)
            return {
                'host': hostname,
                'ip': result,
                'is_live': True,
                'method': 'dns_resolution',
                'response_time': None
            }
        except socket.gaierror:
            return None

    def _http_connectivity_check(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Check HTTP/HTTPS connectivity"""
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{hostname}"
                response = requests.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
                return {
                    'host': hostname,
                    'url': url,
                    'is_live': True,
                    'method': 'http_connectivity',
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'headers': dict(response.headers)
                }
            except requests.RequestException:
                continue
        return None

    def _ping_check(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Check connectivity via ping (not stealth)"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', hostname],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return {
                    'host': hostname,
                    'is_live': True,
                    'method': 'ping',
                    'response_time': self._extract_ping_time(result.stdout)
                }
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None

    def _extract_ping_time(self, ping_output: str) -> Optional[float]:
        """Extract ping time from ping output"""
        match = re.search(r'time=(\d+\.?\d*)', ping_output)
        return float(match.group(1)) if match else None

    async def _analyze_live_hosts(self) -> Dict[str, Any]:
        """Perform detailed analysis of live hosts"""
        logger.info(f"Analyzing {len(self.discovered_assets['live_hosts'])} live hosts")
        
        analysis_results = {
            'host_details': {},
            'ip_ranges': set(),
            'hosting_providers': {},
            'cdn_detection': {},
            'load_balancer_detection': {}
        }
        
        for host in self.discovered_assets['live_hosts']:
            try:
                # Get IP information
                ip_info = await self._get_ip_information(host)
                analysis_results['host_details'][host] = ip_info
                
                if ip_info.get('ip'):
                    analysis_results['ip_ranges'].add(self._get_ip_range(ip_info['ip']))
                
                # Detect CDN and load balancers
                cdn_info = await self._detect_cdn(host)
                if cdn_info:
                    analysis_results['cdn_detection'][host] = cdn_info
                
            except Exception as e:
                logger.debug(f"Error analyzing host {host}: {e}")
        
        return analysis_results

    async def _get_ip_information(self, hostname: str) -> Dict[str, Any]:
        """Get detailed IP information for a hostname"""
        try:
            # DNS resolution
            ip = socket.gethostbyname(hostname)
            
            # Reverse DNS lookup
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                reverse_dns = None
            
            # ASN and geolocation (simplified - in production use proper APIs)
            asn_info = await self._get_asn_info(ip)
            
            return {
                'hostname': hostname,
                'ip': ip,
                'reverse_dns': reverse_dns,
                'asn_info': asn_info
            }
        except Exception as e:
            logger.debug(f"Error getting IP info for {hostname}: {e}")
            return {'hostname': hostname, 'error': str(e)}

    async def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for an IP (simplified implementation)"""
        # In production, use proper ASN lookup services
        return {
            'asn': 'Unknown',
            'organization': 'Unknown',
            'country': 'Unknown'
        }

    def _get_ip_range(self, ip: str) -> str:
        """Get IP range (simplified to /24)"""
        parts = ip.split('.')
        return f"{'.'.join(parts[:3])}.0/24"

    async def _detect_cdn(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Detect CDN usage"""
        try:
            # Check CNAME records for CDN indicators
            resolver = dns.resolver.Resolver()
            try:
                cname_records = resolver.resolve(hostname, 'CNAME')
                for record in cname_records:
                    cname = str(record.target).lower()
                    for cdn in ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'maxcdn']:
                        if cdn in cname:
                            return {'cdn_provider': cdn, 'cname': cname}
            except dns.resolver.NXDOMAIN:
                pass
            
            # Check HTTP headers for CDN indicators
            try:
                response = requests.head(f"https://{hostname}", timeout=self.timeout, verify=False)
                headers = response.headers
                
                cdn_headers = {
                    'cf-ray': 'Cloudflare',
                    'x-served-by': 'Fastly',
                    'x-cache': 'Various CDNs',
                    'x-amz-cf-id': 'CloudFront'
                }
                
                for header, provider in cdn_headers.items():
                    if header in headers:
                        return {'cdn_provider': provider, 'header': header, 'value': headers[header]}
            except requests.RequestException:
                pass
                
        except Exception as e:
            logger.debug(f"CDN detection error for {hostname}: {e}")
        
        return None

    async def _comprehensive_port_scan(self, deep_scan: bool = False, stealth_mode: bool = False) -> Dict[str, Any]:
        """Perform comprehensive port scanning on live hosts"""
        logger.info("Starting comprehensive port scanning")
        
        port_scan_results = {
            'scan_config': {
                'deep_scan': deep_scan,
                'stealth_mode': stealth_mode,
                'ports_scanned': self.common_ports if not deep_scan else list(range(1, 65536))
            },
            'host_results': {}
        }
        
        # Determine ports to scan
        ports_to_scan = self.common_ports
        if deep_scan:
            ports_to_scan = list(range(1, 1001))  # Top 1000 ports for deep scan
        
        # Scan each live host
        for host in self.discovered_assets['live_hosts']:
            try:
                host_results = await self._scan_host_ports(host, ports_to_scan, stealth_mode)
                port_scan_results['host_results'][host] = host_results
                
                # Store open ports for later use
                if host_results.get('open_ports'):
                    self.discovered_assets['open_ports'][host] = host_results['open_ports']
                    
            except Exception as e:
                logger.error(f"Port scan error for {host}: {e}")
                port_scan_results['host_results'][host] = {'error': str(e)}
        
        return port_scan_results

    async def _scan_host_ports(self, hostname: str, ports: List[int], stealth_mode: bool = False) -> Dict[str, Any]:
        """Scan ports on a specific host"""
        logger.debug(f"Scanning {len(ports)} ports on {hostname}")
        
        # Use nmap for comprehensive scanning
        nmap_args = [
            'nmap',
            '-sS' if not stealth_mode else '-sT',  # SYN scan vs TCP connect
            '-T4' if not stealth_mode else '-T2',   # Timing template
            '--open',  # Only show open ports
            '-sV',     # Service version detection
            '-O',      # OS detection
            '--script=default',  # Default scripts
            '-p', ','.join(map(str, ports)),
            hostname
        ]
        
        if stealth_mode:
            nmap_args.extend(['-f', '--scan-delay', '1s'])  # Fragment packets, add delay
        
        try:
            result = subprocess.run(
                nmap_args,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
            else:
                logger.warning(f"Nmap scan failed for {hostname}: {result.stderr}")
                return {'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Nmap scan timeout for {hostname}")
            return {'error': 'Scan timeout'}
        except Exception as e:
            logger.error(f"Nmap scan error for {hostname}: {e}")
            return {'error': str(e)}

    def _parse_nmap_output(self, nmap_output: str) -> Dict[str, Any]:
        """Parse nmap output to extract useful information"""
        results = {
            'open_ports': [],
            'os_detection': {},
            'services': {},
            'scripts': {}
        }
        
        lines = nmap_output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Parse open ports
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    
                    port_info = {
                        'port': int(port),
                        'service': service,
                        'version': version
                    }
                    results['open_ports'].append(port_info)
                    results['services'][port] = port_info
            
            # Parse OS detection
            elif 'OS details:' in line:
                results['os_detection']['details'] = line.replace('OS details:', '').strip()
            elif 'Running:' in line:
                results['os_detection']['running'] = line.replace('Running:', '').strip()
        
        return results

    async def _detailed_tech_fingerprinting(self) -> Dict[str, Any]:
        """Perform detailed technology fingerprinting on web services"""
        logger.info("Starting detailed technology fingerprinting")
        
        fingerprint_results = {
            'web_technologies': {},
            'frameworks': {},
            'cms_detection': {},
            'javascript_libraries': {},
            'api_technologies': {}
        }
        
        # Find web services
        web_services = []
        for host, ports in self.discovered_assets['open_ports'].items():
            for port_info in ports:
                if port_info['port'] in self.web_ports:
                    scheme = 'https' if port_info['port'] in [443, 8443] else 'http'
                    url = f"{scheme}://{host}:{port_info['port']}"
                    web_services.append(url)
        
        # Fingerprint each web service
        for url in web_services:
            try:
                tech_info = await self._fingerprint_web_service(url)
                fingerprint_results['web_technologies'][url] = tech_info
                
                # Store technologies for AI feedback
                parsed_url = urlparse(url)
                host = parsed_url.netloc.split(':')[0]
                if host not in self.discovered_assets['technologies']:
                    self.discovered_assets['technologies'][host] = []
                self.discovered_assets['technologies'][host].extend(tech_info.get('technologies', []))
                
            except Exception as e:
                logger.debug(f"Fingerprinting error for {url}: {e}")
                fingerprint_results['web_technologies'][url] = {'error': str(e)}
        
        return fingerprint_results

    async def _fingerprint_web_service(self, url: str) -> Dict[str, Any]:
        """Fingerprint a specific web service"""
        fingerprint_info = {
            'url': url,
            'technologies': [],
            'server_info': {},
            'cms': None,
            'frameworks': [],
            'javascript_libs': [],
            'security_headers': {}
        }
        
        try:
            # HTTP response analysis
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Analyze headers
            headers = response.headers
            fingerprint_info['server_info'] = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'technology': headers.get('X-Technology', 'Unknown')
            }
            
            # Security headers analysis
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy'
            ]
            
            for header in security_headers:
                if header in headers:
                    fingerprint_info['security_headers'][header] = headers[header]
            
            # Content analysis
            content = response.text
            
            # CMS detection
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
                'Drupal': ['sites/default', 'misc/drupal.js', '/node/'],
                'Joomla': ['media/jui', 'templates/system', '/component/'],
                'Magento': ['skin/frontend', 'js/mage', 'var/cache']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    fingerprint_info['cms'] = cms
                    fingerprint_info['technologies'].append(cms)
                    break
            
            # JavaScript library detection
            js_libraries = {
                'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)', r'jQuery v(\d+\.\d+\.\d+)'],
                'Angular': [r'angular[.-](\d+\.\d+\.\d+)', r'ng-version="(\d+\.\d+\.\d+)"'],
                'React': [r'react[.-](\d+\.\d+\.\d+)', r'React v(\d+\.\d+\.\d+)'],
                'Vue.js': [r'vue[.-](\d+\.\d+\.\d+)', r'Vue.js v(\d+\.\d+\.\d+)']
            }
            
            for lib, patterns in js_libraries.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else 'Unknown'
                        fingerprint_info['javascript_libs'].append({
                            'library': lib,
                            'version': version
                        })
                        fingerprint_info['technologies'].append(f"{lib} {version}")
                        break
            
            # Framework detection
            framework_signatures = {
                'Laravel': ['laravel_session', 'csrf-token', '/vendor/laravel'],
                'Django': ['csrfmiddlewaretoken', 'django', '__admin_media_prefix__'],
                'Rails': ['csrf-param', 'csrf-token', 'rails'],
                'Express.js': ['X-Powered-By: Express', 'express'],
                'Spring': ['jsessionid', 'spring', 'SPRING_SECURITY']
            }
            
            for framework, signatures in framework_signatures.items():
                if any(sig.lower() in content.lower() or sig.lower() in str(headers).lower() for sig in signatures):
                    fingerprint_info['frameworks'].append(framework)
                    fingerprint_info['technologies'].append(framework)
            
        except Exception as e:
            fingerprint_info['error'] = str(e)
        
        return fingerprint_info

    async def _discover_apis(self) -> Dict[str, Any]:
        """Discover and analyze APIs"""
        logger.info("Starting API discovery")
        
        api_results = {
            'discovered_apis': [],
            'api_endpoints': {},
            'graphql_endpoints': [],
            'rest_apis': [],
            'soap_services': []
        }
        
        # Common API paths to check
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/graphiql',
            '/swagger', '/swagger-ui', '/swagger.json',
            '/openapi.json', '/api-docs',
            '/wsdl', '/soap',
            '/.well-known/openapi_desc'
        ]
        
        # Check each web service for APIs
        for host, ports in self.discovered_assets['open_ports'].items():
            for port_info in ports:
                if port_info['port'] in self.web_ports:
                    scheme = 'https' if port_info['port'] in [443, 8443] else 'http'
                    base_url = f"{scheme}://{host}:{port_info['port']}"
                    
                    for api_path in api_paths:
                        try:
                            url = urljoin(base_url, api_path)
                            response = requests.get(url, timeout=self.timeout, verify=False)
                            
                            if response.status_code == 200:
                                api_info = {
                                    'url': url,
                                    'status_code': response.status_code,
                                    'content_type': response.headers.get('Content-Type', ''),
                                    'api_type': self._detect_api_type(url, response)
                                }
                                
                                api_results['discovered_apis'].append(api_info)
                                self.discovered_assets['apis'].add(url)
                                
                                # Categorize by API type
                                if 'graphql' in api_path.lower():
                                    api_results['graphql_endpoints'].append(api_info)
                                elif 'soap' in api_path.lower() or 'wsdl' in api_path.lower():
                                    api_results['soap_services'].append(api_info)
                                else:
                                    api_results['rest_apis'].append(api_info)
                                
                        except requests.RequestException:
                            continue
        
        return api_results

    def _detect_api_type(self, url: str, response: requests.Response) -> str:
        """Detect the type of API based on URL and response"""
        url_lower = url.lower()
        content_type = response.headers.get('Content-Type', '').lower()
        content = response.text.lower()
        
        if 'graphql' in url_lower or 'graphql' in content:
            return 'GraphQL'
        elif 'soap' in url_lower or 'wsdl' in url_lower or 'soap' in content_type:
            return 'SOAP'
        elif 'application/json' in content_type or 'json' in content:
            return 'REST'
        elif 'application/xml' in content_type or 'xml' in content:
            return 'XML-RPC'
        else:
            return 'Unknown'

    async def _analyze_certificates(self) -> Dict[str, Any]:
        """Analyze SSL/TLS certificates"""
        logger.info("Starting certificate analysis")
        
        cert_results = {
            'certificate_info': {},
            'san_domains': set(),
            'certificate_chains': {},
            'vulnerabilities': []
        }
        
        # Analyze certificates for HTTPS services
        for host, ports in self.discovered_assets['open_ports'].items():
            for port_info in ports:
                if port_info['port'] in [443, 8443]:
                    try:
                        cert_info = await self._get_certificate_info(host, port_info['port'])
                        cert_results['certificate_info'][f"{host}:{port_info['port']}"] = cert_info
                        
                        # Extract SAN domains
                        if cert_info.get('san_domains'):
                            cert_results['san_domains'].update(cert_info['san_domains'])
                            # Add SAN domains to discovered subdomains for further analysis
                            self.discovered_assets['subdomains'].update(cert_info['san_domains'])
                            
                    except Exception as e:
                        logger.debug(f"Certificate analysis error for {host}:{port_info['port']}: {e}")
        
        return cert_results

    async def _get_certificate_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Get detailed certificate information"""
        import ssl
        import socket
        from datetime import datetime
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san_domains': []
                    }
                    
                    # Extract SAN domains
                    if 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                cert_info['san_domains'].append(san_value)
                    
                    return cert_info
                    
        except Exception as e:
            return {'error': str(e)}

    async def _comprehensive_dns_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive DNS analysis"""
        logger.info("Starting comprehensive DNS analysis")
        
        dns_results = {
            'dns_records': {},
            'zone_transfer_attempts': {},
            'dns_security': {},
            'subdomain_takeover_checks': {}
        }
        
        # Analyze DNS records for each discovered domain
        domains_to_analyze = {self.target}
        domains_to_analyze.update(self.discovered_assets['subdomains'])
        
        for domain in domains_to_analyze:
            try:
                dns_info = await self._analyze_domain_dns(domain)
                dns_results['dns_records'][domain] = dns_info
                
                # Store DNS records
                self.discovered_assets['dns_records'][domain] = dns_info
                
            except Exception as e:
                logger.debug(f"DNS analysis error for {domain}: {e}")
                dns_results['dns_records'][domain] = {'error': str(e)}
        
        return dns_results

    async def _analyze_domain_dns(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for a specific domain"""
        dns_info = {
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'SOA': None
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    if record_type == 'SOA':
                        dns_info[record_type] = str(answer)
                    else:
                        dns_info[record_type].append(str(answer))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.debug(f"DNS query error for {domain} {record_type}: {e}")
        
        return dns_info

    async def _ai_feedback_loop(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze reconnaissance results and suggest next steps"""
        if not self.llm_client:
            return {'error': 'No LLM client available'}
        
        logger.info("Analyzing reconnaissance results with AI")
        
        # Prepare context for AI analysis
        context = {
            'target': self.target,
            'live_hosts_count': len(self.discovered_assets['live_hosts']),
            'open_ports_summary': self._summarize_open_ports(),
            'technologies_found': self._summarize_technologies(),
            'apis_discovered': len(self.discovered_assets['apis']),
            'certificates_analyzed': len(recon_results.get('certificate_analysis', {}).get('certificate_info', {}))
        }
        
        # AI prompt for analysis
        prompt = f"""
        Analyze the following reconnaissance results and provide strategic recommendations for the next phase of security testing:

        Target: {context['target']}
        Live Hosts Found: {context['live_hosts_count']}
        Open Ports Summary: {context['open_ports_summary']}
        Technologies Identified: {context['technologies_found']}
        APIs Discovered: {context['apis_discovered']}
        
        Based on these findings, recommend:
        1. Priority targets for deeper analysis
        2. Specific vulnerability tests to perform
        3. Attack vectors to explore
        4. Tools and techniques to use next
        5. Potential security weaknesses to investigate
        
        Focus on actionable recommendations that could lead to finding exploitable vulnerabilities.
        """
        
        try:
            ai_response = await self.llm_client.agenerate(prompt)
            
            return {
                'ai_analysis': ai_response,
                'context_provided': context,
                'recommendations_generated': True
            }
        except Exception as e:
            logger.error(f"AI feedback error: {e}")
            return {'error': str(e)}

    def _summarize_open_ports(self) -> Dict[str, Any]:
        """Summarize open ports across all hosts"""
        port_summary = {}
        for host, ports in self.discovered_assets['open_ports'].items():
            for port_info in ports:
                port = port_info['port']
                service = port_info.get('service', 'unknown')
                
                if port not in port_summary:
                    port_summary[port] = {
                        'service': service,
                        'hosts': [],
                        'count': 0
                    }
                
                port_summary[port]['hosts'].append(host)
                port_summary[port]['count'] += 1
        
        return port_summary

    def _summarize_technologies(self) -> Dict[str, List[str]]:
        """Summarize technologies found across all hosts"""
        tech_summary = {}
        for host, technologies in self.discovered_assets['technologies'].items():
            for tech in technologies:
                if tech not in tech_summary:
                    tech_summary[tech] = []
                tech_summary[tech].append(host)
        
        return tech_summary

    def _generate_recon_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive summary of reconnaissance results"""
        summary = {
            'total_subdomains_discovered': len(self.discovered_assets['subdomains']),
            'live_hosts_identified': len(self.discovered_assets['live_hosts']),
            'total_open_ports': sum(len(ports) for ports in self.discovered_assets['open_ports'].values()),
            'unique_services': len(set(
                port_info.get('service', 'unknown') 
                for ports in self.discovered_assets['open_ports'].values() 
                for port_info in ports
            )),
            'technologies_identified': len(set(
                tech for technologies in self.discovered_assets['technologies'].values() 
                for tech in technologies
            )),
            'apis_discovered': len(self.discovered_assets['apis']),
            'certificates_analyzed': len(results.get('certificate_analysis', {}).get('certificate_info', {})),
            'high_value_targets': self._identify_high_value_targets(),
            'recommended_next_steps': self._generate_next_steps()
        }
        
        return summary

    def _identify_high_value_targets(self) -> List[Dict[str, Any]]:
        """Identify high-value targets for further analysis"""
        high_value_targets = []
        
        # Hosts with many open ports
        for host, ports in self.discovered_assets['open_ports'].items():
            if len(ports) >= 5:
                high_value_targets.append({
                    'host': host,
                    'reason': 'Multiple open ports',
                    'port_count': len(ports),
                    'priority': 'high'
                })
        
        # Hosts with interesting technologies
        interesting_tech = ['admin', 'api', 'graphql', 'jenkins', 'gitlab', 'jira']
        for host, technologies in self.discovered_assets['technologies'].items():
            for tech in technologies:
                if any(interesting in tech.lower() for interesting in interesting_tech):
                    high_value_targets.append({
                        'host': host,
                        'reason': f'Interesting technology: {tech}',
                        'technology': tech,
                        'priority': 'medium'
                    })
        
        # Hosts with APIs
        for api_url in self.discovered_assets['apis']:
            parsed = urlparse(api_url)
            host = parsed.netloc.split(':')[0]
            high_value_targets.append({
                'host': host,
                'reason': 'API endpoint discovered',
                'api_url': api_url,
                'priority': 'high'
            })
        
        return high_value_targets

    def _generate_next_steps(self) -> List[str]:
        """Generate recommended next steps based on findings"""
        next_steps = []
        
        if self.discovered_assets['apis']:
            next_steps.append("Perform API security testing on discovered endpoints")
        
        if any('admin' in tech.lower() for technologies in self.discovered_assets['technologies'].values() for tech in technologies):
            next_steps.append("Test admin interfaces for default credentials and vulnerabilities")
        
        if self.discovered_assets['open_ports']:
            next_steps.append("Perform service-specific vulnerability scans")
        
        web_services = sum(1 for ports in self.discovered_assets['open_ports'].values() 
                          for port_info in ports if port_info['port'] in self.web_ports)
        if web_services > 0:
            next_steps.append("Conduct web application security testing")
        
        next_steps.append("Perform targeted fuzzing based on discovered technologies")
        next_steps.append("Test for business logic vulnerabilities")
        
        return next_steps