"""
Web Vulnerability Scanner

Comprehensive web application security testing using Kali Linux tools:
- nikto, sqlmap, wfuzz, gobuster, whatweb, wafw00f, nuclei
- Custom vulnerability detection patterns
- OWASP Top 10 testing coverage
"""

import asyncio
import json
import re
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
from app.reconnaissance.kali_tools import KaliToolsManager
from app.logger import logger


class WebScanner:
    """Advanced web application vulnerability scanner using Kali tools"""
    
    def __init__(self, target_url: str, output_dir: str = "./results"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.vulnerabilities = []
        self.scan_results = {}
    
    async def scan_web_application(self, deep_scan: bool = False) -> Dict:
        """Scan web application for vulnerabilities"""
        logger.info(f"Starting web application scan for {self.target_url}")
        
        try:
            # Mock web scanning results
            results = {
                'target': self.target_url,
                'vulnerabilities': [
                    {
                        'type': 'XSS',
                        'severity': 'Medium',
                        'description': 'Potential XSS vulnerability found',
                        'location': '/search?q=test'
                    }
                ],
                'technologies': ['Apache', 'PHP'],
                'status': 'completed'
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Web scan failed: {e}")
            return {'error': str(e)}


class WebVulnerabilityScanner:
    """Advanced web application vulnerability scanner using Kali tools"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.kali_tools = KaliToolsManager()
        self.vulnerabilities = []
        self.scan_results = {}
        
    async def comprehensive_scan(self, test_xss: bool = True, test_sqli: bool = True, 
                               test_lfi: bool = True, test_command_injection: bool = True, 
                               stealth_mode: bool = False) -> Dict[str, Any]:
        """Run comprehensive web vulnerability assessment"""
        logger.info(f"Starting comprehensive web vulnerability scan for {self.target_url}")
        
        scan_results = {
            'target': self.target_url,
            'technology_detection': {},
            'directory_enumeration': {},
            'vulnerability_scan': {},
            'sql_injection_test': {},
            'waf_detection': {},
            'nuclei_scan': {},
            'custom_checks': {},
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Run all scanning modules
        tasks = [
            self._technology_detection(),
            self._directory_enumeration(),
            self._nikto_vulnerability_scan(),
            self._sql_injection_testing(),
            self._waf_detection(),
            self._nuclei_comprehensive_scan(),
            self._custom_vulnerability_checks()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        scan_methods = [
            'technology_detection',
            'directory_enumeration', 
            'vulnerability_scan',
            'sql_injection_test',
            'waf_detection',
            'nuclei_scan',
            'custom_checks'
        ]
        
        for i, result in enumerate(results):
            if not isinstance(result, Exception):
                scan_results[scan_methods[i]] = result
            else:
                logger.error(f"Scan method {scan_methods[i]} failed: {result}")
                scan_results[scan_methods[i]] = {'error': str(result)}
        
        # Generate summary
        scan_results['summary'] = self._generate_summary(scan_results)
        
        self.scan_results = scan_results
        logger.info(f"Web vulnerability scan completed. Found {scan_results['summary']['total_vulnerabilities']} issues")
        
        return scan_results
    
    async def _technology_detection(self) -> Dict:
        """Detect web technologies using whatweb and custom methods"""
        logger.info("Detecting web technologies")
        
        results = {
            'whatweb': {},
            'custom_detection': {},
            'headers': {},
            'cookies': {}
        }
        
        # Use whatweb from Kali
        whatweb_result = self.kali_tools.whatweb_scan(self.target_url)
        results['whatweb'] = whatweb_result
        
        # Custom technology detection
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            # Analyze headers
            results['headers'] = dict(response.headers)
            
            # Analyze cookies
            results['cookies'] = {cookie.name: cookie.value for cookie in response.cookies}
            
            # Custom detection patterns
            tech_patterns = {
                'WordPress': [r'wp-content', r'wp-includes', r'/wp-admin/'],
                'Drupal': [r'sites/default', r'misc/drupal.js', r'Drupal.settings'],
                'Joomla': [r'/components/', r'/modules/', r'joomla'],
                'PHP': [r'\.php', r'PHPSESSID'],
                'ASP.NET': [r'\.aspx', r'ASP.NET_SessionId', r'__VIEWSTATE'],
                'Apache': [r'Apache/', r'Server: Apache'],
                'Nginx': [r'nginx/', r'Server: nginx'],
                'IIS': [r'IIS/', r'Server: Microsoft-IIS'],
                'jQuery': [r'jquery', r'jQuery'],
                'Bootstrap': [r'bootstrap', r'Bootstrap'],
                'React': [r'react', r'React'],
                'Angular': [r'angular', r'ng-'],
                'Vue.js': [r'vue\.js', r'Vue'],
            }
            
            detected_tech = []
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, headers_str, re.IGNORECASE):
                        detected_tech.append(tech)
                        break
            
            results['custom_detection']['technologies'] = list(set(detected_tech))
            results['custom_detection']['status_code'] = response.status_code
            results['custom_detection']['content_length'] = len(response.content)
            
        except Exception as e:
            logger.error(f"Custom technology detection failed: {e}")
            results['custom_detection']['error'] = str(e)
        
        return results
    
    async def _directory_enumeration(self) -> Dict:
        """Enumerate directories and files using gobuster and custom wordlists"""
        logger.info("Enumerating directories and files")
        
        results = {
            'gobuster': {},
            'common_files': {},
            'admin_panels': {}
        }
        
        # Use gobuster from Kali
        gobuster_result = self.kali_tools.gobuster_dir(self.target_url)
        results['gobuster'] = gobuster_result
        
        # Check for common sensitive files
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'config', 'database', 'db', 'sql', 'dump',
            '.git', '.svn', '.env', 'config.php', 'wp-config.php',
            'test', 'dev', 'staging', 'beta', 'demo'
        ]
        
        found_files = []
        for file_path in common_files:
            try:
                url = urljoin(self.target_url, file_path)
                response = requests.head(url, timeout=5, verify=False)
                if response.status_code == 200:
                    found_files.append({
                        'path': file_path,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': response.headers.get('content-length', 'unknown')
                    })
            except:
                continue
        
        results['common_files']['found'] = found_files
        
        # Check for admin panels
        admin_paths = [
            'admin', 'administrator', 'admin.php', 'admin.html',
            'wp-admin', 'wp-login.php', 'login', 'login.php',
            'phpmyadmin', 'pma', 'mysql', 'cpanel', 'webmail'
        ]
        
        admin_panels = []
        for admin_path in admin_paths:
            try:
                url = urljoin(self.target_url, admin_path)
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                     for keyword in ['login', 'password', 'username', 'admin']):
                    admin_panels.append({
                        'path': admin_path,
                        'url': url,
                        'title': self._extract_title(response.text)
                    })
            except:
                continue
        
        results['admin_panels']['found'] = admin_panels
        
        return results
    
    async def _nikto_vulnerability_scan(self) -> Dict:
        """Run nikto vulnerability scanner"""
        logger.info("Running nikto vulnerability scan")
        
        nikto_result = self.kali_tools.nikto_scan(self.target_url)
        
        # Parse and categorize nikto findings
        if nikto_result.get('success') and 'vulnerabilities' in nikto_result:
            categorized_vulns = {
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
            
            for vuln in nikto_result['vulnerabilities']:
                severity = self._categorize_nikto_finding(vuln)
                categorized_vulns[severity].append(vuln)
            
            nikto_result['categorized'] = categorized_vulns
        
        return nikto_result
    
    async def _sql_injection_testing(self) -> Dict:
        """Test for SQL injection vulnerabilities using sqlmap"""
        logger.info("Testing for SQL injection vulnerabilities")
        
        results = {
            'sqlmap': {},
            'manual_tests': {}
        }
        
        # Use sqlmap from Kali
        sqlmap_result = self.kali_tools.sqlmap_test(self.target_url)
        results['sqlmap'] = sqlmap_result
        
        # Manual SQL injection tests
        sql_payloads = [
            "'", '"', "' OR '1'='1", '" OR "1"="1', 
            "' OR 1=1--", '" OR 1=1--', "'; DROP TABLE users--",
            "1' UNION SELECT NULL--", "1 UNION SELECT NULL--"
        ]
        
        vulnerable_params = []
        
        try:
            # Test GET parameters
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                
                for payload in sql_payloads[:3]:  # Test only first 3 to avoid being too aggressive
                    test_url = f"{base_url}?{parsed_url.query.replace('=', f'={payload}')}"
                    try:
                        response = requests.get(test_url, timeout=10, verify=False)
                        
                        # Check for SQL error patterns
                        sql_errors = [
                            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB',
                            'SQLServer JDBC Driver', 'PostgreSQL query failed',
                            'Warning: mysql_', 'MySQLSyntaxErrorException',
                            'valid MySQL result', 'check the manual that corresponds'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                vulnerable_params.append({
                                    'url': test_url,
                                    'payload': payload,
                                    'error_pattern': error,
                                    'response_length': len(response.text)
                                })
                                break
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Manual SQL injection testing failed: {e}")
        
        results['manual_tests']['vulnerable_parameters'] = vulnerable_params
        
        return results
    
    async def _waf_detection(self) -> Dict:
        """Detect Web Application Firewall using wafw00f"""
        logger.info("Detecting Web Application Firewall")
        
        results = {
            'wafw00f': {},
            'custom_detection': {}
        }
        
        # Use wafw00f from Kali if available
        if self.kali_tools.tools_available.get('wafw00f'):
            wafw00f_result = self.kali_tools._execute_command(['wafw00f', self.target_url])
            results['wafw00f'] = wafw00f_result
        
        # Custom WAF detection
        try:
            # Send a malicious request to trigger WAF
            malicious_payload = "' OR 1=1 UNION SELECT * FROM users--"
            response = requests.get(f"{self.target_url}?test={malicious_payload}", 
                                  timeout=10, verify=False)
            
            waf_indicators = {
                'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
                'AWS WAF': ['aws', 'x-amzn-requestid'],
                'Akamai': ['akamai', 'ak-'],
                'Incapsula': ['incap_ses', 'visid_incap'],
                'Sucuri': ['sucuri', 'x-sucuri'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'F5 BIG-IP': ['f5', 'bigip', 'x-waf-event'],
                'Barracuda': ['barracuda', 'barra'],
                'Fortinet': ['fortinet', 'fortigate']
            }
            
            detected_waf = []
            response_text = response.text.lower()
            headers_str = str(response.headers).lower()
            
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in response_text or indicator in headers_str:
                        detected_waf.append(waf_name)
                        break
            
            results['custom_detection'] = {
                'detected_waf': list(set(detected_waf)),
                'status_code': response.status_code,
                'blocked': response.status_code in [403, 406, 429, 503]
            }
            
        except Exception as e:
            logger.error(f"Custom WAF detection failed: {e}")
            results['custom_detection']['error'] = str(e)
        
        return results
    
    async def _nuclei_comprehensive_scan(self) -> Dict:
        """Run nuclei for comprehensive vulnerability scanning"""
        logger.info("Running nuclei comprehensive scan")
        
        nuclei_result = self.kali_tools.nuclei_scan(self.target_url)
        
        # Categorize nuclei findings by severity
        if nuclei_result.get('success') and 'vulnerabilities' in nuclei_result:
            categorized = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
            
            for vuln in nuclei_result['vulnerabilities']:
                severity = vuln.get('info', {}).get('severity', 'info').lower()
                if severity in categorized:
                    categorized[severity].append(vuln)
                else:
                    categorized['info'].append(vuln)
            
            nuclei_result['categorized'] = categorized
        
        return nuclei_result
    
    async def _custom_vulnerability_checks(self) -> Dict:
        """Custom vulnerability detection patterns"""
        logger.info("Running custom vulnerability checks")
        
        results = {
            'information_disclosure': [],
            'security_headers': {},
            'ssl_tls_issues': [],
            'authentication_issues': [],
            'session_management': []
        }
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            # Check security headers
            security_headers = {
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-XSS-Protection': 'Missing XSS protection',
                'X-Content-Type-Options': 'Missing MIME type sniffing protection',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Permitted-Cross-Domain-Policies': 'Missing cross-domain policy'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append({
                        'header': header,
                        'description': description,
                        'severity': 'medium'
                    })
            
            results['security_headers']['missing'] = missing_headers
            results['security_headers']['present'] = [h for h in security_headers.keys() 
                                                    if h in response.headers]
            
            # Check for information disclosure
            info_patterns = [
                (r'Server: (.+)', 'Server version disclosure'),
                (r'X-Powered-By: (.+)', 'Technology stack disclosure'),
                (r'PHP/[\d.]+', 'PHP version disclosure'),
                (r'Apache/[\d.]+', 'Apache version disclosure'),
                (r'nginx/[\d.]+', 'Nginx version disclosure'),
                (r'<!--.*-->', 'HTML comments found'),
                (r'DEBUG|debug', 'Debug information found'),
                (r'error|Error|ERROR', 'Error messages found')
            ]
            
            for pattern, description in info_patterns:
                matches = re.findall(pattern, response.text + str(response.headers), re.IGNORECASE)
                if matches:
                    results['information_disclosure'].append({
                        'pattern': pattern,
                        'description': description,
                        'matches': matches[:5],  # Limit to first 5 matches
                        'severity': 'low'
                    })
            
        except Exception as e:
            logger.error(f"Custom vulnerability checks failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _categorize_nikto_finding(self, finding: str) -> str:
        """Categorize nikto finding by severity"""
        high_keywords = ['exploit', 'injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi']
        medium_keywords = ['disclosure', 'exposure', 'misconfiguration', 'weak']
        
        finding_lower = finding.lower()
        
        if any(keyword in finding_lower for keyword in high_keywords):
            return 'high'
        elif any(keyword in finding_lower for keyword in medium_keywords):
            return 'medium'
        else:
            return 'low'
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            return title_match.group(1).strip() if title_match else 'No title'
        except:
            return 'No title'
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate vulnerability summary"""
        summary = {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Count vulnerabilities from different scan results
        for scan_type, results in scan_results.items():
            if scan_type == 'summary':
                continue
                
            if isinstance(results, dict):
                # Count categorized vulnerabilities
                if 'categorized' in results:
                    for severity, vulns in results['categorized'].items():
                        if severity in summary and isinstance(vulns, list):
                            summary[severity] += len(vulns)
                
                # Count other vulnerability indicators
                if 'vulnerabilities' in results and isinstance(results['vulnerabilities'], list):
                    summary['medium'] += len(results['vulnerabilities'])
                
                if 'vulnerable_parameters' in results and isinstance(results['vulnerable_parameters'], list):
                    summary['high'] += len(results['vulnerable_parameters'])
        
        summary['total_vulnerabilities'] = sum([
            summary['critical'], summary['high'], summary['medium'], 
            summary['low'], summary['info']
        ])
        
        return summary