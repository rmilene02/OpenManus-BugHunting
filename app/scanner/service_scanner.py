"""
Service Scanner Module

This module provides service-specific scanning capabilities for various
network services and protocols.
"""

import asyncio
import json
import socket
import ssl
from typing import Dict, List, Optional
from pathlib import Path

from app.logger import logger


class ServiceScanner:
    """Service-specific scanning and enumeration engine"""
    
    def __init__(self, target: str, output_dir: str = "./results"):
        """
        Initialize service scanner
        
        Args:
            target: Target IP address or hostname
            output_dir: Directory to save results
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage
        self.service_results = {
            'http_services': [],
            'ssh_services': [],
            'ftp_services': [],
            'smtp_services': [],
            'dns_services': [],
            'database_services': [],
            'other_services': []
        }
    
    async def scan_services(self, ports: List[int]) -> Dict:
        """
        Scan specific services on given ports
        
        Args:
            ports: List of ports to scan for services
            
        Returns:
            Dictionary containing service scan results
        """
        logger.info(f"Starting service scan for {len(ports)} ports on {self.target}")
        
        try:
            # Scan each port for specific services
            for port in ports:
                await self._scan_port_service(port)
            
            # Save results
            await self._save_results()
            
            return self._format_results()
            
        except Exception as e:
            logger.error(f"Service scan failed: {e}")
            return {'error': str(e)}
    
    async def _scan_port_service(self, port: int):
        """Scan a specific port for service information"""
        try:
            # Determine service type based on port
            if port in [80, 8080, 8000, 8888]:
                await self._scan_http_service(port)
            elif port in [443, 8443]:
                await self._scan_https_service(port)
            elif port == 22:
                await self._scan_ssh_service(port)
            elif port == 21:
                await self._scan_ftp_service(port)
            elif port in [25, 587, 465]:
                await self._scan_smtp_service(port)
            elif port == 53:
                await self._scan_dns_service(port)
            elif port in [3306, 5432, 1433]:
                await self._scan_database_service(port)
            else:
                await self._scan_generic_service(port)
                
        except Exception as e:
            logger.debug(f"Error scanning service on port {port}: {e}")
    
    async def _scan_http_service(self, port: int):
        """Scan HTTP service"""
        logger.debug(f"Scanning HTTP service on port {port}")
        
        try:
            # Mock HTTP service detection
            service_info = {
                'port': port,
                'service': 'HTTP',
                'version': 'Apache/2.4.41',
                'headers': {
                    'Server': 'Apache/2.4.41 (Ubuntu)',
                    'X-Powered-By': 'PHP/7.4.3'
                },
                'status_codes': {
                    '/': 200,
                    '/admin': 403,
                    '/robots.txt': 200
                },
                'technologies': ['Apache', 'PHP'],
                'security_headers': {
                    'X-Frame-Options': False,
                    'X-XSS-Protection': False,
                    'X-Content-Type-Options': False
                }
            }
            
            self.service_results['http_services'].append(service_info)
            logger.info(f"HTTP service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan HTTP service on port {port}: {e}")
    
    async def _scan_https_service(self, port: int):
        """Scan HTTPS service"""
        logger.debug(f"Scanning HTTPS service on port {port}")
        
        try:
            # Mock HTTPS service detection with SSL info
            service_info = {
                'port': port,
                'service': 'HTTPS',
                'version': 'Apache/2.4.41',
                'ssl_info': {
                    'certificate': {
                        'subject': f'CN={self.target}',
                        'issuer': 'DigiCert Inc',
                        'valid_from': '2023-01-01',
                        'valid_to': '2024-01-01',
                        'san_domains': [self.target, f'www.{self.target}']
                    },
                    'protocols': ['TLSv1.2', 'TLSv1.3'],
                    'ciphers': ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256']
                },
                'security_headers': {
                    'Strict-Transport-Security': True,
                    'X-Frame-Options': True,
                    'X-Content-Type-Options': True
                }
            }
            
            self.service_results['http_services'].append(service_info)
            logger.info(f"HTTPS service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan HTTPS service on port {port}: {e}")
    
    async def _scan_ssh_service(self, port: int):
        """Scan SSH service"""
        logger.debug(f"Scanning SSH service on port {port}")
        
        try:
            # Mock SSH service detection
            service_info = {
                'port': port,
                'service': 'SSH',
                'version': 'OpenSSH_8.0',
                'banner': 'SSH-2.0-OpenSSH_8.0',
                'algorithms': {
                    'kex': ['diffie-hellman-group14-sha256', 'ecdh-sha2-nistp256'],
                    'encryption': ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'],
                    'mac': ['hmac-sha2-256', 'hmac-sha2-512']
                },
                'auth_methods': ['publickey', 'password'],
                'security_issues': []
            }
            
            self.service_results['ssh_services'].append(service_info)
            logger.info(f"SSH service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan SSH service on port {port}: {e}")
    
    async def _scan_ftp_service(self, port: int):
        """Scan FTP service"""
        logger.debug(f"Scanning FTP service on port {port}")
        
        try:
            # Mock FTP service detection
            service_info = {
                'port': port,
                'service': 'FTP',
                'version': 'vsftpd 3.0.3',
                'banner': '220 Welcome to FTP service',
                'anonymous_login': False,
                'features': ['PASV', 'EPSV', 'UTF8'],
                'security_issues': []
            }
            
            self.service_results['ftp_services'].append(service_info)
            logger.info(f"FTP service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan FTP service on port {port}: {e}")
    
    async def _scan_smtp_service(self, port: int):
        """Scan SMTP service"""
        logger.debug(f"Scanning SMTP service on port {port}")
        
        try:
            # Mock SMTP service detection
            service_info = {
                'port': port,
                'service': 'SMTP',
                'version': 'Postfix 3.4.13',
                'banner': '220 mail.example.com ESMTP Postfix',
                'capabilities': ['PIPELINING', 'SIZE', 'VRFY', 'ETRN', 'STARTTLS'],
                'auth_methods': ['PLAIN', 'LOGIN'],
                'tls_support': True,
                'open_relay': False
            }
            
            self.service_results['smtp_services'].append(service_info)
            logger.info(f"SMTP service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan SMTP service on port {port}: {e}")
    
    async def _scan_dns_service(self, port: int):
        """Scan DNS service"""
        logger.debug(f"Scanning DNS service on port {port}")
        
        try:
            # Mock DNS service detection
            service_info = {
                'port': port,
                'service': 'DNS',
                'version': 'BIND 9.16.1',
                'recursion_enabled': False,
                'zone_transfer': False,
                'dnssec_enabled': True,
                'supported_records': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            }
            
            self.service_results['dns_services'].append(service_info)
            logger.info(f"DNS service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan DNS service on port {port}: {e}")
    
    async def _scan_database_service(self, port: int):
        """Scan database service"""
        logger.debug(f"Scanning database service on port {port}")
        
        try:
            # Determine database type by port
            if port == 3306:
                db_type = 'MySQL'
                version = '8.0.25'
            elif port == 5432:
                db_type = 'PostgreSQL'
                version = '13.3'
            elif port == 1433:
                db_type = 'SQL Server'
                version = '2019'
            else:
                db_type = 'Unknown'
                version = 'Unknown'
            
            service_info = {
                'port': port,
                'service': db_type,
                'version': version,
                'authentication_required': True,
                'ssl_support': True,
                'default_databases': [],
                'security_issues': []
            }
            
            self.service_results['database_services'].append(service_info)
            logger.info(f"{db_type} service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan database service on port {port}: {e}")
    
    async def _scan_generic_service(self, port: int):
        """Scan generic/unknown service"""
        logger.debug(f"Scanning generic service on port {port}")
        
        try:
            # Mock generic service detection
            service_info = {
                'port': port,
                'service': 'Unknown',
                'banner': '',
                'protocol': 'TCP',
                'state': 'open',
                'fingerprint': ''
            }
            
            self.service_results['other_services'].append(service_info)
            logger.debug(f"Generic service detected on port {port}")
            
        except Exception as e:
            logger.debug(f"Failed to scan generic service on port {port}: {e}")
    
    async def _save_results(self):
        """Save service scan results to file"""
        target_name = self.target.replace('.', '_').replace(':', '_')
        results_file = self.output_dir / f"service_scan_{target_name}.json"
        
        with open(results_file, 'w') as f:
            json.dump(self.service_results, f, indent=2)
        
        logger.info(f"Service scan results saved to: {results_file}")
    
    def _format_results(self) -> Dict:
        """Format results for return"""
        total_services = sum(len(services) for services in self.service_results.values())
        
        return {
            'target': self.target,
            'scan_summary': {
                'total_services': total_services,
                'http_services': len(self.service_results['http_services']),
                'ssh_services': len(self.service_results['ssh_services']),
                'ftp_services': len(self.service_results['ftp_services']),
                'smtp_services': len(self.service_results['smtp_services']),
                'dns_services': len(self.service_results['dns_services']),
                'database_services': len(self.service_results['database_services']),
                'other_services': len(self.service_results['other_services'])
            },
            'services': self.service_results,
            'status': 'completed'
        }
    
    def get_http_services(self) -> List[Dict]:
        """Get HTTP/HTTPS services"""
        return self.service_results['http_services']
    
    def get_database_services(self) -> List[Dict]:
        """Get database services"""
        return self.service_results['database_services']
    
    def get_all_services(self) -> Dict:
        """Get all detected services"""
        return self.service_results


# Example usage
async def main():
    """Example usage of ServiceScanner"""
    scanner = ServiceScanner("example.com", "./test_results")
    results = await scanner.scan_services([22, 80, 443, 3306])
    
    print("Service Scan Results:")
    print(f"Total services: {results['scan_summary']['total_services']}")
    
    for service_type, count in results['scan_summary'].items():
        if count > 0 and service_type != 'total_services':
            print(f"{service_type}: {count}")


if __name__ == "__main__":
    asyncio.run(main())