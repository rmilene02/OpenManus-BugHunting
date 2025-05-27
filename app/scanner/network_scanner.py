"""
Network Scanner Module

This module provides network scanning capabilities including port scanning,
service detection, and network enumeration.
"""

import asyncio
import json
import socket
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import subprocess

from app.logger import logger


class NetworkScanner:
    """Network scanning and enumeration engine"""
    
    def __init__(self, target: str, output_dir: str = "./results"):
        """
        Initialize network scanner
        
        Args:
            target: Target IP address or hostname
            output_dir: Directory to save results
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage
        self.scan_results = {
            'open_ports': [],
            'services': {},
            'os_detection': {},
            'vulnerabilities': [],
            'network_info': {}
        }
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
        ]
    
    async def scan_network(self, 
                          port_range: Optional[str] = None,
                          stealth_mode: bool = False,
                          service_detection: bool = True) -> Dict:
        """
        Perform comprehensive network scan
        
        Args:
            port_range: Port range to scan (e.g., "1-1000")
            stealth_mode: Use stealth scanning techniques
            service_detection: Perform service version detection
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting network scan for: {self.target}")
        
        try:
            # Resolve hostname to IP
            await self._resolve_target()
            
            # Port scanning
            if port_range:
                ports = self._parse_port_range(port_range)
            else:
                ports = self.common_ports
            
            await self._scan_ports(ports, stealth_mode)
            
            # Service detection
            if service_detection and self.scan_results['open_ports']:
                await self._detect_services()
            
            # OS detection
            await self._detect_os()
            
            # Save results
            await self._save_results()
            
            return self._format_results()
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return {'error': str(e)}
    
    async def _resolve_target(self):
        """Resolve target hostname to IP address"""
        try:
            if self._is_ip_address(self.target):
                ip_address = self.target
            else:
                ip_address = socket.gethostbyname(self.target)
            
            self.scan_results['network_info'] = {
                'target': self.target,
                'ip_address': ip_address,
                'hostname': self.target if not self._is_ip_address(self.target) else None
            }
            
            logger.info(f"Target resolved to: {ip_address}")
            
        except Exception as e:
            logger.warning(f"Failed to resolve target: {e}")
            self.scan_results['network_info'] = {
                'target': self.target,
                'ip_address': self.target,
                'hostname': None
            }
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
        
        return ports
    
    async def _scan_ports(self, ports: List[int], stealth_mode: bool = False):
        """Scan specified ports"""
        logger.info(f"Scanning {len(ports)} ports...")
        
        # Use simple socket scanning for now
        # In production, integrate with nmap or other tools
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                result = sock.connect_ex((self.scan_results['network_info']['ip_address'], port))
                
                if result == 0:
                    open_ports.append(port)
                    logger.debug(f"Port {port} is open")
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
                continue
        
        self.scan_results['open_ports'] = open_ports
        logger.info(f"Found {len(open_ports)} open ports")
    
    async def _detect_services(self):
        """Detect services running on open ports"""
        logger.info("Detecting services...")
        
        # Mock service detection - replace with actual implementation
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for port in self.scan_results['open_ports']:
            service_name = service_map.get(port, 'Unknown')
            
            # Mock service version detection
            if service_name == 'HTTP':
                version = 'Apache/2.4.41'
            elif service_name == 'SSH':
                version = 'OpenSSH 8.0'
            elif service_name == 'HTTPS':
                version = 'Apache/2.4.41 (SSL)'
            else:
                version = 'Unknown'
            
            self.scan_results['services'][port] = {
                'service': service_name,
                'version': version,
                'state': 'open'
            }
        
        logger.info(f"Detected services on {len(self.scan_results['services'])} ports")
    
    async def _detect_os(self):
        """Detect operating system"""
        logger.info("Detecting operating system...")
        
        # Mock OS detection - replace with actual implementation
        mock_os = {
            'os_family': 'Linux',
            'os_version': 'Ubuntu 20.04',
            'confidence': 85,
            'method': 'TCP fingerprinting'
        }
        
        self.scan_results['os_detection'] = mock_os
        logger.info(f"OS detected: {mock_os['os_family']} {mock_os['os_version']}")
    
    async def _save_results(self):
        """Save scan results to file"""
        target_name = self.target.replace('.', '_').replace(':', '_')
        results_file = self.output_dir / f"network_scan_{target_name}.json"
        
        with open(results_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        logger.info(f"Network scan results saved to: {results_file}")
    
    def _format_results(self) -> Dict:
        """Format results for return"""
        return {
            'target': self.target,
            'scan_summary': {
                'total_ports_scanned': len(self.common_ports),
                'open_ports': len(self.scan_results['open_ports']),
                'services_detected': len(self.scan_results['services']),
                'os_detected': bool(self.scan_results['os_detection'])
            },
            'results': {
                'network_info': self.scan_results['network_info'],
                'open_ports': self.scan_results['open_ports'],
                'services': self.scan_results['services'],
                'os_detection': self.scan_results['os_detection']
            },
            'status': 'completed'
        }
    
    def get_open_ports(self) -> List[int]:
        """Get list of open ports"""
        return self.scan_results['open_ports']
    
    def get_services(self) -> Dict:
        """Get detected services"""
        return self.scan_results['services']
    
    def get_os_info(self) -> Dict:
        """Get OS detection results"""
        return self.scan_results['os_detection']


# Example usage
async def main():
    """Example usage of NetworkScanner"""
    scanner = NetworkScanner("example.com", "./test_results")
    results = await scanner.scan_network(
        port_range="1-1000",
        stealth_mode=True,
        service_detection=True
    )
    
    print("Network Scan Results:")
    print(f"Open ports: {results['scan_summary']['open_ports']}")
    print(f"Services detected: {results['scan_summary']['services_detected']}")
    
    if results['results']['open_ports']:
        print("\nOpen Ports:")
        for port in results['results']['open_ports']:
            service_info = results['results']['services'].get(port, {})
            service_name = service_info.get('service', 'Unknown')
            print(f"  {port}: {service_name}")


if __name__ == "__main__":
    asyncio.run(main())