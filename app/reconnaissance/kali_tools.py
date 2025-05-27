"""
Kali Linux Tools Integration Module

This module provides integration with native Kali Linux security tools for reconnaissance,
vulnerability scanning, and penetration testing. It acts as a wrapper to execute and
parse results from various Kali tools.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import re
import os
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path
from app.logger import logger


class KaliToolsManager:
    """Manager for executing and parsing results from Kali Linux security tools"""
    
    def __init__(self):
        self.tools_available = self._check_available_tools()
        
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which Kali tools are available on the system"""
        tools = {
            # Reconnaissance
            'nmap': self._check_tool('nmap'),
            'masscan': self._check_tool('masscan'),
            'amass': self._check_tool('amass'),
            'subfinder': self._check_tool('subfinder'),
            'assetfinder': self._check_tool('assetfinder'),
            'sublist3r': self._check_tool('sublist3r'),
            'dnsrecon': self._check_tool('dnsrecon'),
            'fierce': self._check_tool('fierce'),
            'theharvester': self._check_tool('theharvester'),
            'recon-ng': self._check_tool('recon-ng'),
            'shodan': self._check_tool('shodan'),
            
            # Web Application Testing
            'nikto': self._check_tool('nikto'),
            'dirb': self._check_tool('dirb'),
            'dirbuster': self._check_tool('dirbuster'),
            'gobuster': self._check_tool('gobuster'),
            'wfuzz': self._check_tool('wfuzz'),
            'ffuf': self._check_tool('ffuf'),
            'sqlmap': self._check_tool('sqlmap'),
            'wpscan': self._check_tool('wpscan'),
            'whatweb': self._check_tool('whatweb'),
            'wafw00f': self._check_tool('wafw00f'),
            
            # Vulnerability Scanners
            'openvas': self._check_tool('openvas'),
            'nuclei': self._check_tool('nuclei'),
            'nessus': self._check_tool('nessus'),
            
            # Network Analysis
            'wireshark': self._check_tool('wireshark'),
            'tcpdump': self._check_tool('tcpdump'),
            'netcat': self._check_tool('nc'),
            'netstat': self._check_tool('netstat'),
            
            # Exploitation
            'metasploit': self._check_tool('msfconsole'),
            'searchsploit': self._check_tool('searchsploit'),
            'exploit-db': self._check_tool('searchsploit'),
            
            # Other utilities
            'curl': self._check_tool('curl'),
            'wget': self._check_tool('wget'),
            'dig': self._check_tool('dig'),
            'nslookup': self._check_tool('nslookup'),
            'whois': self._check_tool('whois'),
        }
        
        available_count = sum(tools.values())
        logger.info(f"Found {available_count}/{len(tools)} Kali tools available")
        return tools
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _execute_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute a command and return structured results"""
        try:
            logger.info(f"Executing: {' '.join(command)}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(command)
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'command': ' '.join(command)
            }
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'command': ' '.join(command)
            }

    # Reconnaissance Tools
    def nmap_scan(self, target: str, scan_type: str = 'basic', ports: str = None) -> Dict:
        """Execute nmap scan with various options"""
        if not self.tools_available.get('nmap'):
            return {'error': 'nmap not available'}
        
        base_cmd = ['nmap']
        
        scan_profiles = {
            'basic': ['-sS', '-O', '-sV'],
            'stealth': ['-sS', '-f', '-T2'],
            'aggressive': ['-A', '-T4'],
            'vuln': ['--script=vuln'],
            'discovery': ['-sn'],
            'tcp_connect': ['-sT'],
            'udp': ['-sU'],
            'comprehensive': ['-sS', '-sU', '-O', '-sV', '-sC', '--script=vuln']
        }
        
        if scan_type in scan_profiles:
            base_cmd.extend(scan_profiles[scan_type])
        
        if ports:
            base_cmd.extend(['-p', ports])
        
        # Output in XML format for better parsing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_output = f.name
        
        base_cmd.extend(['-oX', xml_output, target])
        
        result = self._execute_command(base_cmd, timeout=600)
        
        if result['success'] and os.path.exists(xml_output):
            try:
                parsed_results = self._parse_nmap_xml(xml_output)
                result['parsed'] = parsed_results
            except Exception as e:
                logger.error(f"Failed to parse nmap XML: {e}")
            finally:
                os.unlink(xml_output)
        
        return result
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse nmap XML output"""
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        results = {
            'hosts': [],
            'scan_info': {}
        }
        
        # Parse scan info
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            results['scan_info'] = scaninfo.attrib
        
        # Parse hosts
        for host in root.findall('host'):
            host_info = {
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'os': {},
                'status': {}
            }
            
            # Status
            status = host.find('status')
            if status is not None:
                host_info['status'] = status.attrib
            
            # Addresses
            for address in host.findall('address'):
                host_info['addresses'].append(address.attrib)
            
            # Hostnames
            hostnames = host.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    host_info['hostnames'].append(hostname.attrib)
            
            # Ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_info = port.attrib.copy()
                    
                    state = port.find('state')
                    if state is not None:
                        port_info['state'] = state.attrib
                    
                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = service.attrib
                    
                    host_info['ports'].append(port_info)
            
            # OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    host_info['os'] = osmatch.attrib
            
            results['hosts'].append(host_info)
        
        return results
    
    def subfinder_scan(self, domain: str) -> Dict:
        """Execute subfinder for subdomain enumeration"""
        if not self.tools_available.get('subfinder'):
            return {'error': 'subfinder not available'}
        
        command = ['subfinder', '-d', domain, '-silent']
        result = self._execute_command(command)
        
        if result['success']:
            subdomains = [line.strip() for line in result['stdout'].split('\n') if line.strip()]
            result['subdomains'] = subdomains
            result['count'] = len(subdomains)
        
        return result
    
    def amass_enum(self, domain: str) -> Dict:
        """Execute amass for comprehensive subdomain enumeration"""
        if not self.tools_available.get('amass'):
            return {'error': 'amass not available'}
        
        command = ['amass', 'enum', '-d', domain]
        result = self._execute_command(command, timeout=900)  # 15 minutes timeout
        
        if result['success']:
            subdomains = [line.strip() for line in result['stdout'].split('\n') if line.strip()]
            result['subdomains'] = subdomains
            result['count'] = len(subdomains)
        
        return result
    
    def theharvester_scan(self, domain: str, sources: str = 'google,bing,yahoo') -> Dict:
        """Execute theHarvester for OSINT gathering"""
        if not self.tools_available.get('theharvester'):
            return {'error': 'theharvester not available'}
        
        command = ['theharvester', '-d', domain, '-b', sources, '-l', '500']
        result = self._execute_command(command, timeout=600)
        
        if result['success']:
            # Parse theHarvester output
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', result['stdout'])
            hosts = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', result['stdout'])
            
            result['emails'] = list(set(emails))
            result['hosts'] = list(set(hosts))
        
        return result
    
    # Web Application Testing Tools
    def nikto_scan(self, target: str) -> Dict:
        """Execute nikto web vulnerability scanner"""
        if not self.tools_available.get('nikto'):
            return {'error': 'nikto not available'}
        
        command = ['nikto', '-h', target, '-Format', 'txt']
        result = self._execute_command(command, timeout=900)
        
        if result['success']:
            # Parse nikto output for vulnerabilities
            vulnerabilities = []
            for line in result['stdout'].split('\n'):
                if '+ ' in line and any(keyword in line.lower() for keyword in 
                                     ['vuln', 'risk', 'security', 'exploit', 'injection']):
                    vulnerabilities.append(line.strip())
            
            result['vulnerabilities'] = vulnerabilities
        
        return result
    
    def gobuster_dir(self, target: str, wordlist: str = '/usr/share/wordlists/dirb/common.txt') -> Dict:
        """Execute gobuster for directory/file enumeration"""
        if not self.tools_available.get('gobuster'):
            return {'error': 'gobuster not available'}
        
        command = ['gobuster', 'dir', '-u', target, '-w', wordlist, '-q']
        result = self._execute_command(command, timeout=600)
        
        if result['success']:
            # Parse gobuster output
            found_paths = []
            for line in result['stdout'].split('\n'):
                if line.startswith('/'):
                    found_paths.append(line.strip())
            
            result['found_paths'] = found_paths
        
        return result
    
    def sqlmap_test(self, target: str, data: str = None) -> Dict:
        """Execute sqlmap for SQL injection testing"""
        if not self.tools_available.get('sqlmap'):
            return {'error': 'sqlmap not available'}
        
        command = ['sqlmap', '-u', target, '--batch', '--level=1', '--risk=1']
        
        if data:
            command.extend(['--data', data])
        
        result = self._execute_command(command, timeout=900)
        
        if result['success']:
            # Check for SQL injection vulnerabilities
            vulnerable = 'vulnerable' in result['stdout'].lower()
            result['vulnerable'] = vulnerable
            
            if vulnerable:
                # Extract vulnerability details
                vuln_details = []
                lines = result['stdout'].split('\n')
                for i, line in enumerate(lines):
                    if 'parameter' in line.lower() and 'vulnerable' in line.lower():
                        vuln_details.append(line.strip())
                
                result['vulnerability_details'] = vuln_details
        
        return result
    
    def whatweb_scan(self, target: str) -> Dict:
        """Execute whatweb for technology detection"""
        if not self.tools_available.get('whatweb'):
            return {'error': 'whatweb not available'}
        
        command = ['whatweb', target, '--log-brief=-']
        result = self._execute_command(command)
        
        if result['success']:
            # Parse whatweb output
            technologies = []
            for line in result['stdout'].split('\n'):
                if '[' in line and ']' in line:
                    tech_match = re.findall(r'\[([^\]]+)\]', line)
                    technologies.extend(tech_match)
            
            result['technologies'] = list(set(technologies))
        
        return result
    
    def nuclei_scan(self, target: str, templates: str = None) -> Dict:
        """Execute nuclei vulnerability scanner"""
        if not self.tools_available.get('nuclei'):
            return {'error': 'nuclei not available'}
        
        command = ['nuclei', '-u', target, '-json']
        
        if templates:
            command.extend(['-t', templates])
        
        result = self._execute_command(command, timeout=900)
        
        if result['success']:
            # Parse nuclei JSON output
            vulnerabilities = []
            for line in result['stdout'].split('\n'):
                if line.strip():
                    try:
                        vuln_data = json.loads(line)
                        vulnerabilities.append(vuln_data)
                    except json.JSONDecodeError:
                        continue
            
            result['vulnerabilities'] = vulnerabilities
        
        return result
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Return dictionary of available tools"""
        return self.tools_available.copy()
    
    def get_tool_help(self, tool_name: str) -> str:
        """Get help information for a specific tool"""
        if not self.tools_available.get(tool_name):
            return f"Tool '{tool_name}' is not available"
        
        try:
            result = subprocess.run([tool_name, '--help'], 
                                  capture_output=True, text=True, timeout=10)
            return result.stdout if result.stdout else result.stderr
        except:
            try:
                result = subprocess.run([tool_name, '-h'], 
                                      capture_output=True, text=True, timeout=10)
                return result.stdout if result.stdout else result.stderr
            except:
                return f"Could not get help for {tool_name}"