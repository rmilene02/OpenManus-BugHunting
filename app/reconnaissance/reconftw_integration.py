"""
Advanced Reconnaissance Tools Module

This module implements intelligent selection and execution of reconnaissance tools
following the methodology and tool selection used by reconFTW, but executing
each tool independently for maximum control and customization.

The module automatically detects available tools and selects the most appropriate
ones based on the target type and scanning requirements.
"""

import subprocess
import json
import os
import tempfile
import asyncio
from typing import Dict, List, Optional, Any
from pathlib import Path
from app.logger import logger


class AdvancedReconTools:
    """
    Advanced reconnaissance using individual security tools with intelligent selection.
    
    This class implements the methodology used by reconFTW but executes each tool
    independently, allowing for better control, customization, and error handling.
    """
    
    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        self.output_dir = output_dir or f"/tmp/recon_{target.replace('.', '_')}"
        self.tools_available = self._detect_available_tools()
        self.tool_priorities = self._define_tool_priorities()
        
    def _detect_available_tools(self) -> Dict[str, bool]:
        """Detect available reconnaissance tools on the system"""
        tools = {
            # Subdomain Enumeration
            'subfinder': self._check_tool('subfinder'),
            'amass': self._check_tool('amass'),
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
            
            # Network Scanning
            'nmap': self._check_tool('nmap'),
            'masscan': self._check_tool('masscan'),
            'zmap': self._check_tool('zmap'),
            
            # Vulnerability Scanners
            'nuclei': self._check_tool('nuclei'),
            'nessus': self._check_tool('nessus'),
            
            # Web Crawling and Analysis
            'katana': self._check_tool('katana'),
            'httpx': self._check_tool('httpx'),
            'gau': self._check_tool('gau'),
            'waybackurls': self._check_tool('waybackurls'),
            
            # DNS Tools
            'dnsx': self._check_tool('dnsx'),
            'puredns': self._check_tool('puredns'),
            'massdns': self._check_tool('massdns'),
            
            # Other Tools
            'curl': self._check_tool('curl'),
            'wget': self._check_tool('wget'),
            'dig': self._check_tool('dig'),
            'whois': self._check_tool('whois'),
            'gf': self._check_tool('gf'),
            'anew': self._check_tool('anew'),
            'unfurl': self._check_tool('unfurl'),
            'qsreplace': self._check_tool('qsreplace'),
            'dalfox': self._check_tool('dalfox'),
            'crlfuzz': self._check_tool('crlfuzz'),
            'commix': self._check_tool('commix'),
            'ghauri': self._check_tool('ghauri'),
        }
        
        available_count = sum(tools.values())
        logger.info(f"Found {available_count}/{len(tools)} reconnaissance tools available")
        return tools
    
    def _define_tool_priorities(self) -> Dict[str, Dict[str, int]]:
        """Define tool priorities for different reconnaissance phases"""
        return {
            'subdomain_enumeration': {
                'subfinder': 10,      # Fast and reliable
                'amass': 9,           # Comprehensive but slower
                'assetfinder': 8,     # Good for quick scans
                'sublist3r': 7,       # Older but still useful
                'dnsrecon': 6,        # DNS-focused
                'fierce': 5,          # Brute force approach
                'theharvester': 4     # OSINT focused
            },
            'web_discovery': {
                'httpx': 10,          # Fast HTTP probing
                'whatweb': 9,         # Technology detection
                'wafw00f': 8,         # WAF detection
                'nikto': 7,           # Vulnerability scanning
                'gobuster': 6,        # Directory enumeration
                'ffuf': 6,            # Fast fuzzing
                'wfuzz': 5,           # Web fuzzing
                'dirb': 4             # Directory brute force
            },
            'network_scanning': {
                'nmap': 10,           # The gold standard
                'masscan': 9,         # Fast port scanning
                'zmap': 8,            # Internet-wide scanning
                'nuclei': 7           # Template-based scanning
            },
            'vulnerability_detection': {
                'nuclei': 10,         # Modern template engine
                'nikto': 8,           # Web vulnerabilities
                'nessus': 7,          # Commercial scanner
                'sqlmap': 6           # SQL injection specific
            }
        }
    
    def _select_optimal_tools(self, phase: str, max_tools: int = 3) -> List[str]:
        """Select the best available tools for a specific reconnaissance phase"""
        if phase not in self.tool_priorities:
            logger.warning(f"Unknown reconnaissance phase: {phase}")
            return []
        
        phase_tools = self.tool_priorities[phase]
        available_tools = []
        
        # Get available tools with their priorities
        for tool, priority in phase_tools.items():
            if self.tools_available.get(tool, False):
                available_tools.append((tool, priority))
        
        # Sort by priority (highest first) and limit to max_tools
        available_tools.sort(key=lambda x: x[1], reverse=True)
        selected_tools = [tool for tool, _ in available_tools[:max_tools]]
        
        logger.info(f"Selected tools for {phase}: {selected_tools}")
        return selected_tools
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _execute_command(self, command: List[str], timeout: int = 300, 
                        output_file: str = None) -> Dict[str, Any]:
        """Execute a command with proper error handling and output capture"""
        try:
            logger.info(f"Executing: {' '.join(command)}")
            
            if output_file:
                with open(output_file, 'w') as f:
                    result = subprocess.run(
                        command,
                        stdout=f,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=timeout,
                        check=False
                    )
            else:
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
                'stdout': result.stdout if not output_file else '',
                'stderr': result.stderr,
                'command': ' '.join(command),
                'output_file': output_file
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
    
    async def comprehensive_recon(self, passive_only: bool = False, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Run comprehensive reconnaissance using intelligently selected tools
        
        Args:
            passive_only: Use only passive reconnaissance techniques
            deep_scan: Enable deep scanning (more thorough but slower)
        """
        logger.info(f"Starting intelligent reconnaissance for {self.target}")
        logger.info(f"Mode: {'Passive' if passive_only else 'Active'}, Deep scan: {deep_scan}")
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        recon_results = {
            'target': self.target,
            'scan_config': {
                'passive_only': passive_only,
                'deep_scan': deep_scan,
                'tools_available': len([t for t in self.tools_available.values() if t])
            },
            'subdomain_enumeration': {},
            'web_discovery': {},
            'vulnerability_scanning': {},
            'network_scanning': {},
            'osint_gathering': {},
            'tool_selection': {},
            'summary': {}
        }
        
        # Select optimal tools for each phase
        recon_results['tool_selection'] = {
            'subdomain_enumeration': self._select_optimal_tools('subdomain_enumeration', 4 if deep_scan else 2),
            'web_discovery': self._select_optimal_tools('web_discovery', 5 if deep_scan else 3),
            'network_scanning': self._select_optimal_tools('network_scanning', 3 if deep_scan else 2),
            'vulnerability_detection': self._select_optimal_tools('vulnerability_detection', 3 if deep_scan else 2)
        }
        
        # Run reconnaissance modules with selected tools
        tasks = [
            self._intelligent_subdomain_enumeration(recon_results['tool_selection']['subdomain_enumeration'], deep_scan),
            self._intelligent_web_discovery(recon_results['tool_selection']['web_discovery'], passive_only),
            self._intelligent_network_scanning(recon_results['tool_selection']['network_scanning'], passive_only),
            self._intelligent_vulnerability_scanning(recon_results['tool_selection']['vulnerability_detection'], passive_only),
            self._intelligent_osint_gathering(passive_only)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        recon_modules = [
            'subdomain_enumeration',
            'web_discovery',
            'network_scanning',
            'vulnerability_scanning',
            'osint_gathering'
        ]
        
        for i, result in enumerate(results):
            if not isinstance(result, Exception):
                recon_results[recon_modules[i]] = result
            else:
                logger.error(f"Recon module {recon_modules[i]} failed: {result}")
                recon_results[recon_modules[i]] = {'error': str(result)}
        
        # Generate summary
        recon_results['summary'] = self._generate_summary(recon_results)
        
        logger.info(f"Intelligent reconnaissance completed for {self.target}")
        return recon_results
    
    async def _intelligent_subdomain_enumeration(self, selected_tools: List[str], deep_scan: bool = False) -> Dict:
        """Intelligent subdomain enumeration using selected tools"""
        logger.info(f"Starting subdomain enumeration with tools: {selected_tools}")
        
        results = {
            'tools_used': selected_tools,
            'subdomains': set(),
            'tool_results': {},
            'statistics': {}
        }
        
        # Run each selected tool
        for tool in selected_tools:
            try:
                if tool == 'subfinder':
                    tool_result = await self._run_subfinder(deep_scan)
                elif tool == 'amass':
                    tool_result = await self._run_amass(deep_scan)
                elif tool == 'assetfinder':
                    tool_result = await self._run_assetfinder()
                elif tool == 'sublist3r':
                    tool_result = await self._run_sublist3r()
                elif tool == 'dnsrecon':
                    tool_result = await self._run_dnsrecon()
                elif tool == 'fierce':
                    tool_result = await self._run_fierce()
                elif tool == 'theharvester':
                    tool_result = await self._run_theharvester()
                else:
                    logger.warning(f"Unknown subdomain tool: {tool}")
                    continue
                
                results['tool_results'][tool] = tool_result
                if 'subdomains' in tool_result:
                    results['subdomains'].update(tool_result['subdomains'])
                    
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results['tool_results'][tool] = {'error': str(e)}
        
        # Convert set to list for JSON serialization
        results['subdomains'] = list(results['subdomains'])
        results['statistics'] = {
            'total_subdomains': len(results['subdomains']),
            'tools_successful': len([t for t in results['tool_results'] if 'error' not in results['tool_results'][t]]),
            'tools_failed': len([t for t in results['tool_results'] if 'error' in results['tool_results'][t]])
        }
        
        logger.info(f"Subdomain enumeration completed. Found {len(results['subdomains'])} unique subdomains")
        return results
    
    async def _intelligent_web_discovery(self, selected_tools: List[str], passive_only: bool = False) -> Dict:
        """Intelligent web discovery using selected tools"""
        logger.info(f"Starting web discovery with tools: {selected_tools}")
        
        results = {
            'tools_used': selected_tools,
            'live_hosts': [],
            'technologies': {},
            'waf_detection': {},
            'tool_results': {},
            'statistics': {}
        }
        
        # Run each selected tool
        for tool in selected_tools:
            try:
                if tool == 'httpx' and not passive_only:
                    tool_result = await self._run_httpx()
                elif tool == 'whatweb':
                    tool_result = await self._run_whatweb()
                elif tool == 'wafw00f' and not passive_only:
                    tool_result = await self._run_wafw00f()
                elif tool == 'nikto' and not passive_only:
                    tool_result = await self._run_nikto()
                elif tool in ['gobuster', 'ffuf', 'wfuzz', 'dirb'] and not passive_only:
                    # Skip directory enumeration in web discovery phase
                    continue
                else:
                    if passive_only and tool in ['httpx', 'wafw00f', 'nikto']:
                        logger.info(f"Skipping {tool} in passive mode")
                        continue
                    logger.warning(f"Unknown web discovery tool: {tool}")
                    continue
                
                results['tool_results'][tool] = tool_result
                
                # Aggregate results
                if 'live_hosts' in tool_result:
                    results['live_hosts'].extend(tool_result['live_hosts'])
                if 'technologies' in tool_result:
                    results['technologies'].update(tool_result['technologies'])
                if 'waf_detected' in tool_result:
                    results['waf_detection'][tool] = tool_result['waf_detected']
                    
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results['tool_results'][tool] = {'error': str(e)}
        
        # Remove duplicates and generate statistics
        results['live_hosts'] = list(set(results['live_hosts']))
        results['statistics'] = {
            'live_hosts_found': len(results['live_hosts']),
            'technologies_detected': len(results['technologies']),
            'tools_successful': len([t for t in results['tool_results'] if 'error' not in results['tool_results'][t]]),
            'tools_failed': len([t for t in results['tool_results'] if 'error' in results['tool_results'][t]])
        }
        
        logger.info(f"Web discovery completed. Found {len(results['live_hosts'])} live hosts")
        return results
    
    async def _intelligent_network_scanning(self, selected_tools: List[str], passive_only: bool = False) -> Dict:
        """Intelligent network scanning using selected tools"""
        logger.info(f"Starting network scanning with tools: {selected_tools}")
        
        if passive_only:
            logger.info("Skipping network scanning in passive mode")
            return {
                'tools_used': [],
                'open_ports': [],
                'services': {},
                'tool_results': {},
                'statistics': {'skipped': 'passive_mode'}
            }
        
        results = {
            'tools_used': selected_tools,
            'open_ports': [],
            'services': {},
            'tool_results': {},
            'statistics': {}
        }
        
        # Run each selected tool
        for tool in selected_tools:
            try:
                if tool == 'nmap':
                    tool_result = await self._run_nmap_scan()
                elif tool == 'masscan':
                    tool_result = await self._run_masscan()
                elif tool == 'zmap':
                    tool_result = await self._run_zmap()
                elif tool == 'nuclei':
                    tool_result = await self._run_nuclei_scan()
                else:
                    logger.warning(f"Unknown network scanning tool: {tool}")
                    continue
                
                results['tool_results'][tool] = tool_result
                
                # Aggregate results
                if 'open_ports' in tool_result:
                    results['open_ports'].extend(tool_result['open_ports'])
                if 'services' in tool_result:
                    results['services'].update(tool_result['services'])
                    
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results['tool_results'][tool] = {'error': str(e)}
        
        # Remove duplicates and generate statistics
        results['open_ports'] = list(set(results['open_ports']))
        results['statistics'] = {
            'open_ports_found': len(results['open_ports']),
            'services_detected': len(results['services']),
            'tools_successful': len([t for t in results['tool_results'] if 'error' not in results['tool_results'][t]]),
            'tools_failed': len([t for t in results['tool_results'] if 'error' in results['tool_results'][t]])
        }
        
        logger.info(f"Network scanning completed. Found {len(results['open_ports'])} open ports")
        return results
    
    async def _intelligent_vulnerability_scanning(self, selected_tools: List[str], passive_only: bool = False) -> Dict:
        """Intelligent vulnerability scanning using selected tools"""
        logger.info(f"Starting vulnerability scanning with tools: {selected_tools}")
        
        if passive_only:
            logger.info("Skipping vulnerability scanning in passive mode")
            return {
                'tools_used': [],
                'vulnerabilities': [],
                'tool_results': {},
                'statistics': {'skipped': 'passive_mode'}
            }
        
        results = {
            'tools_used': selected_tools,
            'vulnerabilities': [],
            'tool_results': {},
            'statistics': {}
        }
        
        # Run each selected tool
        for tool in selected_tools:
            try:
                if tool == 'nuclei':
                    tool_result = await self._run_nuclei_vuln_scan()
                elif tool == 'nikto':
                    tool_result = await self._run_nikto_vuln_scan()
                elif tool == 'sqlmap':
                    tool_result = await self._run_sqlmap()
                else:
                    logger.warning(f"Unknown vulnerability scanning tool: {tool}")
                    continue
                
                results['tool_results'][tool] = tool_result
                
                # Aggregate results
                if 'vulnerabilities' in tool_result:
                    results['vulnerabilities'].extend(tool_result['vulnerabilities'])
                    
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results['tool_results'][tool] = {'error': str(e)}
        
        # Generate statistics
        results['statistics'] = {
            'vulnerabilities_found': len(results['vulnerabilities']),
            'critical_vulns': len([v for v in results['vulnerabilities'] if v.get('severity') == 'critical']),
            'high_vulns': len([v for v in results['vulnerabilities'] if v.get('severity') == 'high']),
            'medium_vulns': len([v for v in results['vulnerabilities'] if v.get('severity') == 'medium']),
            'low_vulns': len([v for v in results['vulnerabilities'] if v.get('severity') == 'low']),
            'tools_successful': len([t for t in results['tool_results'] if 'error' not in results['tool_results'][t]]),
            'tools_failed': len([t for t in results['tool_results'] if 'error' in results['tool_results'][t]])
        }
        
        logger.info(f"Vulnerability scanning completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        return results
    
    async def _intelligent_osint_gathering(self, passive_only: bool = False) -> Dict:
        """Intelligent OSINT gathering using available tools"""
        logger.info("Starting OSINT gathering")
        
        results = {
            'tools_used': [],
            'emails': [],
            'social_media': [],
            'leaked_credentials': [],
            'technology_stack': {},
            'tool_results': {},
            'statistics': {}
        }
        
        # Select OSINT tools based on availability
        osint_tools = []
        if self.tools_available.get('theharvester'):
            osint_tools.append('theharvester')
        if self.tools_available.get('whatweb'):
            osint_tools.append('whatweb')
        
        results['tools_used'] = osint_tools
        
        # Run OSINT tools
        for tool in osint_tools:
            try:
                if tool == 'theharvester':
                    tool_result = await self._run_theharvester_osint()
                elif tool == 'whatweb':
                    tool_result = await self._run_whatweb_osint()
                else:
                    continue
                
                results['tool_results'][tool] = tool_result
                
                # Aggregate results
                if 'emails' in tool_result:
                    results['emails'].extend(tool_result['emails'])
                if 'technology_stack' in tool_result:
                    results['technology_stack'].update(tool_result['technology_stack'])
                    
            except Exception as e:
                logger.error(f"Error running {tool}: {e}")
                results['tool_results'][tool] = {'error': str(e)}
        
        # Remove duplicates and generate statistics
        results['emails'] = list(set(results['emails']))
        results['statistics'] = {
            'emails_found': len(results['emails']),
            'technologies_detected': len(results['technology_stack']),
            'tools_successful': len([t for t in results['tool_results'] if 'error' not in results['tool_results'][t]]),
            'tools_failed': len([t for t in results['tool_results'] if 'error' in results['tool_results'][t]])
        }
        
        logger.info(f"OSINT gathering completed. Found {len(results['emails'])} emails")
        return results
    
    async def _subdomain_enumeration(self) -> Dict:
        """Comprehensive subdomain enumeration using multiple tools"""
        logger.info("Starting subdomain enumeration")
        
        results = {
            'subfinder': {},
            'amass': {},
            'assetfinder': {},
            'sublist3r': {},
            'dnsrecon': {},
            'fierce': {},
            'combined_results': []
        }
        
        subdomain_files = []
        
        # Subfinder
        if self.tools_available.get('subfinder'):
            subfinder_output = os.path.join(self.output_dir, 'subfinder.txt')
            subfinder_cmd = ['subfinder', '-d', self.target, '-o', subfinder_output, '-silent']
            result = self._execute_command(subfinder_cmd, output_file=subfinder_output)
            results['subfinder'] = result
            if result['success']:
                subdomain_files.append(subfinder_output)
        
        # Amass
        if self.tools_available.get('amass'):
            amass_output = os.path.join(self.output_dir, 'amass.txt')
            amass_cmd = ['amass', 'enum', '-d', self.target, '-o', amass_output]
            result = self._execute_command(amass_cmd, timeout=900, output_file=amass_output)
            results['amass'] = result
            if result['success']:
                subdomain_files.append(amass_output)
        
        # Assetfinder
        if self.tools_available.get('assetfinder'):
            assetfinder_output = os.path.join(self.output_dir, 'assetfinder.txt')
            assetfinder_cmd = ['assetfinder', '--subs-only', self.target]
            result = self._execute_command(assetfinder_cmd, output_file=assetfinder_output)
            results['assetfinder'] = result
            if result['success']:
                subdomain_files.append(assetfinder_output)
        
        # Sublist3r
        if self.tools_available.get('sublist3r'):
            sublist3r_output = os.path.join(self.output_dir, 'sublist3r.txt')
            sublist3r_cmd = ['sublist3r', '-d', self.target, '-o', sublist3r_output]
            result = self._execute_command(sublist3r_cmd, timeout=600, output_file=sublist3r_output)
            results['sublist3r'] = result
            if result['success']:
                subdomain_files.append(sublist3r_output)
        
        # DNSRecon
        if self.tools_available.get('dnsrecon'):
            dnsrecon_output = os.path.join(self.output_dir, 'dnsrecon.txt')
            dnsrecon_cmd = ['dnsrecon', '-d', self.target, '-t', 'brt', '-o', dnsrecon_output]
            result = self._execute_command(dnsrecon_cmd, timeout=600, output_file=dnsrecon_output)
            results['dnsrecon'] = result
            if result['success']:
                subdomain_files.append(dnsrecon_output)
        
        # Fierce
        if self.tools_available.get('fierce'):
            fierce_output = os.path.join(self.output_dir, 'fierce.txt')
            fierce_cmd = ['fierce', '--domain', self.target, '--subdomains', '/usr/share/fierce/hosts.txt']
            result = self._execute_command(fierce_cmd, timeout=600, output_file=fierce_output)
            results['fierce'] = result
            if result['success']:
                subdomain_files.append(fierce_output)
        
        # Combine and deduplicate results
        all_subdomains = set()
        for file_path in subdomain_files:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and '.' in subdomain:
                            all_subdomains.add(subdomain)
            except:
                continue
        
        results['combined_results'] = sorted(list(all_subdomains))
        
        # Save combined results
        combined_output = os.path.join(self.output_dir, 'all_subdomains.txt')
        with open(combined_output, 'w') as f:
            for subdomain in results['combined_results']:
                f.write(f"{subdomain}\n")
        
        logger.info(f"Found {len(results['combined_results'])} unique subdomains")
        return results
    
    async def _web_discovery(self) -> Dict:
        """Web application discovery and probing"""
        logger.info("Starting web discovery")
        
        results = {
            'httpx': {},
            'whatweb': {},
            'wafw00f': {},
            'nikto': {},
            'live_hosts': []
        }
        
        # Check if we have subdomains to work with
        subdomains_file = os.path.join(self.output_dir, 'all_subdomains.txt')
        if not os.path.exists(subdomains_file):
            # Create a file with just the target domain
            with open(subdomains_file, 'w') as f:
                f.write(f"{self.target}\n")
        
        # HTTPx for web probing
        if self.tools_available.get('httpx'):
            httpx_output = os.path.join(self.output_dir, 'httpx.txt')
            httpx_cmd = ['httpx', '-l', subdomains_file, '-o', httpx_output, 
                        '-status-code', '-title', '-tech-detect', '-silent']
            result = self._execute_command(httpx_cmd, timeout=600, output_file=httpx_output)
            results['httpx'] = result
            
            if result['success'] and os.path.exists(httpx_output):
                with open(httpx_output, 'r') as f:
                    results['live_hosts'] = [line.strip() for line in f if line.strip()]
        
        # WhatWeb for technology detection
        if self.tools_available.get('whatweb') and results['live_hosts']:
            whatweb_output = os.path.join(self.output_dir, 'whatweb.txt')
            # Test first few hosts to avoid being too aggressive
            test_hosts = results['live_hosts'][:5]
            for host in test_hosts:
                whatweb_cmd = ['whatweb', host, '--log-brief', whatweb_output]
                result = self._execute_command(whatweb_cmd, timeout=120)
                results['whatweb'][host] = result
        
        # WAF detection
        if self.tools_available.get('wafw00f') and results['live_hosts']:
            wafw00f_output = os.path.join(self.output_dir, 'wafw00f.txt')
            # Test first few hosts
            test_hosts = results['live_hosts'][:3]
            for host in test_hosts:
                wafw00f_cmd = ['wafw00f', host]
                result = self._execute_command(wafw00f_cmd, timeout=60)
                results['wafw00f'][host] = result
        
        # Nikto scanning (limited to avoid being too aggressive)
        if self.tools_available.get('nikto') and results['live_hosts']:
            nikto_output = os.path.join(self.output_dir, 'nikto.txt')
            # Only scan the main target to avoid being too aggressive
            nikto_cmd = ['nikto', '-h', f"https://{self.target}", '-o', nikto_output]
            result = self._execute_command(nikto_cmd, timeout=900, output_file=nikto_output)
            results['nikto'] = result
        
        return results
    
    async def _vulnerability_scanning(self) -> Dict:
        """Vulnerability scanning using available tools"""
        logger.info("Starting vulnerability scanning")
        
        results = {
            'nuclei': {},
            'sqlmap': {},
            'dalfox': {},
            'crlfuzz': {},
            'commix': {}
        }
        
        # Get live hosts
        httpx_file = os.path.join(self.output_dir, 'httpx.txt')
        live_hosts = []
        if os.path.exists(httpx_file):
            with open(httpx_file, 'r') as f:
                live_hosts = [line.strip() for line in f if line.strip()]
        
        if not live_hosts:
            live_hosts = [f"https://{self.target}"]
        
        # Nuclei scanning
        if self.tools_available.get('nuclei'):
            nuclei_output = os.path.join(self.output_dir, 'nuclei.txt')
            hosts_file = os.path.join(self.output_dir, 'live_hosts.txt')
            
            # Create hosts file
            with open(hosts_file, 'w') as f:
                for host in live_hosts[:10]:  # Limit to first 10 hosts
                    f.write(f"{host}\n")
            
            nuclei_cmd = ['nuclei', '-l', hosts_file, '-o', nuclei_output, 
                         '-severity', 'medium,high,critical', '-silent']
            result = self._execute_command(nuclei_cmd, timeout=1800, output_file=nuclei_output)
            results['nuclei'] = result
        
        # SQLMap testing (only on specific targets with parameters)
        if self.tools_available.get('sqlmap'):
            # This would be implemented with specific URL parameters
            # For now, just log that it's available
            results['sqlmap']['available'] = True
            results['sqlmap']['note'] = 'SQLMap available for manual testing with specific URLs'
        
        # XSS testing with Dalfox
        if self.tools_available.get('dalfox'):
            dalfox_output = os.path.join(self.output_dir, 'dalfox.txt')
            # Test main target
            dalfox_cmd = ['dalfox', 'url', f"https://{self.target}", '--silence']
            result = self._execute_command(dalfox_cmd, timeout=600, output_file=dalfox_output)
            results['dalfox'] = result
        
        # CRLF injection testing
        if self.tools_available.get('crlfuzz'):
            crlfuzz_output = os.path.join(self.output_dir, 'crlfuzz.txt')
            hosts_file = os.path.join(self.output_dir, 'live_hosts.txt')
            if os.path.exists(hosts_file):
                crlfuzz_cmd = ['crlfuzz', '-l', hosts_file, '-o', crlfuzz_output]
                result = self._execute_command(crlfuzz_cmd, timeout=600, output_file=crlfuzz_output)
                results['crlfuzz'] = result
        
        return results
    
    async def _network_scanning(self) -> Dict:
        """Network scanning and port discovery"""
        logger.info("Starting network scanning")
        
        results = {
            'nmap': {},
            'masscan': {},
            'ports_discovered': []
        }
        
        # Nmap scanning
        if self.tools_available.get('nmap'):
            nmap_output = os.path.join(self.output_dir, 'nmap.xml')
            nmap_cmd = ['nmap', '-sS', '-sV', '-O', '--top-ports', '1000', 
                       '-oX', nmap_output, self.target]
            result = self._execute_command(nmap_cmd, timeout=1800, output_file=nmap_output)
            results['nmap'] = result
            
            # Parse nmap results if successful
            if result['success'] and os.path.exists(nmap_output):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(nmap_output)
                    root = tree.getroot()
                    
                    for host in root.findall('host'):
                        for port in host.findall('.//port'):
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            state = port.find('state').get('state')
                            if state == 'open':
                                results['ports_discovered'].append(f"{port_id}/{protocol}")
                except Exception as e:
                    logger.error(f"Failed to parse nmap XML: {e}")
        
        # Masscan for fast port discovery (if available)
        if self.tools_available.get('masscan'):
            masscan_output = os.path.join(self.output_dir, 'masscan.txt')
            masscan_cmd = ['masscan', self.target, '-p1-65535', '--rate=1000', 
                          '-oL', masscan_output]
            result = self._execute_command(masscan_cmd, timeout=600, output_file=masscan_output)
            results['masscan'] = result
        
        return results
    
    async def _osint_gathering(self) -> Dict:
        """OSINT gathering using available tools"""
        logger.info("Starting OSINT gathering")
        
        results = {
            'theharvester': {},
            'whois': {},
            'shodan': {},
            'recon_ng': {}
        }
        
        # TheHarvester for email and subdomain gathering
        if self.tools_available.get('theharvester'):
            theharvester_output = os.path.join(self.output_dir, 'theharvester.txt')
            theharvester_cmd = ['theharvester', '-d', self.target, '-b', 'google,bing,yahoo', 
                               '-l', '100', '-f', theharvester_output]
            result = self._execute_command(theharvester_cmd, timeout=600, output_file=theharvester_output)
            results['theharvester'] = result
        
        # Whois information
        if self.tools_available.get('whois'):
            whois_output = os.path.join(self.output_dir, 'whois.txt')
            whois_cmd = ['whois', self.target]
            result = self._execute_command(whois_cmd, timeout=60, output_file=whois_output)
            results['whois'] = result
        
        # Shodan search (if API key is available)
        if self.tools_available.get('shodan'):
            # This would require API key configuration
            results['shodan']['available'] = True
            results['shodan']['note'] = 'Shodan available but requires API key configuration'
        
        return results
    
    def _generate_summary(self, recon_results: Dict) -> Dict:
        """Generate reconnaissance summary"""
        summary = {
            'total_subdomains': 0,
            'live_hosts': 0,
            'open_ports': 0,
            'vulnerabilities_found': 0,
            'tools_used': []
        }
        
        # Count subdomains
        if 'subdomain_enumeration' in recon_results:
            subdomain_data = recon_results['subdomain_enumeration']
            if 'combined_results' in subdomain_data:
                summary['total_subdomains'] = len(subdomain_data['combined_results'])
        
        # Count live hosts
        if 'web_discovery' in recon_results:
            web_data = recon_results['web_discovery']
            if 'live_hosts' in web_data:
                summary['live_hosts'] = len(web_data['live_hosts'])
        
        # Count open ports
        if 'network_scanning' in recon_results:
            network_data = recon_results['network_scanning']
            if 'ports_discovered' in network_data:
                summary['open_ports'] = len(network_data['ports_discovered'])
        
        # Count tools used
        for module_name, module_data in recon_results.items():
            if module_name != 'summary' and isinstance(module_data, dict):
                for tool_name, tool_result in module_data.items():
                    if isinstance(tool_result, dict) and tool_result.get('success'):
                        summary['tools_used'].append(tool_name)
        
        summary['tools_used'] = list(set(summary['tools_used']))
        
        return summary
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Return dictionary of available tools"""
        return self.tools_available.copy()
    
    def suggest_tools_for_target(self, target_type: str = 'web') -> List[str]:
        """Suggest appropriate tools based on target type"""
        suggestions = {
            'web': [
                'subfinder', 'httpx', 'whatweb', 'nikto', 'nuclei', 
                'gobuster', 'ffuf', 'wafw00f', 'dalfox'
            ],
            'network': [
                'nmap', 'masscan', 'nuclei', 'dnsx', 'amass'
            ],
            'osint': [
                'theharvester', 'recon-ng', 'shodan', 'whois', 'subfinder'
            ],
            'comprehensive': [
                'subfinder', 'amass', 'httpx', 'nmap', 'nuclei', 'nikto',
                'whatweb', 'theharvester', 'gobuster', 'ffuf'
            ]
        }
        
        recommended = suggestions.get(target_type, suggestions['comprehensive'])
        available_recommended = [tool for tool in recommended if self.tools_available.get(tool)]
        
        return available_recommended