"""
AI-Powered Reconnaissance Engine

This module uses AI to intelligently select and execute reconnaissance tools
based on the target characteristics and scan objectives. The AI analyzes
the context and chooses the most appropriate tools from the available arsenal.

Features:
- AI-driven tool selection
- Dynamic adaptation to target types
- Intelligent execution ordering
- Context-aware decision making
- Learning from previous selections
"""

import subprocess
import json
import os
import asyncio
import tempfile
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse
from app.logger import logger
from app.core.ai_tool_selector import AIToolSelector, ScanContext, ToolInfo


class AIReconEngine:
    """
    AI-powered reconnaissance engine that intelligently selects and executes
    security tools based on context and objectives.
    """
    
    def __init__(self, target: str, output_dir: str = None, llm_client=None):
        self.target = target
        self.output_dir = output_dir or f"/tmp/ai_recon_{target.replace('.', '_')}"
        self.llm_client = llm_client
        
        # Initialize AI tool selector
        self.ai_selector = AIToolSelector(llm_client)
        
        # Detect available tools
        self.tools_available = self._detect_available_tools()
        
        # Analyze target to determine context
        self.scan_context = self._analyze_target()
        
        # Update tool availability in AI selector
        self.ai_selector.update_tool_availability(self.tools_available)
        
        logger.info(f"AI Recon Engine initialized for target: {target}")
        logger.info(f"Target type: {self.scan_context.target_type}")
        logger.info(f"Available tools: {sum(self.tools_available.values())}/{len(self.tools_available)}")
    
    def _analyze_target(self) -> ScanContext:
        """Analyze the target to determine its type and characteristics"""
        target_type = "unknown"
        
        # Determine target type
        if self._is_ip_address(self.target):
            target_type = "ip"
        elif self._is_url(self.target):
            target_type = "url"
        elif self._is_domain(self.target):
            target_type = "domain"
        elif self._is_network_range(self.target):
            target_type = "network"
        
        return ScanContext(
            target=self.target,
            target_type=target_type,
            scan_mode="reconnaissance",  # Default, can be overridden
            passive_only=False,
            deep_scan=False,
            stealth_mode=False,
            time_constraint="normal"
        )
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _is_url(self, target: str) -> bool:
        """Check if target is a URL"""
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain name"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(target))
    
    def _is_network_range(self, target: str) -> bool:
        """Check if target is a network range"""
        import ipaddress
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False
    
    def _detect_available_tools(self) -> Dict[str, bool]:
        """Detect which reconnaissance tools are available on the system"""
        tools = {
            # Subdomain Enumeration
            'subfinder': self._check_tool('subfinder'),
            'amass': self._check_tool('amass'),
            'assetfinder': self._check_tool('assetfinder'),
            'sublist3r': self._check_tool('sublist3r'),
            'dnsrecon': self._check_tool('dnsrecon'),
            'fierce': self._check_tool('fierce'),
            
            # Web Discovery
            'httpx': self._check_tool('httpx'),
            'whatweb': self._check_tool('whatweb'),
            'wafw00f': self._check_tool('wafw00f'),
            'nikto': self._check_tool('nikto'),
            
            # Network Scanning
            'nmap': self._check_tool('nmap'),
            'masscan': self._check_tool('masscan'),
            'zmap': self._check_tool('zmap'),
            
            # Vulnerability Scanning
            'nuclei': self._check_tool('nuclei'),
            
            # Directory Enumeration
            'gobuster': self._check_tool('gobuster'),
            'ffuf': self._check_tool('ffuf'),
            'wfuzz': self._check_tool('wfuzz'),
            'dirb': self._check_tool('dirb'),
            
            # OSINT
            'theharvester': self._check_tool('theharvester'),
        }
        
        available_count = sum(tools.values())
        logger.info(f"Detected {available_count}/{len(tools)} reconnaissance tools")
        return tools
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    async def ai_powered_reconnaissance(self, 
                                      scan_mode: str = "comprehensive",
                                      passive_only: bool = False,
                                      deep_scan: bool = False,
                                      stealth_mode: bool = False,
                                      time_constraint: str = "normal") -> Dict[str, Any]:
        """
        Perform AI-powered reconnaissance with intelligent tool selection
        
        Args:
            scan_mode: Type of scan (reconnaissance, vulnerability-scan, web-scan, etc.)
            passive_only: Use only passive techniques
            deep_scan: Enable deep scanning (more thorough but slower)
            stealth_mode: Use stealth techniques to avoid detection
            time_constraint: Time constraint (fast, normal, thorough)
        """
        logger.info(f"Starting AI-powered reconnaissance for {self.target}")
        
        # Update scan context
        self.scan_context.scan_mode = scan_mode
        self.scan_context.passive_only = passive_only
        self.scan_context.deep_scan = deep_scan
        self.scan_context.stealth_mode = stealth_mode
        self.scan_context.time_constraint = time_constraint
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Let AI select the most appropriate tools
        logger.info("Consulting AI for optimal tool selection...")
        selected_tools = await self.ai_selector.select_tools_with_ai(
            self.scan_context, 
            self.tools_available
        )
        
        # Initialize results structure
        results = {
            'target': self.target,
            'scan_context': {
                'target_type': self.scan_context.target_type,
                'scan_mode': scan_mode,
                'passive_only': passive_only,
                'deep_scan': deep_scan,
                'stealth_mode': stealth_mode,
                'time_constraint': time_constraint
            },
            'ai_tool_selection': selected_tools,
            'execution_results': {},
            'aggregated_results': {},
            'ai_analysis': {},
            'summary': {}
        }
        
        # Execute selected tools in intelligent order
        execution_order = self._determine_execution_order(selected_tools)
        logger.info(f"AI-determined execution order: {execution_order}")
        
        for category in execution_order:
            if category in selected_tools and selected_tools[category]:
                logger.info(f"Executing {category} tools: {selected_tools[category]}")
                
                category_results = await self._execute_tool_category(
                    category, 
                    selected_tools[category]
                )
                
                results['execution_results'][category] = category_results
        
        # Aggregate and analyze results
        results['aggregated_results'] = self._aggregate_results(results['execution_results'])
        
        # Get AI analysis of results (if LLM is available)
        if self.llm_client:
            try:
                results['ai_analysis'] = await self._ai_analyze_results(results['aggregated_results'])
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                results['ai_analysis'] = {'error': str(e)}
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        logger.info(f"AI-powered reconnaissance completed for {self.target}")
        return results
    
    def _determine_execution_order(self, selected_tools: Dict[str, List[str]]) -> List[str]:
        """Determine the optimal order to execute tool categories"""
        # Standard order that makes logical sense
        standard_order = [
            'osint',                    # Start with passive OSINT
            'subdomain_enumeration',    # Find subdomains
            'web_discovery',           # Discover web services
            'network_scanning',        # Scan network services
            'vulnerability_scanning',  # Look for vulnerabilities
            'directory_enumeration'    # Find hidden content
        ]
        
        # Filter to only include categories with selected tools
        execution_order = [category for category in standard_order 
                          if category in selected_tools and selected_tools[category]]
        
        return execution_order
    
    async def _execute_tool_category(self, category: str, tools: List[str]) -> Dict[str, Any]:
        """Execute all tools in a specific category"""
        logger.info(f"Executing {category} with tools: {tools}")
        
        category_results = {
            'category': category,
            'tools_executed': tools,
            'tool_results': {},
            'aggregated_data': {},
            'execution_time': 0
        }
        
        start_time = asyncio.get_event_loop().time()
        
        # Execute tools concurrently where possible
        tasks = []
        for tool in tools:
            task = self._execute_single_tool(tool, category)
            tasks.append(task)
        
        # Wait for all tools to complete
        tool_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(tool_results):
            tool_name = tools[i]
            if not isinstance(result, Exception):
                category_results['tool_results'][tool_name] = result
            else:
                logger.error(f"Tool {tool_name} failed: {result}")
                category_results['tool_results'][tool_name] = {'error': str(result)}
        
        # Aggregate data from all tools in this category
        category_results['aggregated_data'] = self._aggregate_category_data(
            category, category_results['tool_results']
        )
        
        category_results['execution_time'] = asyncio.get_event_loop().time() - start_time
        
        logger.info(f"Completed {category} in {category_results['execution_time']:.2f} seconds")
        return category_results
    
    async def _execute_single_tool(self, tool_name: str, category: str) -> Dict[str, Any]:
        """Execute a single reconnaissance tool"""
        logger.info(f"Executing {tool_name}")
        
        try:
            # Route to appropriate tool execution method
            if tool_name == 'subfinder':
                return await self._run_subfinder()
            elif tool_name == 'amass':
                return await self._run_amass()
            elif tool_name == 'assetfinder':
                return await self._run_assetfinder()
            elif tool_name == 'httpx':
                return await self._run_httpx()
            elif tool_name == 'whatweb':
                return await self._run_whatweb()
            elif tool_name == 'nmap':
                return await self._run_nmap()
            elif tool_name == 'nuclei':
                return await self._run_nuclei()
            elif tool_name == 'gobuster':
                return await self._run_gobuster()
            elif tool_name == 'theharvester':
                return await self._run_theharvester()
            else:
                logger.warning(f"No execution method for tool: {tool_name}")
                return {'error': f'No execution method for {tool_name}'}
                
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return {'error': str(e)}
    
    async def _run_subfinder(self) -> Dict[str, Any]:
        """Execute subfinder for subdomain enumeration"""
        command = ['subfinder', '-d', self.target, '-silent', '-o', '-']
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = [line.strip() for line in stdout.decode().split('\n') if line.strip()]
                return {
                    'tool': 'subfinder',
                    'success': True,
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {
                    'tool': 'subfinder',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'subfinder',
                'success': False,
                'error': str(e)
            }
    
    async def _run_amass(self) -> Dict[str, Any]:
        """Execute amass for comprehensive subdomain enumeration"""
        command = ['amass', 'enum', '-d', self.target, '-silent']
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = [line.strip() for line in stdout.decode().split('\n') if line.strip()]
                return {
                    'tool': 'amass',
                    'success': True,
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {
                    'tool': 'amass',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'amass',
                'success': False,
                'error': str(e)
            }
    
    async def _run_assetfinder(self) -> Dict[str, Any]:
        """Execute assetfinder for subdomain discovery"""
        command = ['assetfinder', self.target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = [line.strip() for line in stdout.decode().split('\n') if line.strip()]
                return {
                    'tool': 'assetfinder',
                    'success': True,
                    'subdomains': subdomains,
                    'count': len(subdomains)
                }
            else:
                return {
                    'tool': 'assetfinder',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'assetfinder',
                'success': False,
                'error': str(e)
            }
    
    async def _run_httpx(self) -> Dict[str, Any]:
        """Execute httpx for web service discovery"""
        # For httpx, we need a list of targets
        if self.scan_context.target_type == 'domain':
            targets = [self.target, f"www.{self.target}"]
        else:
            targets = [self.target]
        
        # Create temporary file with targets
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for target in targets:
                f.write(f"{target}\n")
            temp_file = f.name
        
        try:
            command = ['httpx', '-l', temp_file, '-silent', '-json']
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                live_hosts = []
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        try:
                            host_data = json.loads(line)
                            live_hosts.append(host_data)
                        except json.JSONDecodeError:
                            continue
                
                return {
                    'tool': 'httpx',
                    'success': True,
                    'live_hosts': live_hosts,
                    'count': len(live_hosts)
                }
            else:
                return {
                    'tool': 'httpx',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'httpx',
                'success': False,
                'error': str(e)
            }
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_file)
            except:
                pass
    
    async def _run_whatweb(self) -> Dict[str, Any]:
        """Execute whatweb for technology detection"""
        command = ['whatweb', '--color=never', '--no-errors', self.target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                # Parse whatweb output (simplified)
                technologies = []
                if '[' in output and ']' in output:
                    tech_section = output.split('[')[1].split(']')[0]
                    technologies = [tech.strip() for tech in tech_section.split(',')]
                
                return {
                    'tool': 'whatweb',
                    'success': True,
                    'technologies': technologies,
                    'raw_output': output
                }
            else:
                return {
                    'tool': 'whatweb',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'whatweb',
                'success': False,
                'error': str(e)
            }
    
    async def _run_nmap(self) -> Dict[str, Any]:
        """Execute nmap for network scanning"""
        # Adjust nmap command based on target type and scan context
        if self.scan_context.stealth_mode:
            command = ['nmap', '-sS', '-T2', '--top-ports', '100', self.target]
        elif self.scan_context.time_constraint == 'fast':
            command = ['nmap', '-sS', '-T4', '--top-ports', '100', self.target]
        else:
            command = ['nmap', '-sS', '-sV', '-T3', '--top-ports', '1000', self.target]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                # Parse nmap output (simplified)
                open_ports = []
                for line in output.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        port_info = line.strip()
                        open_ports.append(port_info)
                
                return {
                    'tool': 'nmap',
                    'success': True,
                    'open_ports': open_ports,
                    'raw_output': output
                }
            else:
                return {
                    'tool': 'nmap',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'nmap',
                'success': False,
                'error': str(e)
            }
    
    async def _run_nuclei(self) -> Dict[str, Any]:
        """Execute nuclei for vulnerability scanning"""
        command = ['nuclei', '-target', self.target, '-silent', '-json']
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            vulnerabilities = []
            for line in stdout.decode().split('\n'):
                if line.strip():
                    try:
                        vuln_data = json.loads(line)
                        vulnerabilities.append(vuln_data)
                    except json.JSONDecodeError:
                        continue
            
            return {
                'tool': 'nuclei',
                'success': True,
                'vulnerabilities': vulnerabilities,
                'count': len(vulnerabilities)
            }
                
        except Exception as e:
            return {
                'tool': 'nuclei',
                'success': False,
                'error': str(e)
            }
    
    async def _run_gobuster(self) -> Dict[str, Any]:
        """Execute gobuster for directory enumeration"""
        # Use a basic wordlist
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if not os.path.exists(wordlist):
            wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'
        
        if not os.path.exists(wordlist):
            return {
                'tool': 'gobuster',
                'success': False,
                'error': 'No wordlist found'
            }
        
        target_url = self.target if self.target.startswith('http') else f"http://{self.target}"
        command = ['gobuster', 'dir', '-u', target_url, '-w', wordlist, '-q']
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                directories = []
                for line in stdout.decode().split('\n'):
                    if line.strip() and not line.startswith('='):
                        directories.append(line.strip())
                
                return {
                    'tool': 'gobuster',
                    'success': True,
                    'directories': directories,
                    'count': len(directories)
                }
            else:
                return {
                    'tool': 'gobuster',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'gobuster',
                'success': False,
                'error': str(e)
            }
    
    async def _run_theharvester(self) -> Dict[str, Any]:
        """Execute theharvester for OSINT gathering"""
        command = ['theharvester', '-d', self.target, '-b', 'google,bing,yahoo', '-l', '100']
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                # Parse theharvester output (simplified)
                emails = []
                hosts = []
                
                for line in output.split('\n'):
                    if '@' in line and self.target in line:
                        emails.append(line.strip())
                    elif self.target in line and not line.startswith('['):
                        hosts.append(line.strip())
                
                return {
                    'tool': 'theharvester',
                    'success': True,
                    'emails': list(set(emails)),
                    'hosts': list(set(hosts)),
                    'raw_output': output
                }
            else:
                return {
                    'tool': 'theharvester',
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'tool': 'theharvester',
                'success': False,
                'error': str(e)
            }
    
    def _aggregate_category_data(self, category: str, tool_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate data from all tools in a category"""
        aggregated = {
            'category': category,
            'successful_tools': 0,
            'failed_tools': 0,
            'total_items': 0
        }
        
        if category == 'subdomain_enumeration':
            all_subdomains = set()
            for tool_name, result in tool_results.items():
                if result.get('success') and 'subdomains' in result:
                    all_subdomains.update(result['subdomains'])
                    aggregated['successful_tools'] += 1
                else:
                    aggregated['failed_tools'] += 1
            
            aggregated['subdomains'] = list(all_subdomains)
            aggregated['total_items'] = len(all_subdomains)
        
        elif category == 'web_discovery':
            all_hosts = []
            all_technologies = []
            for tool_name, result in tool_results.items():
                if result.get('success'):
                    if 'live_hosts' in result:
                        all_hosts.extend(result['live_hosts'])
                    if 'technologies' in result:
                        all_technologies.extend(result['technologies'])
                    aggregated['successful_tools'] += 1
                else:
                    aggregated['failed_tools'] += 1
            
            aggregated['live_hosts'] = all_hosts
            aggregated['technologies'] = list(set(all_technologies))
            aggregated['total_items'] = len(all_hosts)
        
        elif category == 'vulnerability_scanning':
            all_vulnerabilities = []
            for tool_name, result in tool_results.items():
                if result.get('success') and 'vulnerabilities' in result:
                    all_vulnerabilities.extend(result['vulnerabilities'])
                    aggregated['successful_tools'] += 1
                else:
                    aggregated['failed_tools'] += 1
            
            aggregated['vulnerabilities'] = all_vulnerabilities
            aggregated['total_items'] = len(all_vulnerabilities)
        
        # Add more category-specific aggregation as needed
        
        return aggregated
    
    def _aggregate_results(self, execution_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from all categories"""
        aggregated = {
            'total_subdomains': 0,
            'total_live_hosts': 0,
            'total_vulnerabilities': 0,
            'total_directories': 0,
            'total_emails': 0,
            'technologies_detected': [],
            'open_ports': [],
            'summary_by_category': {}
        }
        
        for category, results in execution_results.items():
            if 'aggregated_data' in results:
                data = results['aggregated_data']
                aggregated['summary_by_category'][category] = data
                
                # Aggregate specific data types
                if 'subdomains' in data:
                    aggregated['total_subdomains'] += len(data['subdomains'])
                
                if 'live_hosts' in data:
                    aggregated['total_live_hosts'] += len(data['live_hosts'])
                
                if 'vulnerabilities' in data:
                    aggregated['total_vulnerabilities'] += len(data['vulnerabilities'])
                
                if 'technologies' in data:
                    aggregated['technologies_detected'].extend(data['technologies'])
        
        # Remove duplicates
        aggregated['technologies_detected'] = list(set(aggregated['technologies_detected']))
        
        return aggregated
    
    async def _ai_analyze_results(self, aggregated_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to analyze the reconnaissance results"""
        if not self.llm_client:
            return {'error': 'No LLM client available'}
        
        analysis_prompt = f"""
Analyze the following reconnaissance results for target {self.target}:

RESULTS SUMMARY:
- Total subdomains found: {aggregated_results.get('total_subdomains', 0)}
- Total live hosts: {aggregated_results.get('total_live_hosts', 0)}
- Total vulnerabilities: {aggregated_results.get('total_vulnerabilities', 0)}
- Technologies detected: {', '.join(aggregated_results.get('technologies_detected', []))}

DETAILED RESULTS:
{json.dumps(aggregated_results, indent=2)}

Please provide:
1. Risk assessment (High/Medium/Low)
2. Key findings and concerns
3. Recommended next steps
4. Potential attack vectors
5. Security recommendations

Respond in JSON format:
{{
    "risk_level": "High/Medium/Low",
    "key_findings": ["finding1", "finding2"],
    "security_concerns": ["concern1", "concern2"],
    "recommended_actions": ["action1", "action2"],
    "attack_vectors": ["vector1", "vector2"],
    "overall_assessment": "Brief summary"
}}
"""
        
        try:
            ai_response = await self.ai_selector._query_llm(analysis_prompt)
            
            # Try to parse JSON response
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {'raw_analysis': ai_response}
                
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {'error': str(e)}
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the reconnaissance results"""
        summary = {
            'target': self.target,
            'scan_completed': True,
            'total_tools_used': 0,
            'successful_tools': 0,
            'failed_tools': 0,
            'key_metrics': {},
            'recommendations': []
        }
        
        # Count tools
        for category_results in results['execution_results'].values():
            summary['total_tools_used'] += len(category_results['tools_executed'])
            for tool_result in category_results['tool_results'].values():
                if tool_result.get('success'):
                    summary['successful_tools'] += 1
                else:
                    summary['failed_tools'] += 1
        
        # Extract key metrics
        aggregated = results.get('aggregated_results', {})
        summary['key_metrics'] = {
            'subdomains_found': aggregated.get('total_subdomains', 0),
            'live_hosts_found': aggregated.get('total_live_hosts', 0),
            'vulnerabilities_found': aggregated.get('total_vulnerabilities', 0),
            'technologies_detected': len(aggregated.get('technologies_detected', []))
        }
        
        # Generate basic recommendations
        if summary['key_metrics']['vulnerabilities_found'] > 0:
            summary['recommendations'].append('Investigate and remediate identified vulnerabilities')
        
        if summary['key_metrics']['subdomains_found'] > 10:
            summary['recommendations'].append('Review subdomain security and reduce attack surface')
        
        if len(aggregated.get('technologies_detected', [])) > 0:
            summary['recommendations'].append('Ensure all detected technologies are up to date')
        
        return summary