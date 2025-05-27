"""
AI-Powered Tool Selection Module

This module uses LLM to intelligently select the most appropriate security tools
based on the target characteristics, scan objectives, and available resources.
The AI analyzes the context and makes informed decisions about tool selection.
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from app.logger import logger


@dataclass
class ToolInfo:
    """Information about a security tool"""
    name: str
    category: str
    description: str
    strengths: List[str]
    weaknesses: List[str]
    use_cases: List[str]
    speed: str  # fast, medium, slow
    accuracy: str  # high, medium, low
    stealth: str  # high, medium, low
    requirements: List[str]
    available: bool = False


@dataclass
class ScanContext:
    """Context information for the scan"""
    target: str
    target_type: str  # domain, ip, url, network
    scan_mode: str  # reconnaissance, vulnerability-scan, web-scan, fuzzing, comprehensive
    passive_only: bool = False
    deep_scan: bool = False
    stealth_mode: bool = False
    time_constraint: str = "normal"  # fast, normal, thorough
    resources_available: Dict[str, Any] = None


class AIToolSelector:
    """
    AI-powered tool selection system that uses LLM to make intelligent
    decisions about which security tools to use for specific scenarios.
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.available_tools = self._initialize_tool_database()
        self.selection_history = []
    
    def _initialize_tool_database(self) -> Dict[str, ToolInfo]:
        """Initialize the database of available security tools"""
        tools = {
            # Subdomain Enumeration Tools
            'subfinder': ToolInfo(
                name='subfinder',
                category='subdomain_enumeration',
                description='Fast passive subdomain discovery tool',
                strengths=['Very fast', 'Passive', 'Multiple sources', 'Reliable'],
                weaknesses=['Limited to passive sources', 'May miss some subdomains'],
                use_cases=['Quick reconnaissance', 'Passive scanning', 'Bug bounty'],
                speed='fast',
                accuracy='high',
                stealth='high',
                requirements=['internet_connection']
            ),
            
            'amass': ToolInfo(
                name='amass',
                category='subdomain_enumeration',
                description='Comprehensive subdomain enumeration with active and passive techniques',
                strengths=['Very comprehensive', 'Active + passive', 'DNS zone walking', 'Certificate transparency'],
                weaknesses=['Slower than other tools', 'Can be noisy', 'Resource intensive'],
                use_cases=['Thorough reconnaissance', 'Professional assessments', 'Deep scanning'],
                speed='slow',
                accuracy='high',
                stealth='medium',
                requirements=['internet_connection', 'dns_access']
            ),
            
            'assetfinder': ToolInfo(
                name='assetfinder',
                category='subdomain_enumeration',
                description='Simple and fast subdomain finder',
                strengths=['Simple to use', 'Fast', 'Good for quick scans'],
                weaknesses=['Limited sources', 'Less comprehensive than others'],
                use_cases=['Quick checks', 'Initial reconnaissance', 'Lightweight scanning'],
                speed='fast',
                accuracy='medium',
                stealth='high',
                requirements=['internet_connection']
            ),
            
            # Web Discovery Tools
            'httpx': ToolInfo(
                name='httpx',
                category='web_discovery',
                description='Fast HTTP toolkit for probing web services',
                strengths=['Very fast', 'HTTP/HTTPS probing', 'Technology detection', 'Customizable'],
                weaknesses=['Limited vulnerability detection', 'Requires active probing'],
                use_cases=['Live host detection', 'Service enumeration', 'Technology fingerprinting'],
                speed='fast',
                accuracy='high',
                stealth='medium',
                requirements=['network_access']
            ),
            
            'whatweb': ToolInfo(
                name='whatweb',
                category='web_discovery',
                description='Web application fingerprinting tool',
                strengths=['Extensive plugin system', 'Technology detection', 'Detailed fingerprinting'],
                weaknesses=['Can be slow with aggressive modes', 'May trigger WAF'],
                use_cases=['Technology stack identification', 'CMS detection', 'Framework identification'],
                speed='medium',
                accuracy='high',
                stealth='medium',
                requirements=['network_access']
            ),
            
            'wafw00f': ToolInfo(
                name='wafw00f',
                category='web_discovery',
                description='Web Application Firewall detection tool',
                strengths=['WAF detection', 'Multiple detection methods', 'Accurate'],
                weaknesses=['Limited to WAF detection', 'Can trigger security alerts'],
                use_cases=['WAF identification', 'Security assessment', 'Evasion planning'],
                speed='fast',
                accuracy='high',
                stealth='low',
                requirements=['network_access']
            ),
            
            # Network Scanning Tools
            'nmap': ToolInfo(
                name='nmap',
                category='network_scanning',
                description='Network discovery and security auditing tool',
                strengths=['Industry standard', 'Comprehensive', 'Scriptable', 'OS detection'],
                weaknesses=['Can be noisy', 'May trigger IDS', 'Slower for large ranges'],
                use_cases=['Port scanning', 'Service enumeration', 'OS detection', 'Vulnerability scanning'],
                speed='medium',
                accuracy='high',
                stealth='low',
                requirements=['network_access']
            ),
            
            'masscan': ToolInfo(
                name='masscan',
                category='network_scanning',
                description='High-speed port scanner',
                strengths=['Extremely fast', 'Internet-scale scanning', 'Asynchronous'],
                weaknesses=['Limited service detection', 'Can overwhelm targets', 'Less accurate'],
                use_cases=['Large-scale scanning', 'Initial port discovery', 'Fast reconnaissance'],
                speed='fast',
                accuracy='medium',
                stealth='low',
                requirements=['network_access', 'root_privileges']
            ),
            
            # Vulnerability Scanning Tools
            'nuclei': ToolInfo(
                name='nuclei',
                category='vulnerability_scanning',
                description='Template-based vulnerability scanner',
                strengths=['Template-based', 'Fast', 'Community templates', 'Low false positives'],
                weaknesses=['Limited to known vulnerabilities', 'Template dependent'],
                use_cases=['Vulnerability assessment', 'Security testing', 'Compliance checking'],
                speed='fast',
                accuracy='high',
                stealth='medium',
                requirements=['network_access', 'templates']
            ),
            
            'nikto': ToolInfo(
                name='nikto',
                category='vulnerability_scanning',
                description='Web server vulnerability scanner',
                strengths=['Comprehensive web checks', 'Plugin system', 'Detailed reports'],
                weaknesses=['Can be slow', 'Noisy', 'May trigger WAF'],
                use_cases=['Web server assessment', 'Configuration testing', 'Vulnerability discovery'],
                speed='slow',
                accuracy='high',
                stealth='low',
                requirements=['network_access']
            ),
            
            # Directory/File Enumeration Tools
            'gobuster': ToolInfo(
                name='gobuster',
                category='directory_enumeration',
                description='Fast directory and file brute-forcer',
                strengths=['Very fast', 'Multiple modes', 'Customizable', 'Go-based performance'],
                weaknesses=['Brute force approach', 'Wordlist dependent', 'Can be noisy'],
                use_cases=['Directory discovery', 'File enumeration', 'Hidden content discovery'],
                speed='fast',
                accuracy='medium',
                stealth='low',
                requirements=['network_access', 'wordlists']
            ),
            
            'ffuf': ToolInfo(
                name='ffuf',
                category='directory_enumeration',
                description='Fast web fuzzer',
                strengths=['Extremely fast', 'Flexible', 'Multiple fuzzing modes', 'JSON output'],
                weaknesses=['Can overwhelm servers', 'Requires tuning', 'May cause DoS'],
                use_cases=['Web fuzzing', 'Parameter discovery', 'Content discovery'],
                speed='fast',
                accuracy='medium',
                stealth='low',
                requirements=['network_access', 'wordlists']
            ),
            
            # OSINT Tools
            'theharvester': ToolInfo(
                name='theharvester',
                category='osint',
                description='Email and subdomain harvesting tool',
                strengths=['Multiple sources', 'Email discovery', 'Passive', 'OSINT focused'],
                weaknesses=['Source dependent', 'Rate limited', 'May have outdated APIs'],
                use_cases=['Email harvesting', 'OSINT gathering', 'Social engineering prep'],
                speed='medium',
                accuracy='medium',
                stealth='high',
                requirements=['internet_connection', 'api_keys']
            )
        }
        
        return tools
    
    async def select_tools_with_ai(self, context: ScanContext, available_tools: Dict[str, bool]) -> Dict[str, List[str]]:
        """
        Use AI to select the most appropriate tools for the given context
        
        Args:
            context: Scan context with target info and requirements
            available_tools: Dictionary of tool availability
            
        Returns:
            Dictionary with selected tools for each category
        """
        logger.info(f"AI tool selection for target: {context.target}")
        
        # Filter available tools
        available_tool_info = {}
        for tool_name, is_available in available_tools.items():
            if is_available and tool_name in self.available_tools:
                available_tool_info[tool_name] = self.available_tools[tool_name]
        
        # Prepare context for AI
        ai_prompt = self._create_tool_selection_prompt(context, available_tool_info)
        
        # Get AI decision
        if self.llm_client:
            try:
                ai_response = await self._query_llm(ai_prompt)
                selected_tools = self._parse_ai_response(ai_response)
            except Exception as e:
                logger.error(f"AI tool selection failed: {e}")
                # Fallback to rule-based selection
                selected_tools = self._fallback_tool_selection(context, available_tool_info)
        else:
            logger.warning("No LLM client available, using fallback selection")
            selected_tools = self._fallback_tool_selection(context, available_tool_info)
        
        # Log selection for learning
        self.selection_history.append({
            'context': context,
            'available_tools': list(available_tool_info.keys()),
            'selected_tools': selected_tools,
            'timestamp': asyncio.get_event_loop().time()
        })
        
        logger.info(f"AI selected tools: {selected_tools}")
        return selected_tools
    
    def _create_tool_selection_prompt(self, context: ScanContext, available_tools: Dict[str, ToolInfo]) -> str:
        """Create a detailed prompt for the AI to select appropriate tools"""
        
        prompt = f"""
You are an expert cybersecurity professional tasked with selecting the most appropriate security tools for a reconnaissance and vulnerability assessment.

TARGET INFORMATION:
- Target: {context.target}
- Target Type: {context.target_type}
- Scan Mode: {context.scan_mode}
- Passive Only: {context.passive_only}
- Deep Scan: {context.deep_scan}
- Stealth Mode: {context.stealth_mode}
- Time Constraint: {context.time_constraint}

AVAILABLE TOOLS:
"""
        
        # Add tool information
        for tool_name, tool_info in available_tools.items():
            prompt += f"""
{tool_name.upper()}:
- Category: {tool_info.category}
- Description: {tool_info.description}
- Strengths: {', '.join(tool_info.strengths)}
- Weaknesses: {', '.join(tool_info.weaknesses)}
- Speed: {tool_info.speed}
- Accuracy: {tool_info.accuracy}
- Stealth: {tool_info.stealth}
- Use Cases: {', '.join(tool_info.use_cases)}
"""
        
        prompt += f"""

SELECTION CRITERIA:
1. Consider the target type and scan objectives
2. Respect the passive-only constraint if specified
3. Balance speed vs thoroughness based on time constraints
4. Consider stealth requirements
5. Optimize for the specific scan mode
6. Select complementary tools that work well together
7. Avoid redundant tools unless they provide different perspectives

TASK:
Select the most appropriate tools for each category. Consider the trade-offs between speed, accuracy, and stealth. 

For each category, select 1-3 tools that best fit the requirements:
- subdomain_enumeration: Tools for finding subdomains
- web_discovery: Tools for web service discovery and fingerprinting
- network_scanning: Tools for port and service scanning
- vulnerability_scanning: Tools for finding vulnerabilities
- directory_enumeration: Tools for finding hidden directories/files
- osint: Tools for passive information gathering

Respond in JSON format:
{{
    "reasoning": "Brief explanation of your selection strategy",
    "selected_tools": {{
        "subdomain_enumeration": ["tool1", "tool2"],
        "web_discovery": ["tool1"],
        "network_scanning": ["tool1"],
        "vulnerability_scanning": ["tool1", "tool2"],
        "directory_enumeration": ["tool1"],
        "osint": ["tool1"]
    }},
    "execution_order": ["category1", "category2", "category3"],
    "special_considerations": "Any special notes or warnings"
}}

Only select tools that are in the AVAILABLE TOOLS list above.
"""
        
        return prompt
    
    async def _query_llm(self, prompt: str) -> str:
        """Query the LLM with the tool selection prompt"""
        # This would integrate with your LLM client
        # For now, return a placeholder response
        if hasattr(self.llm_client, 'chat') or hasattr(self.llm_client, 'complete'):
            try:
                # Adapt this to your specific LLM client interface
                if hasattr(self.llm_client, 'chat'):
                    response = await self.llm_client.chat(prompt)
                else:
                    response = await self.llm_client.complete(prompt)
                return response
            except Exception as e:
                logger.error(f"LLM query failed: {e}")
                raise
        else:
            raise Exception("LLM client not properly configured")
    
    def _parse_ai_response(self, response: str) -> Dict[str, List[str]]:
        """Parse the AI response and extract tool selections"""
        try:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                parsed = json.loads(json_str)
                
                if 'selected_tools' in parsed:
                    return parsed['selected_tools']
            
            # If JSON parsing fails, try to extract tool names
            logger.warning("Failed to parse AI response as JSON, attempting text parsing")
            return self._extract_tools_from_text(response)
            
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            raise
    
    def _extract_tools_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract tool names from free-form text response"""
        # Simple text parsing as fallback
        categories = {
            'subdomain_enumeration': [],
            'web_discovery': [],
            'network_scanning': [],
            'vulnerability_scanning': [],
            'directory_enumeration': [],
            'osint': []
        }
        
        # Look for tool names in the text
        for tool_name in self.available_tools.keys():
            if tool_name.lower() in text.lower():
                category = self.available_tools[tool_name].category
                if category in categories:
                    categories[category].append(tool_name)
        
        return categories
    
    def _fallback_tool_selection(self, context: ScanContext, available_tools: Dict[str, ToolInfo]) -> Dict[str, List[str]]:
        """Fallback rule-based tool selection when AI is not available"""
        logger.info("Using fallback rule-based tool selection")
        
        selected = {
            'subdomain_enumeration': [],
            'web_discovery': [],
            'network_scanning': [],
            'vulnerability_scanning': [],
            'directory_enumeration': [],
            'osint': []
        }
        
        # Group tools by category
        tools_by_category = {}
        for tool_name, tool_info in available_tools.items():
            category = tool_info.category
            if category not in tools_by_category:
                tools_by_category[category] = []
            tools_by_category[category].append((tool_name, tool_info))
        
        # Select tools based on context
        for category, tools in tools_by_category.items():
            if context.passive_only:
                # Prefer high stealth tools
                tools.sort(key=lambda x: (x[1].stealth == 'high', x[1].speed == 'fast'), reverse=True)
            elif context.time_constraint == 'fast':
                # Prefer fast tools
                tools.sort(key=lambda x: (x[1].speed == 'fast', x[1].accuracy == 'high'), reverse=True)
            elif context.deep_scan:
                # Prefer comprehensive tools
                tools.sort(key=lambda x: (x[1].accuracy == 'high', x[1].speed != 'slow'), reverse=True)
            else:
                # Balanced selection
                tools.sort(key=lambda x: (x[1].accuracy == 'high', x[1].speed == 'medium'), reverse=True)
            
            # Select top tools (limit based on scan type)
            max_tools = 3 if context.deep_scan else 2 if context.scan_mode == 'comprehensive' else 1
            selected[category] = [tool[0] for tool in tools[:max_tools]]
        
        return selected
    
    def get_tool_info(self, tool_name: str) -> Optional[ToolInfo]:
        """Get detailed information about a specific tool"""
        return self.available_tools.get(tool_name)
    
    def get_tools_by_category(self, category: str) -> List[ToolInfo]:
        """Get all tools in a specific category"""
        return [tool for tool in self.available_tools.values() if tool.category == category]
    
    def update_tool_availability(self, tool_availability: Dict[str, bool]):
        """Update the availability status of tools"""
        for tool_name, available in tool_availability.items():
            if tool_name in self.available_tools:
                self.available_tools[tool_name].available = available
    
    def get_selection_history(self) -> List[Dict]:
        """Get the history of tool selections for analysis"""
        return self.selection_history