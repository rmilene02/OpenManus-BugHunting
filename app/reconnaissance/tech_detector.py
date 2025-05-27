"""
Technology Detection Module

This module provides functionality for detecting technologies, frameworks,
and services used by web applications and servers.
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Set
from pathlib import Path
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup

from app.logger import logger


class TechnologyDetector:
    """Technology detection and fingerprinting engine"""
    
    def __init__(self, target: str, output_dir: str = "./results"):
        """
        Initialize technology detector
        
        Args:
            target: Target URL or domain
            output_dir: Directory to save results
        """
        self.target = target
        if not target.startswith(('http://', 'https://')):
            self.target = f"https://{target}"
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage
        self.detected_technologies = {
            'web_servers': set(),
            'programming_languages': set(),
            'frameworks': set(),
            'cms': set(),
            'databases': set(),
            'cdn': set(),
            'analytics': set(),
            'security': set(),
            'javascript_libraries': set(),
            'operating_systems': set()
        }
        
        # Technology signatures
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """Load technology detection signatures"""
        return {
            'headers': {
                'Server': {
                    'Apache': r'Apache/[\d.]+',
                    'Nginx': r'nginx/[\d.]+',
                    'IIS': r'Microsoft-IIS/[\d.]+',
                    'LiteSpeed': r'LiteSpeed',
                    'Cloudflare': r'cloudflare'
                },
                'X-Powered-By': {
                    'PHP': r'PHP/[\d.]+',
                    'ASP.NET': r'ASP\.NET',
                    'Express': r'Express',
                    'Django': r'Django'
                },
                'X-Generator': {
                    'WordPress': r'WordPress [\d.]+',
                    'Drupal': r'Drupal [\d.]+',
                    'Joomla': r'Joomla! [\d.]+'
                }
            },
            'html_patterns': {
                'WordPress': [
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json'
                ],
                'Drupal': [
                    r'/sites/default/',
                    r'Drupal.settings',
                    r'/modules/'
                ],
                'Joomla': [
                    r'/components/',
                    r'/templates/',
                    r'Joomla!'
                ],
                'React': [
                    r'react',
                    r'__REACT_DEVTOOLS_GLOBAL_HOOK__'
                ],
                'Vue.js': [
                    r'Vue\.js',
                    r'vue-'
                ],
                'Angular': [
                    r'ng-',
                    r'angular'
                ],
                'jQuery': [
                    r'jquery',
                    r'jQuery'
                ],
                'Bootstrap': [
                    r'bootstrap',
                    r'Bootstrap'
                ]
            },
            'javascript_patterns': {
                'Google Analytics': [
                    r'google-analytics\.com',
                    r'gtag\(',
                    r'ga\('
                ],
                'Google Tag Manager': [
                    r'googletagmanager\.com'
                ],
                'Facebook Pixel': [
                    r'facebook\.net/tr',
                    r'fbq\('
                ]
            }
        }
    
    async def detect_technologies(self, deep_scan: bool = False) -> Dict:
        """
        Perform technology detection
        
        Args:
            deep_scan: If True, perform more thorough detection
            
        Returns:
            Dictionary containing detected technologies
        """
        logger.info(f"Starting technology detection for: {self.target}")
        
        try:
            # Perform HTTP request
            response = await self._make_request()
            if not response:
                return {'error': 'Failed to connect to target'}
            
            # Analyze HTTP headers
            await self._analyze_headers(response.headers)
            
            # Analyze HTML content
            await self._analyze_html_content(response.text)
            
            # Analyze JavaScript
            await self._analyze_javascript(response.text)
            
            # Additional deep scan techniques
            if deep_scan:
                await self._deep_scan_analysis()
            
            # Save results
            await self._save_results()
            
            return self._format_results()
            
        except Exception as e:
            logger.error(f"Technology detection failed: {e}")
            return {'error': str(e)}
    
    async def _make_request(self) -> Optional[requests.Response]:
        """Make HTTP request to target"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(self.target, headers=headers, timeout=10, verify=False)
            response.raise_for_status()
            return response
            
        except Exception as e:
            logger.warning(f"Failed to make request to {self.target}: {e}")
            return None
    
    async def _analyze_headers(self, headers: Dict):
        """Analyze HTTP response headers for technology indicators"""
        logger.info("Analyzing HTTP headers...")
        
        for header_name, patterns in self.signatures['headers'].items():
            if header_name in headers:
                header_value = headers[header_name]
                
                for tech, pattern in patterns.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        if 'server' in tech.lower() or tech in ['Apache', 'Nginx', 'IIS', 'LiteSpeed']:
                            self.detected_technologies['web_servers'].add(tech)
                        elif tech in ['PHP', 'ASP.NET', 'Django']:
                            self.detected_technologies['programming_languages'].add(tech)
                        elif tech in ['WordPress', 'Drupal', 'Joomla']:
                            self.detected_technologies['cms'].add(tech)
                        elif tech == 'Cloudflare':
                            self.detected_technologies['cdn'].add(tech)
        
        # Check for additional security headers
        security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
        for header in security_headers:
            if header in headers:
                self.detected_technologies['security'].add(f"{header} Header")
    
    async def _analyze_html_content(self, html_content: str):
        """Analyze HTML content for technology indicators"""
        logger.info("Analyzing HTML content...")
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            content = meta_generator.get('content')
            if 'WordPress' in content:
                self.detected_technologies['cms'].add('WordPress')
            elif 'Drupal' in content:
                self.detected_technologies['cms'].add('Drupal')
            elif 'Joomla' in content:
                self.detected_technologies['cms'].add('Joomla')
        
        # Check for framework patterns in HTML
        for tech, patterns in self.signatures['html_patterns'].items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    if tech in ['WordPress', 'Drupal', 'Joomla']:
                        self.detected_technologies['cms'].add(tech)
                    elif tech in ['React', 'Vue.js', 'Angular']:
                        self.detected_technologies['frameworks'].add(tech)
                    elif tech in ['jQuery', 'Bootstrap']:
                        self.detected_technologies['javascript_libraries'].add(tech)
        
        # Check script and link tags
        scripts = soup.find_all('script', src=True)
        links = soup.find_all('link', href=True)
        
        for element in scripts + links:
            src = element.get('src') or element.get('href', '')
            
            if 'jquery' in src.lower():
                self.detected_technologies['javascript_libraries'].add('jQuery')
            if 'bootstrap' in src.lower():
                self.detected_technologies['javascript_libraries'].add('Bootstrap')
            if 'react' in src.lower():
                self.detected_technologies['frameworks'].add('React')
            if 'vue' in src.lower():
                self.detected_technologies['frameworks'].add('Vue.js')
            if 'angular' in src.lower():
                self.detected_technologies['frameworks'].add('Angular')
    
    async def _analyze_javascript(self, html_content: str):
        """Analyze JavaScript for analytics and tracking technologies"""
        logger.info("Analyzing JavaScript...")
        
        for tech, patterns in self.signatures['javascript_patterns'].items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    self.detected_technologies['analytics'].add(tech)
    
    async def _deep_scan_analysis(self):
        """Perform additional deep scan analysis"""
        logger.info("Performing deep scan analysis...")
        
        # Check common paths for technology indicators
        common_paths = [
            '/robots.txt',
            '/sitemap.xml',
            '/wp-admin/',
            '/admin/',
            '/.well-known/',
            '/api/',
            '/graphql'
        ]
        
        for path in common_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                response = requests.head(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    if 'wp-admin' in path:
                        self.detected_technologies['cms'].add('WordPress')
                    elif 'graphql' in path:
                        self.detected_technologies['frameworks'].add('GraphQL')
                    elif 'api' in path:
                        self.detected_technologies['frameworks'].add('REST API')
                        
            except Exception:
                continue
    
    async def _save_results(self):
        """Save detection results to file"""
        target_name = self.target.replace('https://', '').replace('http://', '').replace('/', '_')
        results_file = self.output_dir / f"tech_detection_{target_name}.json"
        
        # Convert sets to lists for JSON serialization
        serializable_results = {}
        for key, value in self.detected_technologies.items():
            serializable_results[key] = list(value)
        
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"Technology detection results saved to: {results_file}")
    
    def _format_results(self) -> Dict:
        """Format results for return"""
        total_technologies = sum(len(techs) for techs in self.detected_technologies.values())
        
        return {
            'target': self.target,
            'total_technologies': total_technologies,
            'categories': {
                category: len(techs) for category, techs in self.detected_technologies.items()
            },
            'technologies': {
                category: list(techs) for category, techs in self.detected_technologies.items()
            },
            'status': 'completed'
        }
    
    def get_web_servers(self) -> List[str]:
        """Get detected web servers"""
        return list(self.detected_technologies['web_servers'])
    
    def get_cms(self) -> List[str]:
        """Get detected CMS platforms"""
        return list(self.detected_technologies['cms'])
    
    def get_frameworks(self) -> List[str]:
        """Get detected frameworks"""
        return list(self.detected_technologies['frameworks'])
    
    def get_all_technologies(self) -> Dict[str, List[str]]:
        """Get all detected technologies by category"""
        return {
            category: list(techs) for category, techs in self.detected_technologies.items()
        }


# Example usage
async def main():
    """Example usage of TechnologyDetector"""
    detector = TechnologyDetector("https://example.com", "./test_results")
    results = await detector.detect_technologies(deep_scan=True)
    
    print("Technology Detection Results:")
    print(f"Total technologies: {results['total_technologies']}")
    
    for category, count in results['categories'].items():
        if count > 0:
            print(f"{category}: {count}")
            for tech in results['technologies'][category]:
                print(f"  - {tech}")


if __name__ == "__main__":
    asyncio.run(main())