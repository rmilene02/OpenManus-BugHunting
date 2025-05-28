"""
Security Assessment Orchestrator

This module coordinates and orchestrates security assessments using AI-powered
tool selection and execution. It integrates all security testing modules and
provides a unified interface for comprehensive security assessments.
"""

import asyncio
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from app.logger import logger
from app.core.ai_tool_selector import AIToolSelector, ScanContext
from app.reconnaissance.ai_recon_engine import AIReconEngine
from app.scanner.web_scanner import WebVulnerabilityScanner
from app.fuzzer.web_fuzzer import WebFuzzer
from app.exploits.payload_generator import PayloadGenerator
from app.reporting.report_generator import ReportGenerator


class SecurityOrchestrator:
    """
    Main orchestrator for security assessments that coordinates all security
    testing modules using AI-powered decision making.
    """

    def __init__(self, llm_client=None, config: Dict[str, Any] = None):
        self.llm_client = llm_client
        self.config = config or {}

        # Initialize AI tool selector
        self.ai_selector = AIToolSelector(llm_client)

        # Initialize modules
        self.recon_engine = None
        self.web_scanner = None
        self.fuzzer = None
        self.payload_generator = PayloadGenerator()
        self.report_generator = ReportGenerator()

        # Assessment state
        self.current_assessment = None
        self.assessment_history = []

        logger.info("Security Orchestrator initialized")

    async def run_comprehensive_assessment(self,
                                         target: str,
                                         scan_mode: str = "comprehensive",
                                         passive_only: bool = False,
                                         deep_scan: bool = False,
                                         stealth_mode: bool = False,
                                         time_constraint: str = "normal",
                                         output_dir: str = None,
                                         report_format: str = "html") -> Dict[str, Any]:
        """
        Run a comprehensive security assessment using AI-powered tool selection

        Args:
            target: Target to assess (domain, IP, URL)
            scan_mode: Type of assessment (reconnaissance, vulnerability-scan, web-scan, fuzzing, comprehensive)
            passive_only: Use only passive techniques
            deep_scan: Enable deep scanning (more thorough but slower)
            stealth_mode: Use stealth techniques to avoid detection
            time_constraint: Time constraint (fast, normal, thorough)
            output_dir: Directory to save results
            report_format: Report format (html, json, csv, markdown, all)
        """
        logger.info(f"Starting comprehensive security assessment for {target}")

        # Create output directory
        if not output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
            output_dir = f"./results/{safe_target}_{timestamp}"

        os.makedirs(output_dir, exist_ok=True)

        # Initialize assessment
        assessment = {
            'target': target,
            'scan_mode': scan_mode,
            'config': {
                'passive_only': passive_only,
                'deep_scan': deep_scan,
                'stealth_mode': stealth_mode,
                'time_constraint': time_constraint,
                'output_dir': output_dir,
                'report_format': report_format
            },
            'start_time': datetime.now().isoformat(),
            'modules_executed': [],
            'results': {},
            'ai_decisions': {},
            'summary': {},
            'status': 'running'
        }

        self.current_assessment = assessment

        try:
            # Phase 1: AI-Powered Reconnaissance
            if scan_mode in ['reconnaissance', 'comprehensive']:
                logger.info("Phase 1: AI-Powered Reconnaissance")
                recon_results = await self._run_ai_reconnaissance(
                    target, passive_only, deep_scan, stealth_mode, time_constraint, output_dir
                )
                assessment['results']['reconnaissance'] = recon_results
                assessment['modules_executed'].append('reconnaissance')

            # Phase 2: Web Application Testing (if applicable)
            if scan_mode in ['web-scan', 'comprehensive'] and self._is_web_target(target):
                logger.info("Phase 2: Web Application Testing")
                web_results = await self._run_web_assessment(
                    target, passive_only, stealth_mode, output_dir
                )
                assessment['results']['web_assessment'] = web_results
                assessment['modules_executed'].append('web_assessment')

            # Phase 3: Fuzzing (if applicable and not passive)
            if scan_mode in ['fuzzing', 'comprehensive'] and not passive_only:
                logger.info("Phase 3: Fuzzing Assessment")
                fuzz_results = await self._run_fuzzing_assessment(
                    target, stealth_mode, output_dir
                )
                assessment['results']['fuzzing'] = fuzz_results
                assessment['modules_executed'].append('fuzzing')

            # Phase 4: Vulnerability Analysis
            if scan_mode in ['vulnerability-scan', 'comprehensive']:
                logger.info("Phase 4: Vulnerability Analysis")
                vuln_results = await self._run_vulnerability_analysis(assessment['results'])
                assessment['results']['vulnerability_analysis'] = vuln_results
                assessment['modules_executed'].append('vulnerability_analysis')

            # Phase 5: AI Analysis and Reporting
            logger.info("Phase 5: AI Analysis and Report Generation")
            analysis_results = await self._run_ai_analysis(assessment['results'])
            assessment['ai_decisions']['final_analysis'] = analysis_results

            # Generate reports
            report_results = await self._generate_reports(assessment, output_dir, report_format)
            assessment['results']['reporting'] = report_results

            # Generate summary
            assessment['summary'] = self._generate_assessment_summary(assessment)
            assessment['status'] = 'completed'
            assessment['end_time'] = datetime.now().isoformat()

            # Save assessment data
            self._save_assessment_data(assessment, output_dir)

            logger.info(f"Comprehensive security assessment completed for {target}")
            return assessment

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            assessment['status'] = 'failed'
            assessment['error'] = str(e)
            assessment['end_time'] = datetime.now().isoformat()
            return assessment

    async def _run_ai_reconnaissance(self,
                                   target: str,
                                   passive_only: bool,
                                   deep_scan: bool,
                                   stealth_mode: bool,
                                   time_constraint: str,
                                   output_dir: str) -> Dict[str, Any]:
        """Run AI-powered reconnaissance"""
        logger.info("Starting AI-powered reconnaissance")

        # Initialize AI reconnaissance engine
        self.recon_engine = AIReconEngine(target, output_dir, self.llm_client)

        # Run AI-powered reconnaissance
        recon_results = await self.recon_engine.ai_powered_reconnaissance(
            scan_mode="reconnaissance",
            passive_only=passive_only,
            deep_scan=deep_scan,
            stealth_mode=stealth_mode,
            time_constraint=time_constraint
        )

        logger.info("AI-powered reconnaissance completed")
        return recon_results

    async def _run_web_assessment(self,
                                target: str,
                                passive_only: bool,
                                stealth_mode: bool,
                                output_dir: str) -> Dict[str, Any]:
        """Run web application assessment"""
        logger.info("Starting web application assessment")

        # Initialize web scanner
        self.web_scanner = WebVulnerabilityScanner(target)

        # Configure scanner based on AI recommendations
        scan_config = {
            'test_xss': not passive_only,
            'test_sqli': not passive_only,
            'test_lfi': not passive_only,
            'test_command_injection': not passive_only,
            'stealth_mode': stealth_mode
        }

        # Run web assessment
        web_results = await self.web_scanner.comprehensive_scan(**scan_config)

        logger.info("Web application assessment completed")
        return web_results

    async def _run_fuzzing_assessment(self,
                                    target: str,
                                    stealth_mode: bool,
                                    output_dir: str) -> Dict[str, Any]:
        """Run fuzzing assessment"""
        logger.info("Starting fuzzing assessment")

        # Initialize fuzzer
        self.fuzzer = WebFuzzer(target)

        # Configure fuzzer
        fuzz_config = {
            'max_depth': 2 if stealth_mode else 3,
            'delay': 1.0 if stealth_mode else 0.5,
            'threads': 5 if stealth_mode else 10
        }

        # Run fuzzing
        fuzz_results = await self.fuzzer.comprehensive_fuzz(**fuzz_config)

        logger.info("Fuzzing assessment completed")
        return fuzz_results

    async def _run_vulnerability_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results for vulnerabilities"""
        logger.info("Starting vulnerability analysis")

        vulnerabilities = []
        risk_score = 0

        # Analyze reconnaissance results
        if 'reconnaissance' in results:
            recon_vulns = self._analyze_recon_vulnerabilities(results['reconnaissance'])
            vulnerabilities.extend(recon_vulns)

        # Analyze web assessment results
        if 'web_assessment' in results:
            web_vulns = self._analyze_web_vulnerabilities(results['web_assessment'])
            vulnerabilities.extend(web_vulns)

        # Analyze fuzzing results
        if 'fuzzing' in results:
            fuzz_vulns = self._analyze_fuzzing_vulnerabilities(results['fuzzing'])
            vulnerabilities.extend(fuzz_vulns)

        # Calculate overall risk score
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity == 'critical':
                risk_score += 10
            elif severity == 'high':
                risk_score += 7
            elif severity == 'medium':
                risk_score += 4
            elif severity == 'low':
                risk_score += 1

        analysis_results = {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'risk_score': risk_score,
            'risk_level': self._calculate_risk_level(risk_score),
            'vulnerability_categories': self._categorize_vulnerabilities(vulnerabilities)
        }

        logger.info(f"Vulnerability analysis completed. Found {len(vulnerabilities)} vulnerabilities")
        return analysis_results

    def _analyze_recon_vulnerabilities(self, recon_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze reconnaissance results for vulnerabilities"""
        vulnerabilities = []

        # Check for exposed services
        if 'aggregated_results' in recon_results:
            aggregated = recon_results['aggregated_results']

            # Check for excessive subdomain exposure
            if aggregated.get('total_subdomains', 0) > 50:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'medium',
                    'title': 'Excessive Subdomain Exposure',
                    'description': f"Found {aggregated['total_subdomains']} subdomains, indicating large attack surface",
                    'recommendation': 'Review and reduce unnecessary subdomains'
                })

            # Check for outdated technologies
            technologies = aggregated.get('technologies_detected', [])
            for tech in technologies:
                if any(old_tech in tech.lower() for old_tech in ['php/5', 'apache/2.2', 'nginx/1.0']):
                    vulnerabilities.append({
                        'type': 'Outdated Software',
                        'severity': 'high',
                        'title': f'Outdated Technology: {tech}',
                        'description': f'Detected outdated technology: {tech}',
                        'recommendation': 'Update to latest stable version'
                    })

        return vulnerabilities

    def _analyze_web_vulnerabilities(self, web_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze web assessment results for vulnerabilities"""
        vulnerabilities = []

        # Extract vulnerabilities from web scanner results
        if 'vulnerabilities' in web_results:
            for vuln in web_results['vulnerabilities']:
                vulnerabilities.append({
                    'type': vuln.get('type', 'Web Vulnerability'),
                    'severity': vuln.get('severity', 'medium'),
                    'title': vuln.get('title', 'Web Application Vulnerability'),
                    'description': vuln.get('description', ''),
                    'url': vuln.get('url', ''),
                    'parameter': vuln.get('parameter', ''),
                    'payload': vuln.get('payload', ''),
                    'recommendation': vuln.get('recommendation', 'Review and fix the vulnerability')
                })

        return vulnerabilities

    def _analyze_fuzzing_vulnerabilities(self, fuzz_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze fuzzing results for vulnerabilities"""
        vulnerabilities = []

        # Check for interesting findings from fuzzing
        if 'interesting_findings' in fuzz_results:
            for finding in fuzz_results['interesting_findings']:
                if finding.get('status_code') in [200, 403, 500]:
                    severity = 'low'
                    if finding.get('status_code') == 500:
                        severity = 'medium'
                    elif finding.get('status_code') == 200 and 'admin' in finding.get('path', ''):
                        severity = 'high'

                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': severity,
                        'title': f'Exposed Path: {finding.get("path", "")}',
                        'description': f'Found accessible path with status {finding.get("status_code")}',
                        'url': finding.get('url', ''),
                        'recommendation': 'Review access controls for this path'
                    })

        return vulnerabilities

    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate overall risk level based on score"""
        if risk_score >= 30:
            return 'Critical'
        elif risk_score >= 20:
            return 'High'
        elif risk_score >= 10:
            return 'Medium'
        elif risk_score > 0:
            return 'Low'
        else:
            return 'Informational'

    def _categorize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize vulnerabilities by type"""
        categories = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            categories[vuln_type] = categories.get(vuln_type, 0) + 1
        return categories

    async def _run_ai_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Run AI analysis of all results using chunking for large datasets"""
        if not self.llm_client:
            return {'error': 'No LLM client available for AI analysis'}

        # DEBUGGING: Logar e tratar max_input_tokens no início da função
        logger.info(f"Initial llm_client.max_input_tokens: {self.llm_client.max_input_tokens}")
        logger.info("Starting AI analysis of results")

        try:
            full_data_str = json.dumps(results, indent=2)
            data_tokens = self.llm_client.count_tokens(full_data_str)

            # Usar uma variável local para max_input_tokens para a decisão
            current_max_tokens = self.llm_client.max_input_tokens
            if current_max_tokens is None:
                logger.warning(f"Fallback: max_input_tokens from llm_client was None (Value: {self.llm_client.max_input_tokens}). Using 65536 for chunking decision logic.")
                current_max_tokens = 65536 # Fallback

            # Agora current_max_tokens NUNCA será None aqui
            if data_tokens < current_max_tokens * 0.6: # Agora seguro
                logger.info(f"Proceeding with simple AI analysis. data_tokens: {data_tokens}, effective max_input_tokens for decision: {current_max_tokens}")
                return await self._run_simple_ai_analysis(results)
            else:
                logger.info(f"Proceeding with chunked AI analysis. data_tokens: {data_tokens}, effective max_input_tokens for decision: {current_max_tokens}")
                return await self._run_chunked_ai_analysis(results)

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {'error': str(e)}

    async def _run_simple_ai_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Run AI analysis for small datasets that fit in one request"""
        analysis_prompt = f"""
Analyze the following comprehensive security assessment results:

RECONNAISSANCE RESULTS:
{json.dumps(results.get('reconnaissance', {}), indent=2)}

WEB ASSESSMENT RESULTS:
{json.dumps(results.get('web_assessment', {}), indent=2)}

FUZZING RESULTS:
{json.dumps(results.get('fuzzing', {}), indent=2)}

VULNERABILITY ANALYSIS:
{json.dumps(results.get('vulnerability_analysis', {}), indent=2)}

Please provide a comprehensive security analysis including:
1. Executive summary
2. Key security findings
3. Risk assessment
4. Attack scenarios
5. Prioritized recommendations
6. Compliance considerations

Respond in JSON format with detailed analysis.
"""

        try:
            # Query AI for analysis
            ai_response = await self.ai_selector._query_llm(analysis_prompt)

            # Parse response
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {'raw_analysis': ai_response}

        except Exception as e:
            logger.error(f"Simple AI analysis failed: {e}")
            return {'error': str(e)}

    async def _run_chunked_ai_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Run AI analysis for large datasets using chunking"""
        logger.info("Using chunked analysis for large dataset")

        # Analyze each section separately
        section_analyses = {}

        # Define sections to analyze
        sections = {
            'reconnaissance': results.get('reconnaissance', {}),
            'web_assessment': results.get('web_assessment', {}),
            'fuzzing': results.get('fuzzing', {}),
            'vulnerability_analysis': results.get('vulnerability_analysis', {})
        }

        # Analyze each section
        for section_name, section_data in sections.items():
            if not section_data:
                continue

            logger.info(f"Analyzing {section_name} section")

            try:
                section_json = json.dumps(section_data, indent=2)

                # Use chunked analysis if section is still too large
                if self.llm_client.count_text(section_json) > self.llm_client.max_input_tokens * 0.7:
                    analysis = await self._analyze_section_chunked(section_name, section_data)
                else:
                    analysis = await self._analyze_section_simple(section_name, section_data)

                section_analyses[section_name] = analysis

            except Exception as e:
                logger.error(f"Error analyzing {section_name}: {e}")
                section_analyses[section_name] = {'error': str(e)}

        # Combine all section analyses into final report
        return await self._combine_section_analyses(section_analyses)

    async def _analyze_section_simple(self, section_name: str, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single section that fits in one request"""
        prompt = f"""
Analyze the following {section_name} results from a security assessment:

{json.dumps(section_data, indent=2)}

Provide a focused analysis including:
1. Key findings specific to {section_name}
2. Security implications
3. Risk level assessment
4. Specific recommendations

Respond in JSON format.
"""

        try:
            response = await self.ai_selector._query_llm(prompt)

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {'analysis': response}

        except Exception as e:
            logger.error(f"Error in simple section analysis for {section_name}: {e}")
            return {'error': str(e)}

    async def _analyze_section_chunked(self, section_name: str, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a large section using chunking"""
        logger.info(f"Using chunked analysis for {section_name} section")

        # Chunk the section data
        chunks = self.llm_client.chunk_json_data(section_data)
        chunk_analyses = []

        for i, chunk in enumerate(chunks):
            logger.info(f"Analyzing {section_name} chunk {i+1}/{len(chunks)}")

            prompt = f"""
Analyze this portion of {section_name} data from a security assessment:

{json.dumps(chunk, indent=2)}

Provide a concise analysis focusing on:
1. Key security findings
2. Notable vulnerabilities or issues
3. Risk indicators

Keep the response concise but comprehensive.
"""

            try:
                response = await self.ai_selector._query_llm(prompt)
                chunk_analyses.append(f"Chunk {i+1}: {response}")
            except Exception as e:
                logger.error(f"Error analyzing {section_name} chunk {i+1}: {e}")
                chunk_analyses.append(f"Chunk {i+1}: Error - {str(e)}")

        # Combine chunk analyses
        combined_analysis = "\n\n".join(chunk_analyses)

        # Generate final section summary
        summary_prompt = f"""
Combine and summarize the following {section_name} analyses into a comprehensive section report:

{combined_analysis}

Provide a unified analysis in JSON format including:
1. Executive summary for {section_name}
2. Key findings
3. Risk assessment
4. Recommendations
"""

        try:
            final_response = await self.ai_selector._query_llm(summary_prompt)

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', final_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                return {'analysis': final_response}

        except Exception as e:
            logger.error(f"Error in final {section_name} analysis: {e}")
            return {'analysis': combined_analysis, 'error': str(e)}

    async def _combine_section_analyses(self, section_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Combine all section analyses into a final comprehensive report"""
        logger.info("Combining section analyses into final report")

        # Prepare summary of all sections
        sections_summary = []
        for section_name, analysis in section_analyses.items():
            if 'error' not in analysis:
                sections_summary.append(f"{section_name.upper()} ANALYSIS:\n{json.dumps(analysis, indent=2)}")
            else:
                sections_summary.append(f"{section_name.upper()}: Error - {analysis['error']}")

        combined_summary = "\n\n".join(sections_summary)

        # Generate final comprehensive analysis
        final_prompt = f"""
Based on the following section-by-section security analysis, provide a comprehensive final security assessment:

{combined_summary}

Generate a complete security analysis in JSON format including:
1. Executive summary
2. Overall risk assessment
3. Key security findings across all areas
4. Attack scenarios
5. Prioritized recommendations
6. Compliance considerations

Focus on correlating findings across different assessment areas and providing actionable insights.
"""

        try:
            final_response = await self.ai_selector._query_llm(final_prompt)

            # Parse JSON response
            import re
            json_match = re.search(r'\{.*\}', final_response, re.DOTALL)
            if json_match:
                final_analysis = json.loads(json_match.group())
                # Add section details for reference
                final_analysis['section_analyses'] = section_analyses
                return final_analysis
            else:
                return {
                    'raw_analysis': final_response,
                    'section_analyses': section_analyses
                }

        except Exception as e:
            logger.error(f"Error in final analysis combination: {e}")
            return {
                'error': str(e),
                'section_analyses': section_analyses,
                'partial_analysis': combined_summary
            }

    async def _generate_reports(self,
                              assessment: Dict[str, Any],
                              output_dir: str,
                              report_format: str) -> Dict[str, Any]:
        """Generate assessment reports"""
        logger.info("Generating assessment reports")

        # Prepare report data
        report_data = {
            'assessment': assessment,
            'target': assessment['target'],
            'scan_mode': assessment['scan_mode'],
            'results': assessment['results'],
            'ai_analysis': assessment.get('ai_decisions', {}).get('final_analysis', {}),
            'summary': assessment.get('summary', {}),
            'timestamp': datetime.now().isoformat()
        }

        # Generate reports
        report_results = {}

        # Generate comprehensive report (handles all formats internally)
        report_path = self.report_generator.generate_comprehensive_report(report_data, assessment['target'], report_format)
        report_results[report_format] = report_path

        logger.info("Report generation completed")
        return report_results

    def _generate_assessment_summary(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate assessment summary"""
        summary = {
            'target': assessment['target'],
            'scan_mode': assessment['scan_mode'],
            'modules_executed': assessment['modules_executed'],
            'total_vulnerabilities': 0,
            'risk_level': 'Unknown',
            'key_findings': [],
            'recommendations': [],
            'execution_time': None
        }

        # Calculate execution time
        if 'start_time' in assessment and 'end_time' in assessment:
            start = datetime.fromisoformat(assessment['start_time'])
            end = datetime.fromisoformat(assessment['end_time'])
            summary['execution_time'] = str(end - start)

        # Extract vulnerability information
        if 'vulnerability_analysis' in assessment['results']:
            vuln_analysis = assessment['results']['vulnerability_analysis']
            summary['total_vulnerabilities'] = vuln_analysis.get('total_vulnerabilities', 0)
            summary['risk_level'] = vuln_analysis.get('risk_level', 'Unknown')

        # Extract key findings from AI analysis
        ai_analysis = assessment.get('ai_decisions', {}).get('final_analysis', {})
        if 'key_findings' in ai_analysis:
            summary['key_findings'] = ai_analysis['key_findings']
        if 'recommended_actions' in ai_analysis:
            summary['recommendations'] = ai_analysis['recommended_actions']

        return summary

    def _save_assessment_data(self, assessment: Dict[str, Any], output_dir: str):
        """Save assessment data to file"""
        try:
            assessment_file = os.path.join(output_dir, 'assessment_data.json')
            with open(assessment_file, 'w') as f:
                json.dump(assessment, f, indent=2, default=str)
            logger.info(f"Assessment data saved to {assessment_file}")
        except Exception as e:
            logger.error(f"Failed to save assessment data: {e}")

    def _is_web_target(self, target: str) -> bool:
        """Check if target is a web application"""
        return target.startswith('http') or ':80' in target or ':443' in target or ':8080' in target

    def get_assessment_history(self) -> List[Dict[str, Any]]:
        """Get history of assessments"""
        return self.assessment_history

    def get_current_assessment(self) -> Optional[Dict[str, Any]]:
        """Get current running assessment"""
        return self.current_assessment