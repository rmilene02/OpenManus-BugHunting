"""
Report Generator

Comprehensive reporting system for security assessments that generates:
- Executive summaries
- Technical vulnerability reports
- Remediation recommendations
- Risk assessments
- Export to multiple formats (PDF, HTML, JSON, CSV)
"""

import json
import csv
import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import jinja2
from app.logger import logger


class ReportGenerator:
    """Advanced report generator for security assessment results"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment for templating
        self.jinja_env = jinja2.Environment(
            loader=jinja2.DictLoader(self._get_templates()),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Risk scoring matrix
        self.risk_matrix = {
            'critical': {'score': 10, 'color': '#dc3545'},
            'high': {'score': 8, 'color': '#fd7e14'},
            'medium': {'score': 5, 'color': '#ffc107'},
            'low': {'score': 2, 'color': '#28a745'},
            'info': {'score': 1, 'color': '#17a2b8'}
        }
    
    def generate_comprehensive_report(self, assessment_data: Dict[str, Any], 
                                    target: str, format_type: str = 'html') -> str:
        """Generate comprehensive security assessment report"""
        logger.info(f"Generating comprehensive report for {target}")
        
        # Analyze and process the data
        processed_data = self._process_assessment_data(assessment_data, target)
        
        # Generate report based on format
        if format_type.lower() == 'html':
            return self._generate_html_report(processed_data)
        elif format_type.lower() == 'json':
            return self._generate_json_report(processed_data)
        elif format_type.lower() == 'csv':
            return self._generate_csv_report(processed_data)
        elif format_type.lower() == 'markdown':
            return self._generate_markdown_report(processed_data)
        else:
            logger.warning(f"Unsupported format: {format_type}, defaulting to HTML")
            return self._generate_html_report(processed_data)
    
    def _process_assessment_data(self, assessment_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Process and analyze assessment data"""
        processed = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'executive_summary': {},
            'vulnerability_summary': {},
            'detailed_findings': [],
            'recommendations': [],
            'risk_assessment': {},
            'technical_details': {},
            'appendices': {}
        }
        
        # Process reconnaissance data
        if 'reconnaissance' in assessment_data:
            recon_data = assessment_data['reconnaissance']
            processed['technical_details']['reconnaissance'] = {
                'subdomains_found': len(recon_data.get('subdomains', [])),
                'live_hosts': len(recon_data.get('live_hosts', [])),
                'technologies_detected': recon_data.get('technologies', []),
                'open_ports': recon_data.get('open_ports', [])
            }
        
        # Process vulnerability scanning data
        if 'vulnerability_scan' in assessment_data:
            vuln_data = assessment_data['vulnerability_scan']
            processed['detailed_findings'].extend(
                self._process_vulnerability_findings(vuln_data)
            )
        
        # Process web application testing data
        if 'web_scanner' in assessment_data:
            web_data = assessment_data['web_scanner']
            processed['detailed_findings'].extend(
                self._process_web_findings(web_data)
            )
        
        # Process fuzzing results
        if 'fuzzer' in assessment_data:
            fuzz_data = assessment_data['fuzzer']
            processed['detailed_findings'].extend(
                self._process_fuzzing_findings(fuzz_data)
            )
        
        # Generate executive summary
        processed['executive_summary'] = self._generate_executive_summary(processed)
        
        # Generate vulnerability summary
        processed['vulnerability_summary'] = self._generate_vulnerability_summary(processed)
        
        # Generate risk assessment
        processed['risk_assessment'] = self._generate_risk_assessment(processed)
        
        # Generate recommendations
        processed['recommendations'] = self._generate_recommendations(processed)
        
        return processed
    
    def _process_vulnerability_findings(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process vulnerability scanning findings"""
        findings = []
        
        for scan_type, results in vuln_data.items():
            if isinstance(results, dict) and 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    finding = {
                        'id': f"VULN-{len(findings) + 1:04d}",
                        'title': vuln.get('name', 'Unknown Vulnerability'),
                        'severity': vuln.get('severity', 'medium').lower(),
                        'category': 'Vulnerability Scanning',
                        'subcategory': scan_type,
                        'description': vuln.get('description', 'No description available'),
                        'impact': self._get_impact_description(vuln.get('severity', 'medium')),
                        'recommendation': vuln.get('solution', 'Review and remediate'),
                        'references': vuln.get('references', []),
                        'evidence': {
                            'url': vuln.get('url', ''),
                            'method': vuln.get('method', ''),
                            'payload': vuln.get('payload', ''),
                            'response': vuln.get('response', '')
                        },
                        'risk_score': self.risk_matrix[vuln.get('severity', 'medium').lower()]['score']
                    }
                    findings.append(finding)
        
        return findings
    
    def _process_web_findings(self, web_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process web application testing findings"""
        findings = []
        
        # Process different types of web vulnerabilities
        web_categories = {
            'xss_testing': 'Cross-Site Scripting (XSS)',
            'sql_injection_test': 'SQL Injection',
            'command_injection': 'Command Injection',
            'file_inclusion': 'File Inclusion',
            'directory_enumeration': 'Information Disclosure'
        }
        
        for category, results in web_data.items():
            if category in web_categories and isinstance(results, dict):
                category_name = web_categories[category]
                
                if 'findings' in results:
                    for finding_data in results['findings']:
                        finding = {
                            'id': f"WEB-{len(findings) + 1:04d}",
                            'title': f"{category_name} Vulnerability",
                            'severity': finding_data.get('severity', 'medium').lower(),
                            'category': 'Web Application Security',
                            'subcategory': category_name,
                            'description': finding_data.get('description', f"Potential {category_name} vulnerability detected"),
                            'impact': self._get_impact_description(finding_data.get('severity', 'medium')),
                            'recommendation': self._get_remediation_advice(category),
                            'evidence': {
                                'url': finding_data.get('url', ''),
                                'parameter': finding_data.get('parameter', ''),
                                'payload': finding_data.get('payload', ''),
                                'response': finding_data.get('response', '')
                            },
                            'risk_score': self.risk_matrix[finding_data.get('severity', 'medium').lower()]['score']
                        }
                        findings.append(finding)
        
        return findings
    
    def _process_fuzzing_findings(self, fuzz_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process fuzzing findings"""
        findings = []
        
        fuzz_categories = {
            'directory_fuzzing': 'Directory/File Discovery',
            'parameter_fuzzing': 'Parameter Discovery',
            'input_validation': 'Input Validation Issues',
            'boundary_testing': 'Boundary Testing Issues'
        }
        
        for category, results in fuzz_data.items():
            if category in fuzz_categories and isinstance(results, dict):
                category_name = fuzz_categories[category]
                
                if 'findings' in results:
                    for finding_data in results['findings']:
                        severity = 'low'
                        if finding_data.get('has_error') or finding_data.get('potential_vulnerability'):
                            severity = 'medium'
                        
                        finding = {
                            'id': f"FUZZ-{len(findings) + 1:04d}",
                            'title': f"{category_name} Finding",
                            'severity': severity,
                            'category': 'Fuzzing',
                            'subcategory': category_name,
                            'description': finding_data.get('description', f"{category_name} discovered during fuzzing"),
                            'impact': self._get_impact_description(severity),
                            'recommendation': 'Review and validate the discovered endpoints/parameters',
                            'evidence': finding_data,
                            'risk_score': self.risk_matrix[severity]['score']
                        }
                        findings.append(finding)
        
        return findings
    
    def _generate_executive_summary(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        findings = processed_data['detailed_findings']
        
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate overall risk score
        total_risk_score = sum(finding.get('risk_score', 0) for finding in findings)
        avg_risk_score = total_risk_score / len(findings) if findings else 0
        
        # Determine overall risk level
        if avg_risk_score >= 8:
            overall_risk = 'Critical'
        elif avg_risk_score >= 6:
            overall_risk = 'High'
        elif avg_risk_score >= 4:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'overall_risk_level': overall_risk,
            'overall_risk_score': round(avg_risk_score, 2),
            'key_findings': self._get_key_findings(findings),
            'immediate_actions': self._get_immediate_actions(findings)
        }
    
    def _generate_vulnerability_summary(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vulnerability summary"""
        findings = processed_data['detailed_findings']
        
        # Group by category
        categories = {}
        for finding in findings:
            category = finding.get('category', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        # Generate category summaries
        category_summaries = {}
        for category, category_findings in categories.items():
            category_summaries[category] = {
                'count': len(category_findings),
                'highest_severity': self._get_highest_severity(category_findings),
                'subcategories': list(set(f.get('subcategory', '') for f in category_findings))
            }
        
        return {
            'categories': category_summaries,
            'top_vulnerabilities': sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)[:10]
        }
    
    def _generate_risk_assessment(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment"""
        findings = processed_data['detailed_findings']
        
        # Business impact assessment
        business_impact = {
            'confidentiality': 'Medium',
            'integrity': 'Medium',
            'availability': 'Low',
            'reputation': 'Medium'
        }
        
        # Technical risk factors
        technical_risks = []
        if any(f.get('severity') == 'critical' for f in findings):
            technical_risks.append('Critical vulnerabilities present')
        if any('injection' in f.get('subcategory', '').lower() for f in findings):
            technical_risks.append('Injection vulnerabilities detected')
        if any('xss' in f.get('subcategory', '').lower() for f in findings):
            technical_risks.append('Cross-site scripting vulnerabilities found')
        
        return {
            'business_impact': business_impact,
            'technical_risks': technical_risks,
            'compliance_impact': self._assess_compliance_impact(findings),
            'remediation_timeline': self._generate_remediation_timeline(findings)
        }
    
    def _generate_recommendations(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        findings = processed_data['detailed_findings']
        
        recommendations = []
        
        # Priority recommendations based on severity
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        if critical_findings:
            recommendations.append({
                'priority': 'Immediate',
                'title': 'Address Critical Vulnerabilities',
                'description': 'Immediately address all critical severity vulnerabilities',
                'timeline': '24-48 hours',
                'effort': 'High'
            })
        
        high_findings = [f for f in findings if f.get('severity') == 'high']
        if high_findings:
            recommendations.append({
                'priority': 'High',
                'title': 'Remediate High-Risk Issues',
                'description': 'Address high-severity vulnerabilities within one week',
                'timeline': '1 week',
                'effort': 'Medium-High'
            })
        
        # General security recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'title': 'Implement Security Headers',
                'description': 'Implement proper security headers (CSP, HSTS, X-Frame-Options)',
                'timeline': '2 weeks',
                'effort': 'Low'
            },
            {
                'priority': 'Medium',
                'title': 'Regular Security Testing',
                'description': 'Establish regular security testing and code review processes',
                'timeline': '1 month',
                'effort': 'Medium'
            },
            {
                'priority': 'Low',
                'title': 'Security Awareness Training',
                'description': 'Provide security awareness training for development team',
                'timeline': '2 months',
                'effort': 'Low'
            }
        ])
        
        return recommendations
    
    def _generate_html_report(self, processed_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        template = self.jinja_env.get_template('html_report')
        html_content = template.render(data=processed_data, risk_matrix=self.risk_matrix)
        
        # Save to file
        filename = f"security_report_{processed_data['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {filepath}")
        return str(filepath)
    
    def _generate_json_report(self, processed_data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        filename = f"security_report_{processed_data['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {filepath}")
        return str(filepath)
    
    def _generate_csv_report(self, processed_data: Dict[str, Any]) -> str:
        """Generate CSV report of findings"""
        filename = f"security_findings_{processed_data['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.output_dir / filename
        
        findings = processed_data['detailed_findings']
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if findings:
                fieldnames = ['id', 'title', 'severity', 'category', 'subcategory', 'description', 'recommendation', 'risk_score']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for finding in findings:
                    row = {field: finding.get(field, '') for field in fieldnames}
                    writer.writerow(row)
        
        logger.info(f"CSV report saved to {filepath}")
        return str(filepath)
    
    def _generate_markdown_report(self, processed_data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        template = self.jinja_env.get_template('markdown_report')
        markdown_content = template.render(data=processed_data)
        
        filename = f"security_report_{processed_data['target']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report saved to {filepath}")
        return str(filepath)
    
    def _get_templates(self) -> Dict[str, str]:
        """Get report templates"""
        return {
            'html_report': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ data.target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid {{ risk_matrix.critical.color }}; }
        .high { border-left: 5px solid {{ risk_matrix.high.color }}; }
        .medium { border-left: 5px solid {{ risk_matrix.medium.color }}; }
        .low { border-left: 5px solid {{ risk_matrix.low.color }}; }
        .info { border-left: 5px solid {{ risk_matrix.info.color }}; }
        .severity-badge { padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {{ data.target }}</p>
        <p><strong>Date:</strong> {{ data.timestamp }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Findings:</strong> {{ data.executive_summary.total_findings }}</p>
        <p><strong>Overall Risk Level:</strong> {{ data.executive_summary.overall_risk_level }}</p>
        <p><strong>Risk Score:</strong> {{ data.executive_summary.overall_risk_score }}/10</p>
        
        <h3>Severity Breakdown</h3>
        <ul>
            <li>Critical: {{ data.executive_summary.severity_breakdown.critical }}</li>
            <li>High: {{ data.executive_summary.severity_breakdown.high }}</li>
            <li>Medium: {{ data.executive_summary.severity_breakdown.medium }}</li>
            <li>Low: {{ data.executive_summary.severity_breakdown.low }}</li>
            <li>Info: {{ data.executive_summary.severity_breakdown.info }}</li>
        </ul>
    </div>

    <h2>Detailed Findings</h2>
    {% for finding in data.detailed_findings %}
    <div class="finding {{ finding.severity }}">
        <h3>{{ finding.title }} <span class="severity-badge" style="background-color: {{ risk_matrix[finding.severity].color }}">{{ finding.severity.upper() }}</span></h3>
        <p><strong>ID:</strong> {{ finding.id }}</p>
        <p><strong>Category:</strong> {{ finding.category }} - {{ finding.subcategory }}</p>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        <p><strong>Impact:</strong> {{ finding.impact }}</p>
        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
        {% if finding.evidence.url %}
        <p><strong>Evidence URL:</strong> {{ finding.evidence.url }}</p>
        {% endif %}
    </div>
    {% endfor %}

    <h2>Recommendations</h2>
    {% for rec in data.recommendations %}
    <div class="finding">
        <h3>{{ rec.title }}</h3>
        <p><strong>Priority:</strong> {{ rec.priority }}</p>
        <p><strong>Timeline:</strong> {{ rec.timeline }}</p>
        <p><strong>Effort:</strong> {{ rec.effort }}</p>
        <p>{{ rec.description }}</p>
    </div>
    {% endfor %}
</body>
</html>
            ''',
            'markdown_report': '''
# Security Assessment Report

**Target:** {{ data.target }}  
**Date:** {{ data.timestamp }}

## Executive Summary

- **Total Findings:** {{ data.executive_summary.total_findings }}
- **Overall Risk Level:** {{ data.executive_summary.overall_risk_level }}
- **Risk Score:** {{ data.executive_summary.overall_risk_score }}/10

### Severity Breakdown

- Critical: {{ data.executive_summary.severity_breakdown.critical }}
- High: {{ data.executive_summary.severity_breakdown.high }}
- Medium: {{ data.executive_summary.severity_breakdown.medium }}
- Low: {{ data.executive_summary.severity_breakdown.low }}
- Info: {{ data.executive_summary.severity_breakdown.info }}

## Detailed Findings

{% for finding in data.detailed_findings %}
### {{ finding.title }} [{{ finding.severity.upper() }}]

**ID:** {{ finding.id }}  
**Category:** {{ finding.category }} - {{ finding.subcategory }}  
**Description:** {{ finding.description }}  
**Impact:** {{ finding.impact }}  
**Recommendation:** {{ finding.recommendation }}

{% if finding.evidence.url %}
**Evidence URL:** {{ finding.evidence.url }}
{% endif %}

---
{% endfor %}

## Recommendations

{% for rec in data.recommendations %}
### {{ rec.title }}

**Priority:** {{ rec.priority }}  
**Timeline:** {{ rec.timeline }}  
**Effort:** {{ rec.effort }}

{{ rec.description }}

{% endfor %}
            '''
        }
    
    def _get_impact_description(self, severity: str) -> str:
        """Get impact description based on severity"""
        impact_descriptions = {
            'critical': 'Critical impact to system security, immediate attention required',
            'high': 'High impact to security posture, should be addressed promptly',
            'medium': 'Medium impact, should be addressed in next maintenance cycle',
            'low': 'Low impact, can be addressed when convenient',
            'info': 'Informational finding, no immediate security impact'
        }
        return impact_descriptions.get(severity.lower(), 'Unknown impact level')
    
    def _get_remediation_advice(self, category: str) -> str:
        """Get remediation advice based on vulnerability category"""
        remediation_advice = {
            'xss_testing': 'Implement proper input validation and output encoding',
            'sql_injection_test': 'Use parameterized queries and input validation',
            'command_injection': 'Avoid system calls with user input, use safe APIs',
            'file_inclusion': 'Validate and sanitize file paths, use whitelisting',
            'directory_enumeration': 'Implement proper access controls and error handling'
        }
        return remediation_advice.get(category, 'Review and implement appropriate security controls')
    
    def _get_key_findings(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Get key findings for executive summary"""
        key_findings = []
        
        # Get highest severity findings
        critical_high = [f for f in findings if f.get('severity') in ['critical', 'high']]
        if critical_high:
            key_findings.append(f"{len(critical_high)} critical/high severity vulnerabilities identified")
        
        # Check for specific vulnerability types
        injection_vulns = [f for f in findings if 'injection' in f.get('subcategory', '').lower()]
        if injection_vulns:
            key_findings.append(f"{len(injection_vulns)} injection vulnerabilities found")
        
        xss_vulns = [f for f in findings if 'xss' in f.get('subcategory', '').lower()]
        if xss_vulns:
            key_findings.append(f"{len(xss_vulns)} cross-site scripting vulnerabilities detected")
        
        return key_findings[:5]  # Limit to top 5
    
    def _get_immediate_actions(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Get immediate actions for executive summary"""
        actions = []
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        if critical_findings:
            actions.append('Address all critical severity vulnerabilities immediately')
        
        high_findings = [f for f in findings if f.get('severity') == 'high']
        if high_findings:
            actions.append('Plan remediation for high-severity vulnerabilities within one week')
        
        actions.append('Implement security testing in development lifecycle')
        actions.append('Conduct security awareness training for development team')
        
        return actions[:5]  # Limit to top 5
    
    def _get_highest_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Get highest severity from a list of findings"""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            if any(f.get('severity') == severity for f in findings):
                return severity
        
        return 'info'
    
    def _assess_compliance_impact(self, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Assess compliance impact"""
        return {
            'PCI_DSS': 'Medium' if any(f.get('severity') in ['critical', 'high'] for f in findings) else 'Low',
            'GDPR': 'Medium' if any('data' in f.get('description', '').lower() for f in findings) else 'Low',
            'OWASP_Top_10': 'High' if any(f.get('severity') in ['critical', 'high'] for f in findings) else 'Medium'
        }
    
    def _generate_remediation_timeline(self, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate remediation timeline"""
        critical_count = len([f for f in findings if f.get('severity') == 'critical'])
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        
        timeline = {}
        
        if critical_count > 0:
            timeline['Critical'] = '24-48 hours'
        if high_count > 0:
            timeline['High'] = '1 week'
        
        timeline['Medium'] = '2-4 weeks'
        timeline['Low'] = '1-3 months'
        
        return timeline