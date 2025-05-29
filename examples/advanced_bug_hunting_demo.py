#!/usr/bin/env python3
"""
Advanced Bug Hunting Demonstration

This script demonstrates the advanced bug hunting capabilities of the OpenManus-BugHunting platform.
It shows how the platform has evolved from a sequential scanner to an intelligent security orchestrator
that thinks like a persistent attacker.

Usage:
    python examples/advanced_bug_hunting_demo.py --target example.com
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent.parent / "app"))

from app.core.advanced_bug_hunting_orchestrator import AdvancedBugHuntingOrchestrator, BugHuntingConfig
from app.logger import setup_logging, logger


async def demonstrate_advanced_capabilities(target: str):
    """Demonstrate advanced bug hunting capabilities"""
    
    print("🔥 OpenManus-BugHunting Advanced Capabilities Demonstration")
    print("=" * 60)
    print(f"Target: {target}")
    print()
    
    # Configuration for comprehensive testing
    config = BugHuntingConfig(
        target=target,
        deep_exploitation=True,
        business_logic_focus=True,
        privilege_escalation=True,
        stealth_mode=False,  # Disabled for demo
        time_constraint="normal",
        max_concurrent_tests=5,  # Conservative for demo
        ai_guided=True,
        wordlist_optimization=True
    )
    
    print("📋 Configuration:")
    print(f"   • Deep Exploitation: {config.deep_exploitation}")
    print(f"   • Business Logic Focus: {config.business_logic_focus}")
    print(f"   • Privilege Escalation: {config.privilege_escalation}")
    print(f"   • AI Guided: {config.ai_guided}")
    print(f"   • Wordlist Optimization: {config.wordlist_optimization}")
    print()
    
    # Initialize the advanced orchestrator
    orchestrator = AdvancedBugHuntingOrchestrator(config=config, llm_client=None)
    
    print("🚀 Starting Advanced Bug Hunting Campaign...")
    print()
    
    try:
        # Execute comprehensive bug hunting
        results = await orchestrator.execute_comprehensive_bug_hunt()
        
        # Display results summary
        print("📊 Campaign Results Summary:")
        print("=" * 40)
        
        execution_summary = results.get('execution_summary', {})
        print(f"Status: {execution_summary.get('status', 'Unknown')}")
        print(f"Total Execution Time: {execution_summary.get('total_execution_time', 0):.2f} seconds")
        print(f"Phases Completed: {execution_summary.get('phases_completed', 0)}")
        print()
        
        print("🔍 Vulnerability Discovery:")
        print(f"   • Total Vulnerabilities: {execution_summary.get('vulnerabilities_discovered', 0)}")
        print(f"   • Critical Findings: {execution_summary.get('critical_findings', 0)}")
        print(f"   • High Severity: {execution_summary.get('high_findings', 0)}")
        print(f"   • Vulnerability Chains: {execution_summary.get('vulnerability_chains_found', 0)}")
        print(f"   • Attack Paths: {execution_summary.get('attack_paths_identified', 0)}")
        print()
        
        print("🎯 Attack Surface Analysis:")
        attack_surface = execution_summary.get('attack_surface_mapped', {})
        print(f"   • Web Applications: {attack_surface.get('web_applications', 0)}")
        print(f"   • APIs Discovered: {attack_surface.get('apis', 0)}")
        print(f"   • Subdomains: {attack_surface.get('subdomains', 0)}")
        print()
        
        print("⚡ Efficiency Metrics:")
        efficiency = execution_summary.get('efficiency_metrics', {})
        print(f"   • Vulnerabilities per Minute: {efficiency.get('vulnerabilities_per_minute', 0):.2f}")
        print(f"   • Average Phase Time: {efficiency.get('average_phase_time', 0):.2f}s")
        print()
        
        # Show phase breakdown
        timeline = results.get('timeline', [])
        if timeline:
            print("⏱️ Phase Execution Timeline:")
            for phase in timeline:
                status_icon = "✅" if phase.get('status') == 'completed' else "❌"
                print(f"   {status_icon} {phase.get('phase', 'Unknown')}: {phase.get('duration', 0):.2f}s")
            print()
        
        # Show correlation analysis
        correlation_analysis = results.get('correlation_analysis', {})
        if correlation_analysis:
            print("🔗 Vulnerability Correlation Analysis:")
            
            chains = correlation_analysis.get('vulnerability_chains', [])
            if chains:
                print(f"   • Vulnerability Chains Found: {len(chains)}")
                for i, chain in enumerate(chains[:3], 1):  # Show top 3 chains
                    print(f"     {i}. {chain.get('name', 'Unknown')} (Risk Score: {chain.get('total_risk_score', 0):.1f})")
            
            attack_paths = correlation_analysis.get('attack_paths', [])
            if attack_paths:
                print(f"   • Attack Paths Identified: {len(attack_paths)}")
                for i, path in enumerate(attack_paths[:3], 1):  # Show top 3 paths
                    print(f"     {i}. {path.get('description', 'Unknown')} (Risk: {path.get('total_risk_score', 0):.1f})")
            
            critical_findings = correlation_analysis.get('critical_findings', [])
            if critical_findings:
                print(f"   • Critical Findings: {len(critical_findings)}")
                for i, finding in enumerate(critical_findings[:3], 1):  # Show top 3 findings
                    print(f"     {i}. {finding.get('title', 'Unknown')} (Priority: {finding.get('priority', 'Unknown')})")
            print()
        
        # Show AI insights if available
        ai_insights = results.get('ai_insights', {})
        if ai_insights and 'strategic_analysis' in ai_insights:
            print("🤖 AI Strategic Insights:")
            analysis = ai_insights['strategic_analysis']
            # Show first 200 characters of AI analysis
            preview = analysis[:200] + "..." if len(analysis) > 200 else analysis
            print(f"   {preview}")
            print()
        
        # Show recommendations
        recommendations = results.get('final_recommendations', [])
        if recommendations:
            print("💡 Key Recommendations:")
            for i, rec in enumerate(recommendations[:5], 1):  # Show top 5 recommendations
                print(f"   {i}. [{rec.get('priority', 'Unknown').upper()}] {rec.get('title', 'Unknown')}")
                print(f"      Timeline: {rec.get('timeline', 'Unknown')}")
            print()
        
        # Show advanced capabilities demonstrated
        print("🎯 Advanced Capabilities Demonstrated:")
        phases = results.get('phases', {})
        
        if 'reconnaissance_analysis' in phases:
            print("   ✅ Enhanced Reconnaissance Analysis")
            print("      • Technology-specific attack vector identification")
            print("      • High-value target prioritization")
        
        if 'intelligent_fuzzing' in phases:
            print("   ✅ Intelligent Contextual Fuzzing")
            print("      • Wordlist optimization based on discovered technologies")
            print("      • WAF detection and bypass techniques")
            print("      • Contextual payload generation")
        
        if 'advanced_exploitation' in phases:
            print("   ✅ Advanced Exploitation Techniques")
            print("      • GraphQL and API-specific testing")
            print("      • Business logic vulnerability testing")
            print("      • Server-specific exploitation")
        
        if correlation_analysis:
            print("   ✅ Vulnerability Correlation and Analysis")
            print("      • Knowledge graph construction")
            print("      • Attack path discovery")
            print("      • Risk amplification analysis")
        
        if ai_insights:
            print("   ✅ AI-Powered Strategic Analysis")
            print("      • Strategic security posture assessment")
            print("      • Business impact analysis")
            print("      • Prioritized remediation guidance")
        
        print()
        print("🎉 Advanced Bug Hunting Campaign Completed Successfully!")
        print()
        print("Key Differentiators from Traditional Scanning:")
        print("• Contextual exploitation based on discovered technologies")
        print("• Intelligent fuzzing with optimized wordlists")
        print("• Business logic vulnerability focus")
        print("• Vulnerability correlation and chaining")
        print("• AI-powered strategic analysis")
        print("• Attack path discovery and risk amplification")
        
        return results
        
    except Exception as e:
        print(f"❌ Error during advanced bug hunting: {e}")
        logger.error(f"Advanced bug hunting error: {e}")
        return None


async def demonstrate_real_time_monitoring(orchestrator):
    """Demonstrate real-time monitoring capabilities"""
    print("📡 Real-time Monitoring Demonstration:")
    print("   (This would show live updates during actual testing)")
    
    # Simulate real-time status updates
    for i in range(5):
        await asyncio.sleep(1)
        status = await orchestrator.get_real_time_status()
        print(f"   Update {i+1}: {status.get('vulnerabilities_found', 0)} vulnerabilities, "
              f"{status.get('chains_discovered', 0)} chains discovered")
    print()


async def demonstrate_adaptive_strategy(orchestrator):
    """Demonstrate adaptive strategy adjustment"""
    print("🧠 Adaptive Strategy Demonstration:")
    
    # Simulate current findings
    current_findings = {
        'vulnerabilities_found': 15,
        'high_severity': 3,
        'chains_discovered': 2
    }
    
    adjustment = await orchestrator.adaptive_strategy_adjustment(current_findings)
    
    if adjustment.get('adjusted'):
        print("   ✅ Strategy automatically adjusted based on findings")
        print(f"   📝 AI Recommendations: {adjustment.get('ai_recommendations', 'N/A')[:100]}...")
    else:
        print("   ℹ️  No strategy adjustment needed")
    print()


def main():
    """Main demonstration function"""
    parser = argparse.ArgumentParser(description="Advanced Bug Hunting Demonstration")
    parser.add_argument('--target', '-t', required=True, help='Target domain or IP')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--demo-mode', action='store_true', help='Run in demonstration mode (simulated)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = 'INFO' if args.verbose else 'WARNING'
    setup_logging(level=log_level)
    
    # Run demonstration
    asyncio.run(demonstrate_advanced_capabilities(args.target))


if __name__ == "__main__":
    main()