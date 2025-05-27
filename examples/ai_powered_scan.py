#!/usr/bin/env python3
"""
Example: AI-Powered Security Assessment

This example demonstrates how to use OpenManus-BugHunting with AI-powered
tool selection for intelligent security assessments.

The AI analyzes the target and context to select the most appropriate tools
for each phase of the assessment.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent.parent / "app"))

from app.core.orchestrator import SecurityOrchestrator
from app.llm import LLMClient
from app.logger import setup_logging, logger


async def ai_powered_assessment_example():
    """Example of AI-powered security assessment"""
    
    # Setup logging
    setup_logging(level='INFO')
    
    print("🤖 AI-Powered Security Assessment Example")
    print("=" * 50)
    
    # Initialize LLM client (requires API key)
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ Please set OPENAI_API_KEY environment variable")
        print("   export OPENAI_API_KEY='your-api-key-here'")
        return
    
    try:
        llm_client = LLMClient(
            model='gpt-4',
            api_key=api_key,
            temperature=0.1  # Low temperature for consistent decisions
        )
        print("✅ LLM client initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize LLM client: {e}")
        return
    
    # Initialize orchestrator with AI
    orchestrator = SecurityOrchestrator(llm_client=llm_client)
    
    # Example targets
    targets = [
        "example.com",
        "testphp.vulnweb.com",
        "httpbin.org"
    ]
    
    print(f"\n🎯 Testing {len(targets)} targets with AI-powered tool selection")
    
    for target in targets:
        print(f"\n{'='*60}")
        print(f"🔍 Analyzing target: {target}")
        print(f"{'='*60}")
        
        try:
            # Run AI-powered assessment
            result = await orchestrator.run_comprehensive_assessment(
                target=target,
                scan_mode="reconnaissance",  # Start with reconnaissance
                passive_only=False,
                deep_scan=False,
                stealth_mode=True,  # Use stealth mode for examples
                time_constraint="fast",  # Fast scan for demo
                output_dir=f"./examples/results/{target.replace('.', '_')}",
                report_format="json"
            )
            
            # Display AI decisions
            if 'ai_tool_selection' in result:
                print("\n🤖 AI Tool Selection:")
                for category, tools in result['ai_tool_selection'].items():
                    if tools:
                        print(f"   {category}: {', '.join(tools)}")
            
            # Display results summary
            if 'summary' in result:
                summary = result['summary']
                print(f"\n📊 Results Summary:")
                print(f"   Status: {result.get('status', 'unknown')}")
                print(f"   Execution time: {summary.get('execution_time', 'unknown')}")
                print(f"   Vulnerabilities found: {summary.get('total_vulnerabilities', 0)}")
                print(f"   Risk level: {summary.get('risk_level', 'unknown')}")
            
            # Display AI analysis if available
            if 'ai_analysis' in result.get('ai_decisions', {}):
                ai_analysis = result['ai_decisions']['ai_analysis']
                if 'overall_assessment' in ai_analysis:
                    print(f"\n🧠 AI Assessment: {ai_analysis['overall_assessment']}")
                if 'key_findings' in ai_analysis:
                    print(f"🔍 Key Findings: {', '.join(ai_analysis['key_findings'][:3])}")
            
        except Exception as e:
            print(f"❌ Assessment failed for {target}: {e}")
            continue
    
    print(f"\n{'='*60}")
    print("✅ AI-powered assessment examples completed")
    print("📁 Results saved to ./examples/results/")
    print(f"{'='*60}")


async def compare_ai_vs_rules_example():
    """Example comparing AI-powered vs rule-based tool selection"""
    
    print("\n🔬 AI vs Rule-based Tool Selection Comparison")
    print("=" * 50)
    
    target = "example.com"
    
    # Test with AI
    api_key = os.getenv('OPENAI_API_KEY')
    if api_key:
        print("\n🤖 Running with AI-powered tool selection...")
        llm_client = LLMClient(model='gpt-4', api_key=api_key, temperature=0.1)
        orchestrator_ai = SecurityOrchestrator(llm_client=llm_client)
        
        result_ai = await orchestrator_ai.run_comprehensive_assessment(
            target=target,
            scan_mode="reconnaissance",
            stealth_mode=True,
            time_constraint="fast",
            output_dir=f"./examples/results/ai_{target.replace('.', '_')}",
            report_format="json"
        )
        
        print("AI Selected Tools:")
        for category, tools in result_ai.get('ai_tool_selection', {}).items():
            if tools:
                print(f"   {category}: {', '.join(tools)}")
    
    # Test with rule-based fallback
    print("\n🔧 Running with rule-based tool selection...")
    orchestrator_rules = SecurityOrchestrator(llm_client=None)
    
    result_rules = await orchestrator_rules.run_comprehensive_assessment(
        target=target,
        scan_mode="reconnaissance",
        stealth_mode=True,
        time_constraint="fast",
        output_dir=f"./examples/results/rules_{target.replace('.', '_')}",
        report_format="json"
    )
    
    print("Rule-based Selected Tools:")
    for category, tools in result_rules.get('ai_tool_selection', {}).items():
        if tools:
            print(f"   {category}: {', '.join(tools)}")
    
    # Compare results
    print(f"\n📊 Comparison Results:")
    if api_key:
        ai_vulns = result_ai.get('summary', {}).get('total_vulnerabilities', 0)
        print(f"   AI-powered: {ai_vulns} vulnerabilities found")
    
    rules_vulns = result_rules.get('summary', {}).get('total_vulnerabilities', 0)
    print(f"   Rule-based: {rules_vulns} vulnerabilities found")


async def custom_scan_context_example():
    """Example of customizing scan context for AI decisions"""
    
    print("\n⚙️  Custom Scan Context Example")
    print("=" * 50)
    
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ Skipping AI examples - no API key provided")
        return
    
    llm_client = LLMClient(model='gpt-4', api_key=api_key, temperature=0.1)
    orchestrator = SecurityOrchestrator(llm_client=llm_client)
    
    target = "testphp.vulnweb.com"
    
    # Test different scan contexts
    contexts = [
        {
            'name': 'Stealth Reconnaissance',
            'params': {
                'scan_mode': 'reconnaissance',
                'passive_only': True,
                'stealth_mode': True,
                'time_constraint': 'normal'
            }
        },
        {
            'name': 'Fast Vulnerability Scan',
            'params': {
                'scan_mode': 'vulnerability-scan',
                'passive_only': False,
                'stealth_mode': False,
                'time_constraint': 'fast'
            }
        },
        {
            'name': 'Deep Web Assessment',
            'params': {
                'scan_mode': 'web-scan',
                'passive_only': False,
                'deep_scan': True,
                'time_constraint': 'thorough'
            }
        }
    ]
    
    for context in contexts:
        print(f"\n🔍 Testing: {context['name']}")
        print("-" * 30)
        
        try:
            result = await orchestrator.run_comprehensive_assessment(
                target=target,
                output_dir=f"./examples/results/{context['name'].lower().replace(' ', '_')}",
                report_format="json",
                **context['params']
            )
            
            # Show AI tool selection for this context
            if 'ai_tool_selection' in result:
                print("AI Selected Tools:")
                for category, tools in result['ai_tool_selection'].items():
                    if tools:
                        print(f"   {category}: {', '.join(tools)}")
            
            print(f"Status: {result.get('status', 'unknown')}")
            
        except Exception as e:
            print(f"❌ Failed: {e}")


async def main():
    """Main example runner"""
    
    # Create results directory
    os.makedirs("./examples/results", exist_ok=True)
    
    print("🚀 OpenManus-BugHunting AI Examples")
    print("=" * 60)
    
    # Run examples
    await ai_powered_assessment_example()
    await compare_ai_vs_rules_example()
    await custom_scan_context_example()
    
    print("\n🎉 All examples completed!")
    print("📚 Check the generated reports in ./examples/results/")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Examples failed: {e}")
        import traceback
        traceback.print_exc()