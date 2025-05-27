#!/usr/bin/env python3
"""
Test Script for AI Integration

This script tests the AI-powered tool selection system using the DeepSeek API
to verify that all components are working correctly.
"""

import asyncio
import os
import sys
import json
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent / "app"))

from app.core.ai_tool_selector import AIToolSelector, ScanContext
from app.core.orchestrator import SecurityOrchestrator
from app.reconnaissance.ai_recon_engine import AIReconEngine
from app.llm import LLM
from app.logger import logger
from app.schema import Message, Role


async def test_llm_client():
    """Test LLM client initialization and basic functionality"""
    print("🧪 Testing LLM Client...")
    
    try:
        # Initialize DeepSeek client using config
        llm_client = LLM(config_name="default")
        
        # Test basic query
        test_message = Message(
            role=Role.USER,
            content="Respond with 'AI client working correctly' if you can understand this message."
        )
        response = await llm_client.ask([test_message])
        
        print(f"✅ LLM Client Response: {response[:100]}...")
        return llm_client
        
    except Exception as e:
        print(f"❌ LLM Client Test Failed: {e}")
        return None


async def test_ai_tool_selector(llm_client):
    """Test AI tool selector functionality"""
    print("\n🧪 Testing AI Tool Selector...")
    
    try:
        # Initialize AI selector
        ai_selector = AIToolSelector(llm_client)
        
        # Create test context
        context = ScanContext(
            target="example.com",
            target_type="domain",
            scan_mode="reconnaissance",
            passive_only=False,
            deep_scan=False,
            stealth_mode=True,
            time_constraint="normal"
        )
        
        # Mock available tools
        available_tools = {
            'subfinder': True,
            'amass': True,
            'httpx': True,
            'nmap': True,
            'nuclei': True,
            'gobuster': True
        }
        
        # Test AI tool selection
        selected_tools = await ai_selector.select_tools_with_ai(context, available_tools)
        
        print("✅ AI Tool Selection Results:")
        for category, tools in selected_tools.items():
            if tools:
                print(f"   {category}: {', '.join(tools)}")
        
        return True
        
    except Exception as e:
        print(f"❌ AI Tool Selector Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_ai_recon_engine(llm_client):
    """Test AI reconnaissance engine"""
    print("\n🧪 Testing AI Reconnaissance Engine...")
    
    try:
        # Initialize AI recon engine
        recon_engine = AIReconEngine(
            target="httpbin.org",  # Safe test target
            output_dir="/tmp/test_recon",
            llm_client=llm_client
        )
        
        print(f"✅ AI Recon Engine initialized for target: {recon_engine.target}")
        print(f"   Target type: {recon_engine.scan_context.target_type}")
        print(f"   Available tools: {sum(recon_engine.tools_available.values())}/{len(recon_engine.tools_available)}")
        
        # Test tool availability detection
        available_count = sum(recon_engine.tools_available.values())
        print(f"   Detected {available_count} available tools")
        
        return True
        
    except Exception as e:
        print(f"❌ AI Recon Engine Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_security_orchestrator(llm_client):
    """Test security orchestrator with AI"""
    print("\n🧪 Testing Security Orchestrator...")
    
    try:
        # Initialize orchestrator
        orchestrator = SecurityOrchestrator(llm_client=llm_client)
        
        print("✅ Security Orchestrator initialized with AI support")
        
        # Test basic functionality (without full scan)
        print("   AI selector available:", orchestrator.ai_selector is not None)
        print("   LLM client available:", orchestrator.llm_client is not None)
        
        return True
        
    except Exception as e:
        print(f"❌ Security Orchestrator Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_fallback_mechanism():
    """Test fallback to rule-based selection when AI is unavailable"""
    print("\n🧪 Testing Fallback Mechanism...")
    
    try:
        # Initialize AI selector without LLM client
        ai_selector = AIToolSelector(llm_client=None)
        
        # Create test context
        context = ScanContext(
            target="example.com",
            target_type="domain",
            scan_mode="reconnaissance",
            passive_only=True,
            deep_scan=False,
            stealth_mode=True,
            time_constraint="fast"
        )
        
        # Mock available tools
        available_tools = {
            'subfinder': True,
            'amass': True,
            'httpx': True,
            'nmap': True,
            'nuclei': True
        }
        
        # Test fallback selection
        selected_tools = await ai_selector.select_tools_with_ai(context, available_tools)
        
        print("✅ Fallback Tool Selection Results:")
        for category, tools in selected_tools.items():
            if tools:
                print(f"   {category}: {', '.join(tools)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Fallback Mechanism Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_tool_database():
    """Test tool database and information retrieval"""
    print("\n🧪 Testing Tool Database...")
    
    try:
        ai_selector = AIToolSelector()
        
        # Test tool info retrieval
        subfinder_info = ai_selector.get_tool_info('subfinder')
        if subfinder_info:
            print(f"✅ Tool Info Retrieved: {subfinder_info.name}")
            print(f"   Category: {subfinder_info.category}")
            print(f"   Speed: {subfinder_info.speed}")
            print(f"   Stealth: {subfinder_info.stealth}")
        
        # Test category filtering
        subdomain_tools = ai_selector.get_tools_by_category('subdomain_enumeration')
        print(f"✅ Subdomain tools found: {len(subdomain_tools)}")
        for tool in subdomain_tools[:3]:  # Show first 3
            print(f"   - {tool.name}: {tool.description}")
        
        return True
        
    except Exception as e:
        print(f"❌ Tool Database Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_context_analysis():
    """Test different scan contexts and their impact on tool selection"""
    print("\n🧪 Testing Context Analysis...")
    
    try:
        ai_selector = AIToolSelector()
        
        # Test different contexts
        contexts = [
            {
                'name': 'Stealth Passive',
                'context': ScanContext(
                    target="example.com",
                    target_type="domain",
                    scan_mode="reconnaissance",
                    passive_only=True,
                    stealth_mode=True,
                    time_constraint="normal"
                )
            },
            {
                'name': 'Fast Active',
                'context': ScanContext(
                    target="192.168.1.1",
                    target_type="ip",
                    scan_mode="vulnerability-scan",
                    passive_only=False,
                    stealth_mode=False,
                    time_constraint="fast"
                )
            },
            {
                'name': 'Deep Comprehensive',
                'context': ScanContext(
                    target="https://example.com",
                    target_type="url",
                    scan_mode="comprehensive",
                    deep_scan=True,
                    time_constraint="thorough"
                )
            }
        ]
        
        available_tools = {
            'subfinder': True, 'amass': True, 'httpx': True,
            'nmap': True, 'nuclei': True, 'gobuster': True
        }
        
        for test_case in contexts:
            print(f"\n   Testing: {test_case['name']}")
            selected = await ai_selector.select_tools_with_ai(
                test_case['context'], 
                available_tools
            )
            
            tool_count = sum(len(tools) for tools in selected.values())
            print(f"   Selected {tool_count} tools total")
        
        print("✅ Context Analysis Tests Completed")
        return True
        
    except Exception as e:
        print(f"❌ Context Analysis Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_integration_test():
    """Run a simple integration test with a safe target"""
    print("\n🧪 Running Integration Test...")
    
    try:
        # Initialize with DeepSeek
        llm_client = LLM(config_name="default")
        
        # Initialize orchestrator
        orchestrator = SecurityOrchestrator(llm_client=llm_client)
        
        # Run a minimal test scan
        print("   Running minimal reconnaissance test...")
        result = await orchestrator.run_comprehensive_assessment(
            target="httpbin.org",  # Safe test target
            scan_mode="reconnaissance",
            passive_only=True,  # Only passive techniques
            stealth_mode=True,
            time_constraint="fast",
            output_dir="/tmp/integration_test",
            report_format="json"
        )
        
        print(f"✅ Integration Test Completed")
        print(f"   Status: {result.get('status', 'unknown')}")
        print(f"   Modules executed: {len(result.get('modules_executed', []))}")
        
        # Show AI tool selection
        if 'ai_tool_selection' in result:
            print("   AI Tool Selection:")
            for category, tools in result['ai_tool_selection'].items():
                if tools:
                    print(f"     {category}: {', '.join(tools)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration Test Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main test runner"""
    print("🚀 OpenManus-BugHunting AI Integration Tests")
    print("=" * 60)
    
    # Logging is already configured in app.logger
    
    # Track test results
    test_results = {}
    
    # Test 1: LLM Client
    llm_client = await test_llm_client()
    test_results['llm_client'] = llm_client is not None
    
    if llm_client:
        # Test 2: AI Tool Selector
        test_results['ai_tool_selector'] = await test_ai_tool_selector(llm_client)
        
        # Test 3: AI Recon Engine
        test_results['ai_recon_engine'] = await test_ai_recon_engine(llm_client)
        
        # Test 4: Security Orchestrator
        test_results['security_orchestrator'] = await test_security_orchestrator(llm_client)
        
        # Test 5: Integration Test
        test_results['integration_test'] = await run_integration_test()
    
    # Test 6: Fallback Mechanism
    test_results['fallback_mechanism'] = await test_fallback_mechanism()
    
    # Test 7: Tool Database
    test_results['tool_database'] = await test_tool_database()
    
    # Test 8: Context Analysis
    test_results['context_analysis'] = await test_context_analysis()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name.replace('_', ' ').title()}")
        if result:
            passed += 1
    
    print(f"\n📈 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! AI integration is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Test runner failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)