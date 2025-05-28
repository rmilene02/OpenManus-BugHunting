#!/usr/bin/env python3
"""
Example: Using Custom AI Configuration for Bug Hunting

This example demonstrates how to use the modular AI configuration system
to customize tool selection, prompts, and rules for specific bug bounty programs.
"""

import asyncio
import sys
import os

# Add the parent directory to the path so we can import the app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.ai_config_loader import AIConfigLoader
from app.core.ai_tool_selector import AIToolSelector, ScanContext
from app.llm import LLM
from app.logger import logger


async def example_custom_configuration():
    """Example of using custom AI configuration for bug hunting."""
    
    print("🤖 OpenManus-BugHunting Custom AI Configuration Example")
    print("=" * 60)
    
    # Initialize AI configuration loader
    config_loader = AIConfigLoader("config/ai")
    
    # Validate configuration
    if not config_loader.validate_config():
        print("❌ Configuration validation failed!")
        return
    
    print("✅ AI configuration loaded and validated successfully")
    
    # Display loaded configurations
    print("\n📋 Loaded Configurations:")
    print(f"- Prompts: {len(config_loader.prompts_config)} sections")
    print(f"- Tools: {len(config_loader.tools_config)} categories")
    print(f"- Wordlists: {len(config_loader.wordlists_config)} categories")
    print(f"- Custom Rules: {len(config_loader.custom_rules)} files")
    
    # Example 1: Get system prompt with custom rules
    print("\n🎯 Example 1: System Prompt with Custom Rules")
    print("-" * 50)
    system_prompt = config_loader.get_system_prompt(include_custom_rules=True)
    print(f"System prompt length: {len(system_prompt)} characters")
    print("First 200 characters:")
    print(system_prompt[:200] + "...")
    
    # Example 2: Get available tools
    print("\n🔧 Example 2: Available Tools Configuration")
    print("-" * 50)
    available_tools = config_loader.get_available_tools()
    for category, tools in available_tools.items():
        print(f"- {category}: {len(tools)} tools")
        for tool_name in list(tools.keys())[:2]:  # Show first 2 tools
            print(f"  • {tool_name}")
    
    # Example 3: Get wordlists for different scenarios
    print("\n📚 Example 3: Wordlist Recommendations")
    print("-" * 50)
    
    scenarios = [
        ("web_application", "reconnaissance", "fast"),
        ("api", "comprehensive", "normal"),
        ("web_application", "comprehensive", "thorough")
    ]
    
    for target_type, scan_mode, time_constraint in scenarios:
        wordlists = config_loader.get_wordlists_for_target(target_type, scan_mode, time_constraint)
        print(f"- {target_type} + {scan_mode} + {time_constraint}: {len(wordlists)} wordlists")
        for wordlist in wordlists[:2]:  # Show first 2
            print(f"  • {wordlist.get('name', 'Unknown')}")
    
    # Example 4: Tool selection rules
    print("\n⚙️ Example 4: Tool Selection Rules")
    print("-" * 50)
    
    contexts = [
        {"stealth_mode": True, "time_constraint": "fast"},
        {"deep_scan": True, "time_constraint": "thorough"},
        {"passive_only": True}
    ]
    
    for context in contexts:
        rules = config_loader.get_tool_selection_rules(context)
        print(f"- Context {context}: {len(rules)} rules applied")
        if "preferred_tools" in rules:
            print(f"  Preferred: {rules['preferred_tools'][:3]}")  # Show first 3
    
    # Example 5: Compliance requirements
    print("\n📋 Example 5: Compliance Requirements")
    print("-" * 50)
    compliance = config_loader.get_compliance_requirements()
    for framework, requirements in compliance.items():
        if isinstance(requirements, str):
            print(f"- {framework}: {len(requirements)} characters")
        else:
            print(f"- {framework}: {type(requirements).__name__}")
    
    print("\n✅ Custom AI configuration example completed!")


async def example_ai_tool_selection():
    """Example of AI tool selection with custom configuration."""
    
    print("\n🎯 AI Tool Selection with Custom Configuration")
    print("=" * 60)
    
    # Note: This example requires a valid LLM configuration
    # For demonstration, we'll show the setup without making actual API calls
    
    try:
        # Initialize LLM client (would need valid API key)
        # llm_client = LLM()
        
        # Initialize AI tool selector with custom config
        ai_selector = AIToolSelector(llm_client=None, config_path="config/ai")
        
        # Create scan context
        context = ScanContext(
            target="example.com",
            target_type="domain",
            scan_mode="reconnaissance",
            stealth_mode=True,
            time_constraint="fast"
        )
        
        print(f"📊 Scan Context:")
        print(f"- Target: {context.target}")
        print(f"- Type: {context.target_type}")
        print(f"- Mode: {context.scan_mode}")
        print(f"- Stealth: {context.stealth_mode}")
        print(f"- Time: {context.time_constraint}")
        
        # Generate prompt (without calling LLM)
        prompt = ai_selector._create_tool_selection_prompt(context, ai_selector.available_tools)
        
        print(f"\n📝 Generated Prompt:")
        print(f"- Length: {len(prompt)} characters")
        print(f"- Contains custom rules: {'CUSTOM RULES' in prompt}")
        print(f"- Contains wordlist recommendations: {'RECOMMENDED WORDLISTS' in prompt}")
        print(f"- Contains selection rules: {'SELECTION RULES' in prompt}")
        
        # Show first few lines of the prompt
        lines = prompt.split('\n')[:10]
        print("\nFirst 10 lines of prompt:")
        for i, line in enumerate(lines, 1):
            print(f"{i:2d}: {line}")
        
        print("\n✅ AI tool selection example completed!")
        
    except Exception as e:
        print(f"❌ Error in AI tool selection example: {e}")
        print("Note: This example requires proper LLM configuration for full functionality")


def create_example_custom_rules():
    """Create an example custom rules file."""
    
    print("\n📝 Creating Example Custom Rules")
    print("=" * 60)
    
    custom_rules_dir = "config/ai/custom/rules"
    os.makedirs(custom_rules_dir, exist_ok=True)
    
    example_rules_path = os.path.join(custom_rules_dir, "example_bugbounty.toml")
    
    example_rules = """# Example Bug Bounty Program Configuration
# Copy and customize this file for your specific programs

[custom_bug_bounty_rules]
program_name = "Example Bug Bounty Program"
scope_domains = ["example.com", "*.example.com", "api.example.com"]
out_of_scope = ["admin.example.com", "internal.example.com"]

# Testing preferences
allowed_techniques = ["subdomain_enumeration", "directory_discovery", "parameter_fuzzing"]
forbidden_techniques = ["sql_injection_testing", "brute_force"]
rate_limit_requests_per_second = 5
max_concurrent_connections = 2

# Priority vulnerabilities
priority_vulnerabilities = ["IDOR", "Authentication_Bypass", "Information_Disclosure"]
excluded_vulnerabilities = ["Self_XSS", "Missing_Security_Headers"]

[custom_ai_instructions]
focus_areas = [
    "Look for business logic vulnerabilities in the checkout process",
    "Pay special attention to API endpoints under /api/v1/",
    "Focus on authentication and authorization flaws",
    "Check for IDOR in user profile management"
]

avoid_areas = [
    "Do not test payment processing endpoints",
    "Avoid testing user registration flows during business hours",
    "Skip social media integration testing"
]

special_considerations = [
    "This target uses a custom authentication system with JWT tokens",
    "API rate limiting is strictly enforced at 100 requests per minute",
    "WAF is known to be very sensitive to SQL injection attempts"
]

[custom_tool_preferences]
preferred_subdomain_tools = ["subfinder", "amass"]
preferred_directory_tools = ["ffuf"]
preferred_vulnerability_tools = ["nuclei"]

# Custom Nuclei configuration
[custom_tool_preferences.nuclei_custom]
templates_path = "/usr/share/nuclei-templates"
severity_filter = ["high", "critical"]
exclude_tags = ["dos", "intrusive"]

[custom_wordlists]
[custom_wordlists.company_specific]
name = "Company Specific Terms"
path = "/path/to/custom/company-wordlist.txt"
description = "Company-specific terms and patterns"
use_cases = ["targeted_discovery"]

[custom_reporting]
include_company_branding = true
executive_summary_focus = ["business_impact", "remediation_priority"]

# Custom severity overrides
[custom_reporting.severity_override]
information_disclosure = "medium"
missing_security_headers = "low"
admin_panel_exposure = "high"
"""
    
    with open(example_rules_path, 'w') as f:
        f.write(example_rules)
    
    print(f"✅ Created example custom rules: {example_rules_path}")
    print("📝 You can copy and customize this file for your bug bounty programs")


async def main():
    """Main function to run all examples."""
    
    try:
        # Run configuration examples
        await example_custom_configuration()
        
        # Run AI tool selection example
        await example_ai_tool_selection()
        
        # Create example custom rules
        create_example_custom_rules()
        
        print("\n🎉 All examples completed successfully!")
        print("\n📚 Next Steps:")
        print("1. Customize config/ai/prompts.toml with your bug hunting rules")
        print("2. Add your wordlists to config/ai/wordlists.toml")
        print("3. Create custom rules in config/ai/custom/rules/")
        print("4. Test with: python main.py --target example.com --llm-api-type deepseek")
        
    except Exception as e:
        logger.error(f"Example failed: {e}")
        print(f"❌ Example failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())