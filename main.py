"""
OpenManus-BugHunting - Advanced Bug Hunting and Security Testing Platform

A comprehensive cybersecurity toolkit focused on bug hunting, vulnerability analysis,
penetration testing, and security assessments.

This platform integrates multiple security testing methodologies and tools to provide
a complete solution for security professionals and researchers.

Features:
- Comprehensive reconnaissance using Kali Linux tools
- Advanced web application testing and fuzzing
- Vulnerability scanning and analysis
- Payload generation and exploitation frameworks
- Detailed reporting and risk assessment
- Integration with popular security tools
- Advanced bug hunting with contextual exploitation
- Vulnerability correlation and attack path analysis
- Business logic vulnerability testing
- AI-powered strategic security analysis
"""

import asyncio
import argparse
import sys
import json
import time
from pathlib import Path

# Add the app directory to the Python path
sys.path.append(str(Path(__file__).parent / "app"))

from app.core.orchestrator import SecurityOrchestrator
from app.logger import setup_logging, logger
from app.llm import LLM
from app.core.advanced_bug_hunting_orchestrator import AdvancedBugHuntingOrchestrator, BugHuntingConfig


def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║    ██████╗ ██████╗ ███████╗███╗   ██╗███╗   ███╗ █████╗      ║
    ║   ██╔═══██╗██╔══██╗██╔════╝████╗  ██║████╗ ████║██╔══██╗     ║
    ║   ██║   ██║██████╔╝█████╗  ██╔██╗ ██║██╔████╔██║███████║     ║
    ║   ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║╚██╔╝██║██╔══██║     ║
    ║   ╚██████╔╝██║     ███████╗██║ ╚████║██║ ╚═╝ ██║██║  ██║     ║
    ║    ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝     ║
    ║                                                               ║
    ║              BugHunting & Security Testing Platform           ║
    ║                                                               ║
    ║   Advanced Cybersecurity Toolkit for Bug Hunters             ║
    ║   Penetration Testers & Security Researchers                 ║
    ║                                                               ║
    ║   🔍 Reconnaissance  🕷️  Web Testing  💥 Exploitation        ║
    ║   🛡️  Vulnerability Scanning  📊 Reporting                   ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="OpenManus-BugHunting - Advanced Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comprehensive assessment of a single target
  python main.py --target example.com --mode comprehensive
  
  # Reconnaissance only with custom output directory
  python main.py --target example.com --mode reconnaissance --output /tmp/results
  
  # Web application testing with increased threads
  python main.py --target https://example.com --mode web-scan --threads 20
  
  # Vulnerability scan from target list
  python main.py --target-list targets.txt --mode vulnerability-scan
  
  # Full assessment with all output formats
  python main.py --target example.com --mode comprehensive --format all
  
  # Advanced bug hunting with AI guidance
  python main.py --target example.com --mode advanced-bug-hunting --ai-guided
  
  # Stealth advanced bug hunting
  python main.py --target example.com --mode advanced-bug-hunting --stealth-mode --time-constraint quick
  
  # Custom scan with specific modules excluded
  python main.py --target example.com --mode comprehensive --exclude fuzzer --exclude exploits
  
  # Scan through proxy with verbose output
  python main.py --target example.com --proxy http://127.0.0.1:8080 --verbose
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--target', '-t',
        help='Single target (domain, IP, or URL)'
    )
    target_group.add_argument(
        '--target-list', '-tL',
        help='File containing list of targets (one per line)'
    )
    
    # Scan modes
    parser.add_argument(
        '--mode', '-m',
        choices=['reconnaissance', 'vulnerability-scan', 'web-scan', 'fuzzing', 'comprehensive', 'advanced-bug-hunting'],
        default='comprehensive',
        help='Scanning mode (default: comprehensive)'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        default='./results',
        help='Output directory (default: ./results)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'csv', 'markdown', 'all'],
        default='html',
        help='Output format (default: html)'
    )
    
    # Performance options
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of threads (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=int,
        default=10,
        help='Requests per second rate limit (default: 10)'
    )
    
    # Verbosity and debugging
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-essential output'
    )
    
    # Network options
    parser.add_argument(
        '--user-agent',
        default='OpenManus-BugHunting/1.0 (Security Scanner)',
        help='Custom User-Agent string'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '--headers',
        action='append',
        help='Custom headers in format "Header: Value" (can be used multiple times)'
    )
    
    # Module control
    parser.add_argument(
        '--exclude',
        action='append',
        choices=['reconnaissance', 'vulnerability_scanner', 'web_scanner', 'fuzzer', 'exploits'],
        help='Exclude specific modules (can be used multiple times)'
    )
    
    parser.add_argument(
        '--include-only',
        action='append',
        choices=['reconnaissance', 'vulnerability_scanner', 'web_scanner', 'fuzzer', 'exploits'],
        help='Include only specific modules (can be used multiple times)'
    )
    
    # Advanced Bug Hunting options
    parser.add_argument(
        '--deep-exploitation',
        action='store_true',
        default=True,
        help='Enable deep exploitation techniques (default: enabled)'
    )
    
    parser.add_argument(
        '--business-logic-focus',
        action='store_true',
        default=True,
        help='Focus on business logic vulnerabilities (default: enabled)'
    )
    
    parser.add_argument(
        '--privilege-escalation',
        action='store_true',
        default=True,
        help='Test privilege escalation scenarios (default: enabled)'
    )
    
    parser.add_argument(
        '--stealth-mode',
        action='store_true',
        help='Use stealth techniques to avoid detection'
    )
    
    parser.add_argument(
        '--time-constraint',
        choices=['quick', 'normal', 'thorough'],
        default='normal',
        help='Time constraint for testing (default: normal)'
    )
    
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=10,
        help='Maximum concurrent tests (default: 10)'
    )
    
    parser.add_argument(
        '--ai-guided',
        action='store_true',
        default=True,
        help='Enable AI-guided testing strategies (default: enabled)'
    )
    
    parser.add_argument(
        '--wordlist-optimization',
        action='store_true',
        default=True,
        help='Enable intelligent wordlist optimization (default: enabled)'
    )
    
    # Advanced options
    parser.add_argument(
        '--wordlist',
        help='Custom wordlist file for fuzzing'
    )
    
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--resume',
        help='Resume from previous scan results directory'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner output'
    )
    
    # Reconnaissance specific options
    parser.add_argument(
        '--passive-only',
        action='store_true',
        help='Use only passive reconnaissance techniques'
    )
    
    parser.add_argument(
        '--deep-scan',
        action='store_true',
        help='Enable deep scanning (more thorough but slower)'
    )
    

    

    
    # AI/LLM Configuration
    ai_group = parser.add_argument_group('AI Configuration', 'Options for AI-powered tool selection')
    
    ai_group.add_argument(
        '--llm-model',
        default='gpt-4',
        help='LLM model to use for AI decisions (default: gpt-4)'
    )
    
    ai_group.add_argument(
        '--llm-api-key',
        help='API key for LLM service (or set OPENAI_API_KEY environment variable)'
    )
    
    ai_group.add_argument(
        '--llm-base-url',
        default='https://api.openai.com/v1',
        help='Base URL for LLM API (default: OpenAI)'
    )
    
    ai_group.add_argument(
        '--llm-api-type',
        choices=['openai', 'azure', 'deepseek', 'aws'],
        default='openai',
        help='Type of LLM API to use (default: openai)'
    )
    
    ai_group.add_argument(
        '--disable-ai',
        action='store_true',
        help='Disable AI-powered tool selection (use fallback rules)'
    )
    
    ai_group.add_argument(
        '--ai-temperature',
        type=float,
        default=0.1,
        help='Temperature for AI responses (0.0-1.0, default: 0.1)'
    )
    
    return parser.parse_args()


def normalize_url(url: str) -> str:
    """Normalize URL by adding scheme if missing"""
    if not url.startswith(('http://', 'https://')):
        # Try HTTPS first, fallback to HTTP if needed
        return f"https://{url}"
    return url


def validate_arguments(args):
    """Validate command line arguments"""
    errors = []
    
    # Check target file exists
    if args.target_list and not Path(args.target_list).exists():
        errors.append(f"Target list file not found: {args.target_list}")
    
    # Check wordlist file exists
    if args.wordlist and not Path(args.wordlist).exists():
        errors.append(f"Wordlist file not found: {args.wordlist}")
    
    # Check config file exists
    if args.config and not Path(args.config).exists():
        errors.append(f"Configuration file not found: {args.config}")
    
    # Check resume directory exists
    if args.resume and not Path(args.resume).exists():
        errors.append(f"Resume directory not found: {args.resume}")
    
    # Validate proxy URL format
    if args.proxy:
        if not (args.proxy.startswith('http://') or args.proxy.startswith('https://')):
            errors.append("Proxy URL must start with http:// or https://")
    
    # Check for conflicting options
    if args.exclude and args.include_only:
        errors.append("Cannot use both --exclude and --include-only options")
    
    if args.quiet and args.verbose:
        errors.append("Cannot use both --quiet and --verbose options")
    
    # Validate thread count
    if args.threads < 1 or args.threads > 100:
        errors.append("Thread count must be between 1 and 100")
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 300:
        errors.append("Timeout must be between 1 and 300 seconds")
    
    # Validate rate limit
    if args.rate_limit < 1 or args.rate_limit > 1000:
        errors.append("Rate limit must be between 1 and 1000 requests per second")
    
    return errors


async def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Print banner unless suppressed
    if not args.no_banner:
        print_banner()
    
    # Validate arguments
    validation_errors = validate_arguments(args)
    if validation_errors:
        print("❌ Validation errors:")
        for error in validation_errors:
            print(f"   • {error}")
        return 1
    
    # Setup logging
    if args.quiet:
        log_level = 'ERROR'
    elif args.debug:
        log_level = 'DEBUG'
    elif args.verbose:
        log_level = 'INFO'
    else:
        log_level = 'WARNING'
    
    setup_logging(level=log_level)
    
    logger.info("🚀 Starting OpenManus-BugHunting Platform")
    logger.info(f"📋 Mode: {args.mode}")
    logger.info(f"🎯 Output: {args.output}")
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
            else:
                logger.warning(f"Invalid header format: {header}")
    
    # Initialize LLM client if not disabled
    llm_client = None
    if not args.disable_ai:
        try:
            import os
            import toml
            from app.config import LLMSettings
            
            # Load configuration from config.toml
            config_path = "/home/kali/OpenManus-BugHunting/config/config.toml"
            if not os.path.exists(config_path):
                # Fallback to local config paths
                config_path = "./config/config.toml"
                if not os.path.exists(config_path):
                    config_path = "./config.toml"
            
            if os.path.exists(config_path):
                logger.info(f"📁 Loading configuration from: {config_path}")
                config_data = toml.load(config_path)
                llm_config_data = config_data.get('llm', {})
                
                # Use config file values, override with command line if provided
                api_key = args.llm_api_key or llm_config_data.get('api_key')
                model = args.llm_model if args.llm_model != 'gpt-4' else llm_config_data.get('model', 'deepseek-chat')
                base_url = args.llm_base_url if args.llm_base_url != 'https://api.openai.com/v1' else llm_config_data.get('base_url', 'https://api.deepseek.com/v1')
                api_type = args.llm_api_type or llm_config_data.get('api_type', 'deepseek')
                temperature = args.ai_temperature or llm_config_data.get('temperature', 0.3)
                max_tokens = llm_config_data.get('max_tokens', 4096)
                api_version = llm_config_data.get('api_version', 'v1')
                
                if api_key and api_key != "your-api-key-here":
                    # Create LLM config
                    llm_config = LLMSettings(
                        model=model,
                        api_key=api_key,
                        base_url=base_url,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        api_type=api_type,
                        api_version=api_version
                    )
                    
                    # Create LLM instance with config
                    llm_client = LLM(config_name="custom", llm_config={"custom": llm_config})
                    logger.info(f"🤖 AI-powered tool selection enabled with {model} ({api_type})")
                else:
                    logger.warning("⚠️  No valid API key found in configuration file")
                    logger.warning("   Please update the api_key in config/config.toml")
            else:
                logger.warning("⚠️  Configuration file not found, using command line arguments")
                # Fallback to command line arguments
                if args.llm_api_type == 'deepseek':
                    api_key = args.llm_api_key or os.getenv('DEEPSEEK_API_KEY')
                    default_base_url = 'https://api.deepseek.com/v1'
                    default_model = 'deepseek-chat'
                else:
                    api_key = args.llm_api_key or os.getenv('OPENAI_API_KEY')
                    default_base_url = 'https://api.openai.com/v1'
                    default_model = 'gpt-4'
                
                if api_key:
                    llm_config = LLMSettings(
                        model=args.llm_model if args.llm_model != 'gpt-4' else default_model,
                        api_key=api_key,
                        base_url=args.llm_base_url if args.llm_base_url != 'https://api.openai.com/v1' else default_base_url,
                        temperature=args.ai_temperature,
                        max_tokens=4000,
                        api_type=args.llm_api_type,
                        api_version="v1"
                    )
                    llm_client = LLM(config_name="custom", llm_config={"custom": llm_config})
                    logger.info(f"🤖 AI-powered tool selection enabled with {args.llm_model}")
                else:
                    logger.warning("⚠️  No API key found in arguments or environment variables")
        except Exception as e:
            logger.error(f"❌ Failed to initialize LLM client: {e}")
            logger.warning("🔄 Falling back to rule-based tool selection")
    else:
        logger.info("🔧 AI features disabled, using rule-based tool selection")
    
    # Initialize orchestrator
    orchestrator_config = {
        'output_dir': args.output,
        'threads': args.threads,
        'timeout': args.timeout,
        'rate_limit': args.rate_limit,
        'user_agent': args.user_agent,
        'proxy': args.proxy,
        'custom_headers': custom_headers,
        'passive_only': args.passive_only,
        'deep_scan': args.deep_scan,
        'wordlist': args.wordlist
    }
    
    orchestrator = SecurityOrchestrator(llm_client=llm_client, config=orchestrator_config)
    
    try:
        # Prepare targets
        targets = []
        if args.target:
            targets = [normalize_url(args.target)]
        elif args.target_list:
            logger.info(f"📂 Loading targets from {args.target_list}")
            with open(args.target_list, 'r') as f:
                targets = [normalize_url(line.strip()) for line in f if line.strip() and not line.startswith('#')]
        
        if not targets:
            logger.error("❌ No targets specified")
            return 1
        
        logger.info(f"🎯 Processing {len(targets)} target(s)")
        
        # Determine modules to run
        excluded_modules = args.exclude or []
        included_modules = args.include_only
        
        # Run assessment for each target
        all_results = []
        for target in targets:
            logger.info(f"🎯 Starting assessment for target: {target}")
            
            # Check if advanced bug hunting mode is requested
            if args.mode == 'advanced-bug-hunting':
                # Create advanced bug hunting configuration
                bug_hunting_config = BugHuntingConfig(
                    target=target.replace('https://', '').replace('http://', ''),
                    deep_exploitation=args.deep_exploitation,
                    business_logic_focus=args.business_logic_focus,
                    privilege_escalation=args.privilege_escalation,
                    stealth_mode=args.stealth_mode,
                    time_constraint=args.time_constraint,
                    max_concurrent_tests=args.max_concurrent,
                    ai_guided=args.ai_guided,
                    wordlist_optimization=args.wordlist_optimization
                )
                
                # Initialize advanced bug hunting orchestrator
                advanced_orchestrator = AdvancedBugHuntingOrchestrator(
                    config=bug_hunting_config,
                    llm_client=llm_client
                )
                
                logger.info("🔥 Starting advanced bug hunting campaign")
                result = await advanced_orchestrator.execute_comprehensive_bug_hunt()
                
                # Add metadata for compatibility
                result['target'] = target
                result['mode'] = 'advanced-bug-hunting'
                result['status'] = 'completed' if 'error' not in result else 'failed'
                
            else:
                # Use standard orchestrator
                result = await orchestrator.run_comprehensive_assessment(
                    target=target,
                    scan_mode=args.mode,
                    passive_only=args.passive_only,
                    deep_scan=args.deep_scan,
                    stealth_mode=args.stealth_mode,
                    time_constraint=args.time_constraint,
                    output_dir=args.output,
                    report_format=args.format
                )
            
            all_results.append(result)
            
            if not args.quiet:
                status = "✅" if result.get('status') == 'completed' else "❌"
                print(f"{status} {target}: {result.get('status', 'unknown')}")
                
                # Show advanced bug hunting summary
                if args.mode == 'advanced-bug-hunting' and result.get('status') == 'completed':
                    summary = result.get('execution_summary', {})
                    print(f"   🔍 Vulnerabilities: {summary.get('vulnerabilities_discovered', 0)}")
                    print(f"   🔗 Chains: {summary.get('vulnerability_chains_found', 0)}")
                    print(f"   🎯 Attack Paths: {summary.get('attack_paths_identified', 0)}")
                    print(f"   ⚠️  Critical: {summary.get('critical_findings', 0)}")
                    print(f"   ⏱️  Time: {summary.get('total_execution_time', 0):.1f}s")
        
        # Aggregate results
        results = {
            'targets': targets,
            'individual_results': all_results,
            'summary': {
                'total_targets': len(targets),
                'successful': len([r for r in all_results if r.get('status') == 'completed']),
                'failed': len([r for r in all_results if r.get('status') == 'failed']),
                'total_vulnerabilities': sum(r.get('results', {}).get('vulnerability_analysis', {}).get('total_vulnerabilities', 0) for r in all_results),
                'overall_risk_level': 'Unknown'
            }
        }
        
        # Determine overall risk level
        risk_levels = [r.get('results', {}).get('vulnerability_analysis', {}).get('risk_level', 'Unknown') for r in all_results]
        if 'Critical' in risk_levels:
            results['summary']['overall_risk_level'] = 'Critical'
        elif 'High' in risk_levels:
            results['summary']['overall_risk_level'] = 'High'
        elif 'Medium' in risk_levels:
            results['summary']['overall_risk_level'] = 'Medium'
        elif 'Low' in risk_levels:
            results['summary']['overall_risk_level'] = 'Low'
        
        # Print summary
        if not args.quiet:
            print("\n" + "="*60)
            print("🎉 ASSESSMENT COMPLETED SUCCESSFULLY")
            print("="*60)
            print(f"📊 Targets processed: {len(targets)}")
            print(f"📁 Results saved to: {args.output}")
            
            # Print basic statistics if available
            if results and 'summary' in results:
                summary = results['summary']
                print(f"🎯 Successful targets: {summary.get('successful', 0)}/{summary.get('total_targets', 0)}")
                if summary.get('total_vulnerabilities', 0) > 0:
                    print(f"⚠️  Total vulnerabilities: {summary['total_vulnerabilities']}")
                if summary.get('overall_risk_level') != 'Unknown':
                    print(f"📈 Overall risk level: {summary['overall_risk_level']}")
                
                # Show AI usage if enabled
                if llm_client:
                    print(f"🤖 AI-powered tool selection: Enabled ({args.llm_model})")
                else:
                    print(f"🔧 Tool selection: Rule-based fallback")
            
            print("="*60)
        
        logger.info("✅ Assessment completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.warning("⚠️  Assessment interrupted by user")
        print("\n🛑 Assessment interrupted by user")
        return 130
    except FileNotFoundError as e:
        logger.error(f"❌ File not found: {e}")
        print(f"❌ File not found: {e}")
        return 2
    except PermissionError as e:
        logger.error(f"❌ Permission denied: {e}")
        print(f"❌ Permission denied: {e}")
        return 3
    except Exception as e:
        logger.error(f"❌ Assessment failed: {e}")
        print(f"❌ Assessment failed: {e}")
        if args.debug:
            import traceback
            print("\n🐛 Debug traceback:")
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        sys.exit(130)
