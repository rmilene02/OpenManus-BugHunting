# OpenManus-BugHunting Usage Guide

This guide provides detailed instructions on how to use OpenManus-BugHunting for various security testing scenarios.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Command Line Interface](#command-line-interface)
3. [Scanning Modes](#scanning-modes)
4. [Configuration](#configuration)
5. [Examples](#examples)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Scan
```bash
# Simple reconnaissance scan
python main.py --target example.com --mode reconnaissance

# Comprehensive security assessment
python main.py --target example.com --mode comprehensive
```

### Multiple Targets
```bash
# Create a target list file
echo "example.com" > targets.txt
echo "test.example.com" >> targets.txt

# Scan multiple targets
python main.py --target-list targets.txt --mode comprehensive
```

## Command Line Interface

### Target Specification
```bash
# Single target
--target example.com
--target https://example.com
--target 192.168.1.100

# Multiple targets from file
--target-list targets.txt
```

### Scanning Modes
```bash
# Reconnaissance only
--mode reconnaissance

# Vulnerability scanning
--mode vulnerability-scan

# Web application testing
--mode web-scan

# Fuzzing
--mode fuzzing

# Complete assessment
--mode comprehensive
```

### Output Options
```bash
# Specify output directory
--output /path/to/results

# Choose report format
--format html          # HTML report (default)
--format json          # JSON format
--format csv           # CSV format
--format markdown      # Markdown format
--format all           # All formats

# Control verbosity
--verbose              # Verbose output
--quiet                # Minimal output
--debug                # Debug information
```

### Performance Tuning
```bash
# Adjust threading
--threads 20           # Use 20 threads

# Set timeouts
--timeout 60           # 60 second timeout

# Rate limiting
--rate-limit 5         # 5 requests per second
```

### Network Options
```bash
# Use proxy
--proxy http://127.0.0.1:8080

# Custom User-Agent
--user-agent "Custom Scanner/1.0"

# Custom headers
--headers "X-Custom: Value"
--headers "Authorization: Bearer token"
```

### Module Control
```bash
# Exclude specific modules
--exclude fuzzer
--exclude exploits

# Include only specific modules
--include-only reconnaissance
--include-only web_scanner
```

## Scanning Modes

### 1. Reconnaissance Mode

**Purpose**: Gather information about the target without active exploitation.

**What it does**:
- Subdomain enumeration
- Technology detection
- OSINT gathering
- DNS analysis
- Port scanning

**Example**:
```bash
python main.py --target example.com --mode reconnaissance --verbose
```

**Advanced options**:
```bash
# Deep reconnaissance (slower but more thorough)
python main.py --target example.com --mode reconnaissance --deep-scan

# Passive only (no active scanning)
python main.py --target example.com --mode reconnaissance --passive-only
```

### 2. Vulnerability Scanning Mode

**Purpose**: Identify security vulnerabilities in the target.

**What it does**:
- CVE detection
- Configuration analysis
- Service enumeration
- SSL/TLS testing

**Example**:
```bash
python main.py --target example.com --mode vulnerability-scan
```

### 3. Web Application Scanning Mode

**Purpose**: Test web applications for common vulnerabilities.

**What it does**:
- XSS testing
- SQL injection detection
- Command injection testing
- File inclusion testing
- Directory enumeration

**Example**:
```bash
python main.py --target https://example.com --mode web-scan
```

### 4. Fuzzing Mode

**Purpose**: Discover hidden functionality and test input validation.

**What it does**:
- Parameter discovery
- Directory/file fuzzing
- Input validation testing
- Boundary testing

**Example**:
```bash
python main.py --target https://example.com --mode fuzzing --wordlist /path/to/wordlist.txt
```

### 5. Comprehensive Mode

**Purpose**: Complete security assessment using all modules.

**What it does**:
- All of the above
- Intelligent tool selection
- Optimized workflow

**Example**:
```bash
python main.py --target example.com --mode comprehensive --format all
```

## Configuration

### Configuration File

Create a `config.yaml` file to customize default settings:

```yaml
global:
  threads: 10
  timeout: 30
  rate_limit: 10

reconnaissance:
  deep_scan: false
  passive_only: false

web_scanner:
  xss:
    enabled: true
  sqli:
    enabled: true

fuzzer:
  web:
    wordlist: "/usr/share/wordlists/dirb/common.txt"
    max_depth: 3
```

### Environment Variables

Set environment variables for API keys:

```bash
export SHODAN_API_KEY="your_shodan_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
```

## Examples

### Example 1: Bug Bounty Reconnaissance

```bash
# Comprehensive reconnaissance for bug bounty
python main.py \
  --target hackerone.com \
  --mode reconnaissance \
  --deep-scan \
  --output ./results/hackerone \
  --format all \
  --verbose
```

### Example 2: Web Application Penetration Test

```bash
# Full web application assessment
python main.py \
  --target https://webapp.example.com \
  --mode comprehensive \
  --threads 15 \
  --timeout 45 \
  --output ./pentest_results \
  --format html
```

### Example 3: Internal Network Scan

```bash
# Internal network vulnerability assessment
python main.py \
  --target-list internal_targets.txt \
  --mode vulnerability-scan \
  --threads 5 \
  --rate-limit 2 \
  --output ./internal_scan
```

### Example 4: API Security Testing

```bash
# API endpoint testing
python main.py \
  --target https://api.example.com \
  --mode web-scan \
  --headers "Authorization: Bearer your_token" \
  --headers "Content-Type: application/json" \
  --exclude fuzzer
```

### Example 5: Stealth Reconnaissance

```bash
# Low-profile reconnaissance
python main.py \
  --target example.com \
  --mode reconnaissance \
  --passive-only \
  --rate-limit 1 \
  --timeout 60 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

## Best Practices

### 1. Authorization and Legal Compliance

- **Always obtain written permission** before testing any target
- Respect scope limitations and rules of engagement
- Follow responsible disclosure practices
- Document all testing activities

### 2. Performance and Reliability

- Start with reconnaissance mode to understand the target
- Use appropriate thread counts (don't overwhelm the target)
- Implement rate limiting to avoid triggering security controls
- Monitor target response times and adjust accordingly

### 3. Operational Security

- Use VPNs or proxies when appropriate
- Rotate User-Agent strings
- Implement random delays between requests
- Monitor for detection and blocking

### 4. Result Management

- Use descriptive output directory names
- Generate multiple report formats for different audiences
- Backup results regularly
- Implement proper data retention policies

### 5. Tool Integration

- Combine with manual testing techniques
- Validate automated findings manually
- Use multiple tools for verification
- Stay updated with latest security tools and techniques

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
```bash
# Solution: Check file permissions
chmod +x main.py
chmod +x install.sh
```

#### 2. Module Import Errors
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# Or reinstall in virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 3. Tool Not Found Errors
```bash
# Solution: Install missing tools (on Kali Linux)
sudo apt update
sudo apt install nmap nikto gobuster nuclei subfinder
```

#### 4. Network Connectivity Issues
```bash
# Test basic connectivity
ping example.com

# Check DNS resolution
nslookup example.com

# Test with proxy
python main.py --target example.com --proxy http://127.0.0.1:8080
```

#### 5. Rate Limiting or Blocking
```bash
# Reduce scan intensity
python main.py --target example.com --threads 1 --rate-limit 1 --timeout 60

# Use different User-Agent
python main.py --target example.com --user-agent "Mozilla/5.0..."
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
python main.py --target example.com --debug
```

### Log Analysis

Check log files for detailed error information:

```bash
# View recent logs
tail -f logs/openmanus.log

# Search for errors
grep -i error logs/openmanus.log
```

### Getting Help

1. Check the documentation and examples
2. Review the configuration file
3. Enable debug mode for detailed output
4. Check GitHub issues for similar problems
5. Create a new issue with detailed information

## Advanced Usage

### Custom Wordlists

```bash
# Use custom wordlist for fuzzing
python main.py \
  --target example.com \
  --mode fuzzing \
  --wordlist /path/to/custom_wordlist.txt
```

### Resume Interrupted Scans

```bash
# Resume from previous results
python main.py \
  --target example.com \
  --resume /path/to/previous/results
```

### Integration with Other Tools

```bash
# Export results for other tools
python main.py --target example.com --format json

# Use results with other security tools
cat results/example.com/subdomains.txt | httpx -silent
```

### Automation and Scripting

```bash
#!/bin/bash
# Automated scanning script

TARGETS=("example1.com" "example2.com" "example3.com")

for target in "${TARGETS[@]}"; do
    echo "Scanning $target..."
    python main.py \
      --target "$target" \
      --mode comprehensive \
      --output "./results/$target" \
      --format all \
      --quiet
done
```

## Conclusion

OpenManus-BugHunting provides a comprehensive platform for security testing. By following this usage guide and best practices, you can effectively use the tool for various security assessment scenarios while maintaining ethical and legal compliance.

Remember: **Always test responsibly and only on authorized targets!**