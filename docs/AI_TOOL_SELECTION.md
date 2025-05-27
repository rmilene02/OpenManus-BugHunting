# AI-Powered Tool Selection

OpenManus-BugHunting features an advanced AI-powered tool selection system that intelligently chooses the most appropriate security tools based on the target characteristics, scan objectives, and available resources.

## Overview

Instead of using fixed tool combinations, the AI analyzes the context and makes informed decisions about which tools to use for each phase of the security assessment. This approach provides:

- **Intelligent Adaptation**: Tools are selected based on target type, scan mode, and constraints
- **Context Awareness**: AI considers stealth requirements, time constraints, and passive-only modes
- **Dynamic Optimization**: Tool selection adapts to available resources and previous results
- **Learning Capability**: The system learns from previous selections to improve future decisions

## How It Works

### 1. Target Analysis
The AI first analyzes the target to understand its characteristics:
- **Target Type**: Domain, IP address, URL, or network range
- **Technology Stack**: Detected technologies and frameworks
- **Service Profile**: Available services and ports
- **Security Posture**: WAF detection, rate limiting, etc.

### 2. Context Evaluation
The scan context is evaluated to understand requirements:
- **Scan Mode**: Reconnaissance, vulnerability scanning, web testing, etc.
- **Constraints**: Passive-only, stealth mode, time limitations
- **Objectives**: Deep scanning, quick assessment, compliance checking
- **Resources**: Available tools, network access, privileges

### 3. Tool Selection
Based on the analysis, the AI selects optimal tools for each category:
- **Subdomain Enumeration**: subfinder, amass, assetfinder, etc.
- **Web Discovery**: httpx, whatweb, wafw00f, etc.
- **Network Scanning**: nmap, masscan, zmap, etc.
- **Vulnerability Scanning**: nuclei, nikto, etc.
- **Directory Enumeration**: gobuster, ffuf, wfuzz, etc.
- **OSINT**: theharvester, etc.

## Configuration

### LLM Setup

#### OpenAI (Default)
```bash
export OPENAI_API_KEY="your-api-key-here"

# Run with AI-powered tool selection
python main.py example.com --llm-model gpt-4
```

#### Custom LLM Provider
```bash
# Use a different LLM provider
python main.py example.com \
    --llm-model gpt-3.5-turbo \
    --llm-base-url https://api.custom-provider.com/v1 \
    --llm-api-key your-custom-key
```

#### Disable AI (Fallback to Rules)
```bash
# Use rule-based tool selection
python main.py example.com --disable-ai
```

## Usage Examples

### Basic AI-Powered Scan
```bash
# Comprehensive AI-powered assessment
python main.py example.com --mode comprehensive

# AI will analyze the target and select appropriate tools
```

### Stealth Mode with AI
```bash
# AI will prioritize stealth tools
python main.py example.com --stealth-mode --passive-only

# Selected tools will focus on passive techniques
```

### Fast Reconnaissance
```bash
# AI will select fast, efficient tools
python main.py example.com --mode reconnaissance --time-constraint fast

# Optimized for speed over thoroughness
```

### Deep Security Assessment
```bash
# AI will select comprehensive, thorough tools
python main.py example.com --deep-scan --time-constraint thorough

# Maximum coverage and accuracy
```

## Best Practices

### 1. API Key Security
- Use environment variables for API keys
- Rotate keys regularly
- Monitor API usage and costs

### 2. Model Selection
- **GPT-4**: Best accuracy, higher cost
- **GPT-3.5-turbo**: Good balance, lower cost
- **Local models**: Privacy, no API costs

### 3. Temperature Settings
- **0.0-0.2**: Consistent, deterministic decisions
- **0.3-0.7**: Balanced creativity and consistency
- **0.8-1.0**: More creative but less predictable

For complete documentation, see the full AI_TOOL_SELECTION.md file.