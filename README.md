# OpenManus-BugHunting

<div align="center">

```
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
╚═══════════════════════════════════════════════════════════════╝
```

**Advanced Cybersecurity Toolkit for Bug Hunters, Penetration Testers & Security Researchers**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Testing-red.svg)](https://github.com/Lucas80061/OpenManus-BugHunting)

</div>

## 🎯 Overview

OpenManus-BugHunting is a comprehensive cybersecurity platform designed specifically for bug hunting, vulnerability analysis, penetration testing, and security assessments. This toolkit integrates multiple security testing methodologies and tools to provide a complete solution for security professionals and researchers.

### 🔥 Key Features

- **🤖 AI-Powered Tool Selection**: Intelligent tool selection using LLM analysis for optimal security assessments
- **🔍 Comprehensive Reconnaissance**: Advanced subdomain enumeration, technology detection, and OSINT gathering
- **🕷️ Web Application Testing**: Automated vulnerability scanning, fuzzing, and exploitation testing
- **💥 Payload Generation**: Advanced payload creation for various attack vectors
- **🛡️ Vulnerability Scanning**: Integration with popular security tools and custom scanners
- **📊 Professional Reporting**: Detailed reports with risk assessment and remediation guidance
- **🧠 Context-Aware Scanning**: Adaptive tool selection based on target type and scan objectives
- **🔧 Kali Linux Integration**: Seamless integration with individual security tools and methodologies

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Kali Linux (recommended) or any Linux distribution
- Basic security tools (nmap, nikto, gobuster, etc.)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Lucas80061/OpenManus-BugHunting.git
cd OpenManus-BugHunting
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install additional security tools (on Kali Linux):**
```bash
sudo apt update
sudo apt install -y nmap nikto gobuster wfuzz ffuf nuclei subfinder amass
```

### Basic Usage

```bash
# Comprehensive assessment of a single target
python main.py --target example.com --mode comprehensive

# Reconnaissance only
python main.py --target example.com --mode reconnaissance

# Web application testing
python main.py --target https://example.com --mode web-scan

# Vulnerability scanning from target list
python main.py --target-list targets.txt --mode vulnerability-scan
```

## 📋 Scanning Modes

### 🔍 Reconnaissance Mode
- Subdomain enumeration using multiple tools
- Technology detection and fingerprinting
- OSINT gathering and information collection
- DNS analysis and zone transfers
- Port scanning and service detection

### 🛡️ Vulnerability Scanning Mode
- Automated vulnerability detection
- CVE matching and severity assessment
- Configuration security analysis
- SSL/TLS security testing
- Network service enumeration

### 🕷️ Web Application Scanning Mode
- XSS (Cross-Site Scripting) testing
- SQL injection detection
- Command injection testing
- File inclusion vulnerabilities
- Directory and file enumeration
- Authentication bypass testing

### 💥 Fuzzing Mode
- Parameter fuzzing and discovery
- Input validation testing
- Boundary condition testing
- File upload security testing
- Header injection testing

### 🎯 Comprehensive Mode
- All of the above combined
- Intelligent tool selection
- Optimized scanning workflow
- Complete security assessment

## 🤖 AI-Powered Tool Selection

OpenManus-BugHunting features an advanced AI system that intelligently selects the most appropriate security tools based on target analysis and scan context.

### How It Works

The AI analyzes:
- **Target characteristics** (domain, IP, technology stack)
- **Scan objectives** (reconnaissance, vulnerability assessment, web testing)
- **Constraints** (passive-only, stealth mode, time limits)
- **Available resources** (tools, network access, privileges)

Based on this analysis, it selects optimal tools for each category and determines the best execution order.

### Usage Examples

```bash
# AI-powered comprehensive assessment
export OPENAI_API_KEY="your-api-key"
python main.py example.com --llm-model gpt-4

# Use DeepSeek AI (cost-effective alternative)
python main.py example.com \
    --llm-model deepseek-chat \
    --llm-base-url https://api.deepseek.com/v1 \
    --llm-api-key your-deepseek-key

# Stealth mode - AI will prioritize passive tools
python main.py example.com --stealth-mode --passive-only

# Fast scan - AI will select efficient tools
python main.py example.com --time-constraint fast

# Disable AI and use rule-based selection
python main.py example.com --disable-ai
```

### Supported LLM Providers

- **OpenAI**: GPT-4, GPT-3.5-turbo (default)
- **DeepSeek**: deepseek-chat (cost-effective)
- **Azure OpenAI**: Enterprise-grade
- **Local models**: Ollama, LM Studio
- **Custom providers**: Any OpenAI-compatible API

For detailed AI configuration, see [AI Tool Selection Guide](docs/AI_TOOL_SELECTION.md).

## 🛠️ Advanced Features

### ReconFTW Integration
OpenManus-BugHunting integrates seamlessly with reconFTW methodology:

```bash
# Use reconFTW tools for comprehensive reconnaissance
python main.py --target example.com --mode reconnaissance --deep-scan

# Passive reconnaissance only
python main.py --target example.com --mode reconnaissance --passive-only
```

### Custom Payload Generation
Generate various types of security payloads:

```python
from app.exploits.payload_generator import PayloadGenerator

generator = PayloadGenerator()

# Generate reverse shells
shells = generator.generate_reverse_shells("10.0.0.1", 4444)

# Generate XSS payloads
xss_payloads = generator.generate_xss_payloads()

# Generate SQL injection payloads
sqli_payloads = generator.generate_sqli_payloads()
```

### Professional Reporting
Generate comprehensive security reports:

```bash
# Generate HTML report
python main.py --target example.com --format html

# Generate all formats (HTML, JSON, CSV, Markdown)
python main.py --target example.com --format all

# Custom output directory
python main.py --target example.com --output /path/to/results
```

## 🏗️ Architecture

### Core Components

```
OpenManus-BugHunting/
├── app/
│   ├── core/                    # Core orchestration and management
│   │   ├── orchestrator.py      # Main assessment orchestrator
│   │   └── config.py            # Configuration management
│   ├── reconnaissance/          # Reconnaissance modules
│   │   ├── kali_tools.py        # Kali Linux tools integration
│   │   ├── reconftw_integration.py # ReconFTW methodology
│   │   └── osint_collector.py   # OSINT gathering
│   ├── vulnerability_scanner/   # Vulnerability scanning
│   │   ├── nuclei_scanner.py    # Nuclei integration
│   │   ├── nmap_scanner.py      # Nmap integration
│   │   └── custom_scanner.py    # Custom vulnerability checks
│   ├── web_scanner/            # Web application testing
│   │   ├── xss_scanner.py       # XSS detection
│   │   ├── sqli_scanner.py      # SQL injection testing
│   │   └── lfi_scanner.py       # File inclusion testing
│   ├── fuzzer/                 # Fuzzing modules
│   │   ├── web_fuzzer.py        # Web application fuzzing
│   │   └── parameter_fuzzer.py  # Parameter discovery
│   ├── exploits/               # Exploitation modules
│   │   ├── payload_generator.py # Payload generation
│   │   └── exploit_framework.py # Exploitation framework
│   ├── reporting/              # Reporting system
│   │   ├── report_generator.py  # Report generation
│   │   └── vulnerability_analyzer.py # Vulnerability analysis
│   └── utils/                  # Utility modules
│       ├── network.py           # Network utilities
│       └── file_utils.py        # File handling utilities
├── main.py                     # Main entry point
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Project Demo

<video src="https://private-user-images.githubusercontent.com/61239030/420168772-6dcfd0d2-9142-45d9-b74e-d10aa75073c6.mp4?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDEzMTgwNTksIm5iZiI6MTc0MTMxNzc1OSwicGF0aCI6Ii82MTIzOTAzMC80MjAxNjg3NzItNmRjZmQwZDItOTE0Mi00NWQ5LWI3NGUtZDEwYWE3NTA3M2M2Lm1wND9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNTAzMDclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjUwMzA3VDAzMjIzOVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTdiZjFkNjlmYWNjMmEzOTliM2Y3M2VlYjgyNDRlZDJmOWE3NWZhZjE1MzhiZWY4YmQ3NjdkNTYwYTU5ZDA2MzYmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.UuHQCgWYkh0OQq9qsUWqGsUbhG3i9jcZDAMeHjLt5T4" data-canonical-src="https://private-user-images.githubusercontent.com/61239030/420168772-6dcfd0d2-9142-45d9-b74e-d10aa75073c6.mp4?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDEzMTgwNTksIm5iZiI6MTc0MTMxNzc1OSwicGF0aCI6Ii82MTIzOTAzMC80MjAxNjg3NzItNmRjZmQwZDItOTE0Mi00NWQ5LWI3NGUtZDEwYWE3NTA3M2M2Lm1wND9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNTAzMDclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjUwMzA3VDAzMjIzOVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTdiZjFkNjlmYWNjMmEzOTliM2Y3M2VlYjgyNDRlZDJmOWE3NWZhZjE1MzhiZWY4YmQ3NjdkNTYwYTU5ZDA2MzYmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.UuHQCgWYkh0OQq9qsUWqGsUbhG3i9jcZDAMeHjLt5T4" controls="controls" muted="muted" class="d-block rounded-bottom-2 border-top width-fit" style="max-height:640px; min-height: 200px"></video>

## Installation

We provide two installation methods. Method 2 (using uv) is recommended for faster installation and better dependency management.

### Method 1: Using conda

1. Create a new conda environment:

```bash
conda create -n open_manus python=3.12
conda activate open_manus
```

2. Clone the repository:

```bash
git clone https://github.com/FoundationAgents/OpenManus.git
cd OpenManus
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

### Method 2: Using uv (Recommended)

1. Install uv (A fast Python package installer and resolver):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Clone the repository:

```bash
git clone https://github.com/FoundationAgents/OpenManus.git
cd OpenManus
```

3. Create a new virtual environment and activate it:

```bash
uv venv --python 3.12
source .venv/bin/activate  # On Unix/macOS
# Or on Windows:
# .venv\Scripts\activate
```

4. Install dependencies:

```bash
uv pip install -r requirements.txt
```

### Browser Automation Tool (Optional)
```bash
playwright install
```

## Configuration

OpenManus requires configuration for the LLM APIs it uses. Follow these steps to set up your configuration:

1. Create a `config.toml` file in the `config` directory (you can copy from the example):

```bash
cp config/config.example.toml config/config.toml
```

2. Edit `config/config.toml` to add your API keys and customize settings:

```toml
# Global LLM configuration
[llm]
model = "gpt-4o"
base_url = "https://api.openai.com/v1"
api_key = "sk-..."  # Replace with your actual API key
max_tokens = 4096
temperature = 0.0

# Optional configuration for specific LLM models
[llm.vision]
model = "gpt-4o"
base_url = "https://api.openai.com/v1"
api_key = "sk-..."  # Replace with your actual API key
```

## Quick Start

One line for run OpenManus:

```bash
python main.py
```

Then input your idea via terminal!

For MCP tool version, you can run:
```bash
python run_mcp.py
```

For unstable multi-agent version, you also can run:

```bash
python run_flow.py
```

## How to contribute

We welcome any friendly suggestions and helpful contributions! Just create issues or submit pull requests.

Or contact @mannaandpoem via 📧email: mannaandpoem@gmail.com

**Note**: Before submitting a pull request, please use the pre-commit tool to check your changes. Run `pre-commit run --all-files` to execute the checks.

## Community Group
Join our networking group on Feishu and share your experience with other developers!

<div align="center" style="display: flex; gap: 20px;">
    <img src="assets/community_group.jpg" alt="OpenManus 交流群" width="300" />
</div>

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=FoundationAgents/OpenManus&type=Date)](https://star-history.com/#FoundationAgents/OpenManus&Date)

## Sponsors
Thanks to [PPIO](https://ppinfra.com/user/register?invited_by=OCPKCN&utm_source=github_openmanus&utm_medium=github_readme&utm_campaign=link) for computing source support.
> PPIO: The most affordable and easily-integrated MaaS and GPU cloud solution.


## Acknowledgement

Thanks to [anthropic-computer-use](https://github.com/anthropics/anthropic-quickstarts/tree/main/computer-use-demo)
and [browser-use](https://github.com/browser-use/browser-use) for providing basic support for this project!

Additionally, we are grateful to [AAAJ](https://github.com/metauto-ai/agent-as-a-judge), [MetaGPT](https://github.com/geekan/MetaGPT), [OpenHands](https://github.com/All-Hands-AI/OpenHands) and [SWE-agent](https://github.com/SWE-agent/SWE-agent).

We also thank stepfun(阶跃星辰) for supporting our Hugging Face demo space.

OpenManus is built by contributors from MetaGPT. Huge thanks to this agent community!

## Cite
```bibtex
@misc{openmanus2025,
  author = {Xinbin Liang and Jinyu Xiang and Zhaoyang Yu and Jiayi Zhang and Sirui Hong and Sheng Fan and Xiao Tang},
  title = {OpenManus: An open-source framework for building general AI agents},
  year = {2025},
  publisher = {Zenodo},
  doi = {10.5281/zenodo.15186407},
  url = {https://doi.org/10.5281/zenodo.15186407},
}
```
