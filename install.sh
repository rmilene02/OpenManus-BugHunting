#!/bin/bash

# OpenManus-BugHunting Installation Script
# This script installs OpenManus-BugHunting and its dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
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
EOF
    echo -e "${NC}"
    echo -e "${GREEN}OpenManus-BugHunting Installation Script${NC}"
    echo ""
}

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may not work as expected."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check OS
check_os() {
    print_status "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if command -v apt-get &> /dev/null; then
            DISTRO="debian"
        elif command -v yum &> /dev/null; then
            DISTRO="redhat"
        elif command -v pacman &> /dev/null; then
            DISTRO="arch"
        else
            DISTRO="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    else
        OS="unknown"
        DISTRO="unknown"
    fi
    
    print_status "Detected OS: $OS ($DISTRO)"
    
    if [[ "$DISTRO" == "debian" ]]; then
        print_status "Debian/Ubuntu-based system detected. Kali Linux tools will be available."
    elif [[ "$OS" != "linux" ]]; then
        print_warning "Non-Linux system detected. Some security tools may not be available."
    fi
}

# Check Python version
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        print_status "Found Python $PYTHON_VERSION"
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
            print_status "Python version is compatible"
        else
            print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_status "pip3 is available"
    else
        print_error "pip3 is not installed"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    case $DISTRO in
        "debian")
            print_status "Updating package list..."
            sudo apt-get update -qq
            
            print_status "Installing basic dependencies..."
            sudo apt-get install -y \
                python3-pip \
                python3-venv \
                python3-dev \
                build-essential \
                libssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                git \
                curl \
                wget \
                unzip
            
            print_status "Installing security tools..."
            sudo apt-get install -y \
                nmap \
                nikto \
                gobuster \
                dirb \
                wfuzz \
                ffuf \
                nuclei \
                subfinder \
                amass \
                dnsrecon \
                fierce \
                theharvester \
                whatweb \
                wafw00f \
                sqlmap \
                wpscan \
                masscan \
                zmap \
                whois \
                dig \
                netcat-traditional
            ;;
        "redhat")
            print_status "Installing dependencies for RedHat/CentOS..."
            sudo yum install -y \
                python3-pip \
                python3-devel \
                gcc \
                openssl-devel \
                libffi-devel \
                libxml2-devel \
                libxslt-devel \
                zlib-devel \
                git \
                curl \
                wget \
                unzip \
                nmap \
                whois \
                bind-utils
            ;;
        "arch")
            print_status "Installing dependencies for Arch Linux..."
            sudo pacman -S --noconfirm \
                python-pip \
                python-virtualenv \
                base-devel \
                openssl \
                libffi \
                libxml2 \
                libxslt \
                zlib \
                git \
                curl \
                wget \
                unzip \
                nmap \
                whois \
                bind-tools
            ;;
        "macos")
            print_status "Installing dependencies for macOS..."
            if command -v brew &> /dev/null; then
                brew install python3 nmap
            else
                print_warning "Homebrew not found. Please install it first: https://brew.sh/"
            fi
            ;;
        *)
            print_warning "Unknown distribution. Please install dependencies manually."
            ;;
    esac
}

# Create virtual environment
create_venv() {
    print_status "Creating Python virtual environment..."
    
    if [[ -d "venv" ]]; then
        print_warning "Virtual environment already exists. Removing..."
        rm -rf venv
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    
    print_status "Upgrading pip..."
    pip install --upgrade pip
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if [[ ! -f "requirements.txt" ]]; then
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Install requirements
    pip install -r requirements.txt
    
    print_status "Python dependencies installed successfully"
}

# Install additional tools
install_additional_tools() {
    print_status "Installing additional security tools..."
    
    # Create tools directory
    mkdir -p tools
    cd tools
    
    # Install Go tools (if Go is available)
    if command -v go &> /dev/null; then
        print_status "Installing Go-based tools..."
        
        # Install httpx
        if ! command -v httpx &> /dev/null; then
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        fi
        
        # Install subfinder
        if ! command -v subfinder &> /dev/null; then
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        fi
        
        # Install nuclei
        if ! command -v nuclei &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        fi
        
        # Install ffuf
        if ! command -v ffuf &> /dev/null; then
            go install github.com/ffuf/ffuf@latest
        fi
        
        # Add Go bin to PATH if not already there
        if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
            export PATH=$PATH:$HOME/go/bin
        fi
    else
        print_warning "Go not found. Some tools will not be installed."
    fi
    
    cd ..
}

# Setup configuration
setup_config() {
    print_status "Setting up configuration..."
    
    # Copy example config if config doesn't exist
    if [[ ! -f "config.yaml" ]]; then
        if [[ -f "config.example.yaml" ]]; then
            cp config.example.yaml config.yaml
            print_status "Created config.yaml from example"
        else
            print_warning "config.example.yaml not found"
        fi
    else
        print_status "config.yaml already exists"
    fi
    
    # Create directories
    mkdir -p results
    mkdir -p logs
    mkdir -p wordlists
    
    print_status "Created necessary directories"
}

# Download wordlists
download_wordlists() {
    print_status "Downloading common wordlists..."
    
    cd wordlists
    
    # Download SecLists if not present
    if [[ ! -d "SecLists" ]]; then
        print_status "Downloading SecLists..."
        git clone https://github.com/danielmiessler/SecLists.git
    else
        print_status "SecLists already exists"
    fi
    
    # Download common wordlists
    if [[ ! -f "common.txt" ]]; then
        print_status "Downloading common wordlist..."
        curl -s -o common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
    fi
    
    cd ..
}

# Set permissions
set_permissions() {
    print_status "Setting file permissions..."
    
    # Make main script executable
    chmod +x main.py
    
    # Make install script executable
    chmod +x install.sh
    
    print_status "Permissions set"
}

# Test installation
test_installation() {
    print_status "Testing installation..."
    
    # Test Python imports
    python3 -c "
import sys
sys.path.append('app')
try:
    from app.core.orchestrator import SecurityOrchestrator
    from app.logger import logger
    print('✓ Core modules imported successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        print_status "Installation test passed"
    else
        print_error "Installation test failed"
        exit 1
    fi
}

# Main installation function
main() {
    print_banner
    
    print_status "Starting OpenManus-BugHunting installation..."
    
    # Check prerequisites
    check_root
    check_os
    check_python
    
    # Install dependencies
    install_system_deps
    
    # Setup Python environment
    create_venv
    install_python_deps
    
    # Install additional tools
    install_additional_tools
    
    # Setup configuration
    setup_config
    
    # Download wordlists
    download_wordlists
    
    # Set permissions
    set_permissions
    
    # Test installation
    test_installation
    
    print_status "Installation completed successfully!"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Activate the virtual environment: source venv/bin/activate"
    echo "2. Edit config.yaml to customize settings"
    echo "3. Run a test scan: python main.py --target example.com --mode reconnaissance"
    echo ""
    echo -e "${YELLOW}Remember: Only test targets you own or have explicit permission to test!${NC}"
    echo ""
    echo -e "${BLUE}Happy bug hunting! 🐛🔍${NC}"
}

# Run main function
main "$@"