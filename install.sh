#!/bin/bash

# OpenManus-BugHunting Installation Script
# Comprehensive cybersecurity tools installer for bug hunting and penetration testing

# Detect if the script is being run in MacOS with Homebrew Bash
if [[ "$OSTYPE" == "darwin"* && "$BASH" != "/opt/homebrew/bin/bash" ]]; then
    exec /opt/homebrew/bin/bash "$0" "$@"
fi

# Colors for output
red='\033[0;31m'
bred='\033[1;31m'
green='\033[0;32m'
bgreen='\033[1;32m'
yellow='\033[0;33m'
byellow='\033[1;33m'
blue='\033[0;34m'
bblue='\033[1;34m'
purple='\033[0;35m'
bpurple='\033[1;35m'
cyan='\033[0;36m'
bcyan='\033[1;36m'
white='\033[0;37m'
bwhite='\033[1;37m'
reset='\033[0m'

# Initialize variables
dir="${HOME}/Tools"
double_check=false

# ARM Detection
ARCH=$(uname -m)

# macOS Detection
IS_MAC=$([[ $OSTYPE == "darwin"* ]] && echo "True" || echo "False")

# Check Bash version
BASH_VERSION_NUM=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ $BASH_VERSION_NUM -lt 4 ]]; then
	echo -e "${bred}Your Bash version is lower than 4, please update.${reset}"
	if [[ $IS_MAC == "True" ]]; then
		echo -e "${yellow}For macOS, run 'brew install bash' and rerun the installer in a new terminal.${reset}"
	fi
	exit 1
fi

# Declare Go tools and their installation commands
declare -A gotools=(
	["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
	["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
	["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
	["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
	["katana"]="go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
	["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
	["tlsx"]="go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
	["mapcidr"]="go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
	["cdncheck"]="go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
	["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
	["notify"]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
	["urlfinder"]="go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
	["ffuf"]="go install -v github.com/ffuf/ffuf/v2@latest"
	["gf"]="go install -v github.com/tomnomnom/gf@latest"
	["anew"]="go install -v github.com/tomnomnom/anew@latest"
	["unfurl"]="go install -v github.com/tomnomnom/unfurl@v0.3.0"
	["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
	["hakip2host"]="go install -v github.com/hakluke/hakip2host@latest"
	["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
	["crlfuzz"]="go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
	["Gxss"]="go install -v github.com/KathanP19/Gxss@latest"
	["subjs"]="go install -v github.com/lc/subjs@latest"
	["puredns"]="go install -v github.com/d3mondev/puredns/v2@latest"
	["gotator"]="go install -v github.com/Josue87/gotator@latest"
	["roboxtractor"]="go install -v github.com/Josue87/roboxtractor@latest"
	["analyticsrelationships"]="go install -v github.com/Josue87/analyticsrelationships@latest"
	["dnstake"]="go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest"
	["smap"]="go install -v github.com/s0md3v/smap/cmd/smap@latest"
	["dsieve"]="go install -v github.com/trickest/dsieve@master"
	["inscope"]="go install -v github.com/tomnomnom/hacks/inscope@latest"
	["enumerepo"]="go install -v github.com/trickest/enumerepo@latest"
	["Web-Cache-Vulnerability-Scanner"]="go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest"
	["mantra"]="go install -v github.com/Brosck/mantra@latest"
	["crt"]="go install -v github.com/cemulus/crt@latest"
	["s3scanner"]="go install -v github.com/sa7mon/s3scanner@latest"
	["nmapurls"]="go install -v github.com/sdcampbell/nmapurls@latest"
	["shortscan"]="go install -v github.com/bitquark/shortscan/cmd/shortscan@latest"
	["sns"]="go install github.com/sw33tLie/sns@latest"
	["ppmap"]="go install -v github.com/kleiton0x00/ppmap@latest"
	["sourcemapper"]="go install -v github.com/denandz/sourcemapper@latest"
	["jsluice"]="go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"
	["cent"]="go install -v github.com/xm1k3/cent@latest"
	["csprecon"]="go install github.com/edoardottt/csprecon/cmd/csprecon@latest"
	["VhostFinder"]="go install -v github.com/wdahlenburg/VhostFinder@latest"
	["misconfig-mapper"]="go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest"
	["github-subdomains"]="go install -v github.com/gwen001/github-subdomains@latest"
	["gitlab-subdomains"]="go install -v github.com/gwen001/gitlab-subdomains@latest"
	["github-endpoints"]="go install -v github.com/gwen001/github-endpoints@latest"
	["gitdorks_go"]="go install -v github.com/damit5/gitdorks_go@latest"
	["brutespray"]="go install -v github.com/x90skysn3k/brutespray@latest"
)

# Declare pipx tools and their paths
declare -A pipxtools=(
	["dnsvalidator"]="vortexau/dnsvalidator"
	["interlace"]="codingo/Interlace"
	["wafw00f"]="EnableSecurity/wafw00f"
	["commix"]="commixproject/commix"
	["urless"]="xnl-h4ck3r/urless"
	["ghauri"]="r0oth3x49/ghauri"
	["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
	["xnldorker"]="xnl-h4ck3r/xnldorker"
	["porch-pirate"]="MandConsultingGroup/porch-pirate"
	["p1radup"]="iambouali/p1radup"
	["subwiz"]="hadriansecurity/subwiz"
)

# Declare repositories and their paths
declare -A repos=(
	["dorks_hunter"]="six2dez/dorks_hunter"
	["gf"]="tomnomnom/gf"
	["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
	["sus_params"]="g0ldencybersec/sus_params"
	["Corsy"]="s0md3v/Corsy"
	["CMSeeK"]="Tuhinshubhra/CMSeeK"
	["fav-up"]="pielco11/fav-up"
	["massdns"]="blechschmidt/massdns"
	["Oralyzer"]="r0075h3ll/Oralyzer"
	["testssl.sh"]="drwetter/testssl.sh"
	["JSA"]="w9w/JSA"
	["CloudHunter"]="belane/CloudHunter"
	["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
	["pydictor"]="LandGrey/pydictor"
	["smuggler"]="defparam/smuggler"
	["regulator"]="cramppet/regulator"
	["gitleaks"]="gitleaks/gitleaks"
	["trufflehog"]="trufflesecurity/trufflehog"
	["nomore403"]="devploit/nomore403"
	["SwaggerSpy"]="UndeadSec/SwaggerSpy"
	["LeakSearch"]="JoelGMSec/LeakSearch"
	["ffufPostprocessing"]="Damian89/ffufPostprocessing"
	["Spoofy"]="MattKeeley/Spoofy"
	["msftrecon"]="Arcanum-Sec/msftrecon"
	["Scopify"]="Arcanum-Sec/Scopify"
	["metagoofil"]="opsdisk/metagoofil"
	["EmailHarvester"]="maldevel/EmailHarvester"
	["sqlmap"]="sqlmapproject/sqlmap"
	["wpscan"]="wpscanteam/wpscan"
	["nikto"]="sullo/nikto"
	["dirb"]="v0re/dirb"
	["dirbuster"]="KajanM/DirBuster"
	["gobuster"]="OJ/gobuster"
	["wfuzz"]="xmendez/wfuzz"
	["SecLists"]="danielmiessler/SecLists"
	["PayloadsAllTheThings"]="swisskyrepo/PayloadsAllTheThings"
	["FuzzDB"]="fuzzdb-project/fuzzdb"
)

# Function to display the banner
function banner() {
	tput clear
	cat <<EOF

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

                    OpenManus-BugHunting Installer
                         by OpenHands AI

EOF
}

# Function to install Go tools
function install_tools() {
	echo -e "${bblue}Running: Installing Golang tools (${#gotools[@]})${reset}\n"

	local go_step=0
	local failed_tools=()
	for gotool in "${!gotools[@]}"; do
		((go_step++))
		if command -v "$gotool" &>/dev/null; then
			echo -e "[${yellow}SKIPPING${reset}] $gotool already installed at $(command -v "$gotool")"
			continue
		fi

		# Install the Go tool
		eval "${gotools[$gotool]}" &>/dev/null
		exit_status=$?
		if [[ $exit_status -eq 0 ]]; then
			echo -e "${yellow}$gotool installed (${go_step}/${#gotools[@]})${reset}"
		else
			echo -e "${red}Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}"
			failed_tools+=("$gotool")
			double_check=true
		fi
	done

	echo -e "\n${bblue}Running: Installing pipx tools (${#pipxtools[@]})${reset}\n"

	local pipx_step=0
	local failed_pipx_tools=()

	for pipxtool in "${!pipxtools[@]}"; do
		((pipx_step++))
		if command -v "$pipxtool" &>/dev/null; then
			echo -e "[${yellow}SKIPPING${reset}] $pipxtool already installed at $(command -v "$pipxtool")"
			continue
		fi

		# Install the pipx tool
		eval pipx install "git+https://github.com/${pipxtools[$pipxtool]}" &>/dev/null
		exit_status=$?
		if [[ $exit_status -ne 0 ]]; then
			echo -e "${red}Failed to install $pipxtool, try manually (${pipx_step}/${#pipxtools[@]})${reset}"
			failed_pipx_tools+=("$pipxtool")
			double_check=true
			continue
		fi

		echo -e "${yellow}$pipxtool installed (${pipx_step}/${#pipxtools[@]})${reset}"
	done

	echo -e "\n${bblue}Running: Installing repositories (${#repos[@]})${reset}\n"

	local repos_step=0
	local failed_repos=()

	for repo in "${!repos[@]}"; do
		((repos_step++))
		if [[ -d "${dir}/${repo}" ]]; then
			echo -e "[${yellow}SKIPPING${reset}] Repository $repo already cloned in ${dir}/${repo}"
			continue
		fi
		
		# Clone the repository
		git clone --filter="blob:none" "https://github.com/${repos[$repo]}" "${dir}/${repo}" &>/dev/null
		exit_status=$?
		if [[ $exit_status -ne 0 ]]; then
			echo -e "${red}Unable to clone repository $repo.${reset}"
			failed_repos+=("$repo")
			double_check=true
			continue
		fi

		# Navigate to the repository directory
		cd "${dir}/${repo}" || {
			echo -e "${red}Failed to navigate to directory '${dir}/${repo}'${reset}"
			failed_repos+=("$repo")
			double_check=true
			continue
		}

		# Install requirements inside a virtual environment
		if [[ -s "requirements.txt" ]]; then
			if [[ ! -f "venv/bin/activate" ]]; then
				python3 -m venv venv &>/dev/null
			fi
			source venv/bin/activate
			eval "pip3 install --upgrade -r requirements.txt" &>/dev/null
			deactivate
		fi

		# Special handling for certain repositories
		case "$repo" in
		"massdns")
			make &>/dev/null && strip -s bin/massdns && $SUDO cp bin/massdns /usr/local/bin/ &>/dev/null
			;;
		"gitleaks")
			make build &>/dev/null && $SUDO cp ./gitleaks /usr/local/bin/ &>/dev/null
			;;
		"nomore403")
			go get &>/dev/null
			go build &>/dev/null
			chmod +x ./nomore403
			;;
		"ffufPostprocessing")
			git reset --hard origin/master &>/dev/null
			git pull &>/dev/null
			go build -o ffufPostprocessing main.go &>/dev/null
			chmod +x ./ffufPostprocessing
			;;
		"misconfig-mapper")
			git reset --hard origin/main &>/dev/null
			git pull &>/dev/null
			go mod tidy &>/dev/null
			go build -o misconfig-mapper &>/dev/null
			chmod +x ./misconfig-mapper &>/dev/null
			cp misconfig-mapper $HOME/go/bin/ &>/dev/null
			;;
		"trufflehog")
			go install &>/dev/null
			;;
		"sqlmap")
			chmod +x sqlmap.py
			;;
		"nikto")
			cd program
			chmod +x nikto.pl
			cd ..
			;;
		esac

		# Copy gf patterns if applicable
		if [[ $repo == "gf" ]]; then
			cp -r examples ${HOME}/.gf &>/dev/null
		elif [[ $repo == "Gf-Patterns" ]]; then
			cp ./*.json ${HOME}/.gf &>/dev/null
		elif [[ $repo == "sus_params" ]]; then
			for f in ./gf-patterns/*.json; do
				base=$(basename "$f")
				dest="${HOME}/.gf/$base"
				cat "$f" | anew -q "$dest" >/dev/null
			done
		fi

		# Return to the main directory
		cd "$dir" || {
			echo -e "${red}Failed to navigate back to directory '$dir'.${reset}"
			exit 1
		}

		echo -e "${yellow}$repo installed (${repos_step}/${#repos[@]})${reset}"
	done

	# Notify and ensure subfinder is installed twice (as per original script)
	notify &>/dev/null
	subfinder &>/dev/null
	subfinder &>/dev/null
	mkdir -p ${HOME}/.config/nuclei/
	nuclei -update-templates &>/dev/null

	# Handle failed installations
	if [[ ${#failed_tools[@]} -ne 0 ]]; then
		echo -e "\n${red}Failed to install the following Go tools: ${failed_tools[*]}${reset}"
	fi

	if [[ ${#failed_pipx_tools[@]} -ne 0 ]]; then
		echo -e "\n${red}Failed to install the following pipx tools: ${failed_pipx_tools[*]}${reset}"
	fi

	if [[ ${#failed_repos[@]} -ne 0 ]]; then
		echo -e "\n${red}Failed to clone or update the following repositories:\n${failed_repos[*]}${reset}"
	fi
}

# Function to install Golang
function install_golang_version() {
	local version="go1.21.5"
	local latest_version
	latest_version=$(curl -s https://go.dev/VERSION?m=text | head -1 || echo "go1.21.5")
	if [[ $latest_version == g* ]]; then
		version="$latest_version"
	fi

	echo -e "${bblue}Running: Installing/Updating Golang($version) ${reset}\n"

	if command -v go &>/dev/null && [[ $version == "$(go version | awk '{print $3}')" ]]; then
		echo -e "${bgreen}Golang is already installed and up to date.${reset}\n"
	else
		$SUDO rm -rf /usr/local/go &>/dev/null || true

		case "$ARCH" in
		arm64 | aarch64)
			if [[ $IS_MAC == "True" ]]; then
				wget "https://dl.google.com/go/${version}.darwin-arm64.tar.gz" -O "/tmp/${version}.darwin-arm64.tar.gz" &>/dev/null
				$SUDO tar -C /usr/local -xzf "/tmp/${version}.darwin-arm64.tar.gz" &>/dev/null
			else
				wget "https://dl.google.com/go/${version}.linux-arm64.tar.gz" -O "/tmp/${version}.linux-arm64.tar.gz" &>/dev/null
				$SUDO tar -C /usr/local -xzf "/tmp/${version}.linux-arm64.tar.gz" &>/dev/null
			fi
			;;
		armv6l | armv7l)
			wget "https://dl.google.com/go/${version}.linux-armv6l.tar.gz" -O "/tmp/${version}.linux-armv6l.tar.gz" &>/dev/null
			$SUDO tar -C /usr/local -xzf "/tmp/${version}.linux-armv6l.tar.gz" &>/dev/null
			;;
		amd64 | x86_64)
			if [[ $IS_MAC == "True" ]]; then
				wget "https://dl.google.com/go/${version}.darwin-amd64.tar.gz" -O "/tmp/${version}.darwin-amd64.tar.gz" &>/dev/null
				$SUDO tar -C /usr/local -xzf "/tmp/${version}.darwin-amd64.tar.gz" &>/dev/null
			else
				wget "https://dl.google.com/go/${version}.linux-amd64.tar.gz" -O "/tmp/${version}.linux-amd64.tar.gz" &>/dev/null
				$SUDO tar -C /usr/local -xzf "/tmp/${version}.linux-amd64.tar.gz" &>/dev/null
			fi
			;;
		*)
			echo -e "${bred}[!] Unsupported architecture. Please install go manually.${reset}"
			exit 1
			;;
		esac

		$SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/ 2>/dev/null
		export GOROOT=/usr/local/go
		export GOPATH="${HOME}/go"
		export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

		# Append Go environment variables to shell profile
		profile_shell=".bashrc"
		[[ $SHELL == *"zsh"* ]] && profile_shell=".zshrc"
		
		cat <<EOF >>${HOME}/"${profile_shell}"

# Golang environment variables
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF
	fi

	# Validate Go environment variables
	if [[ -z ${GOPATH-} ]]; then
		export GOROOT=/usr/local/go
		export GOPATH="${HOME}/go"
		export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"
	fi
}

# Function to install system packages based on OS
function install_system_packages() {
	if [[ -f /etc/debian_version ]]; then
		install_apt
	elif [[ -f /etc/redhat-release ]]; then
		install_yum
	elif [[ -f /etc/arch-release ]]; then
		install_pacman
	elif [[ $IS_MAC == "True" ]]; then
		install_brew
	elif [[ -f /etc/os-release ]]; then
		install_yum # Assuming RedHat-based
	else
		echo -e "${bred}[!] Unsupported OS. Please install dependencies manually.${reset}"
		exit 1
	fi
}

# Function to install required packages for Debian-based systems
function install_apt() {
	echo -e "${bblue}Installing system packages for Debian/Ubuntu...${reset}\n"
	$SUDO apt-get update -y &>/dev/null
	$SUDO apt-get install -y python3 python3-pip python3-venv pipx python3-virtualenv build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl &>/dev/null
	
	# Install additional security tools
	$SUDO apt-get install -y nikto dirb gobuster wfuzz sqlmap hydra john hashcat aircrack-ng wireshark-common tcpdump netcat-openbsd socat &>/dev/null
	
	# Install chromium browser dependencies
	$SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2 &>/dev/null ||
		$SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2t64 &>/dev/null
	
	# Install Rust
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
	pipx ensurepath -f &>/dev/null
}

# Function to install required packages for macOS
function install_brew() {
	echo -e "${bblue}Installing system packages for macOS...${reset}\n"
	if command -v brew &>/dev/null; then
		echo -e "${bgreen}brew is already installed.${reset}\n"
	else
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	fi
	brew update &>/dev/null
	brew install --formula bash coreutils gnu-getopt python pipx massdns jq gcc cmake ruby git curl wget zip pv bind whois nmap jq lynx medusa &>/dev/null
	brew install rustup &>/dev/null
	rustup-init -y &>/dev/null
	cargo install ripgen &>/dev/null
}

# Function to install required packages for RedHat-based systems
function install_yum() {
	echo -e "${bblue}Installing system packages for RedHat/CentOS...${reset}\n"
	$SUDO yum groupinstall "Development Tools" -y &>/dev/null
	$SUDO yum install -y python3 python3-pip gcc cmake ruby git curl libpcap whois wget pipx zip pv bind-utils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx medusa xorg-x11-server-xvfb &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
}

# Function to install required packages for Arch-based systems
function install_pacman() {
	echo -e "${bblue}Installing system packages for Arch Linux...${reset}\n"
	$SUDO pacman -Sy --noconfirm python python-pip base-devel gcc cmake ruby git curl libpcap python-pipx whois wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx medusa xorg-server-xvfb &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
}

# Function to perform initial setup
function initial_setup() {
	banner

	echo -e "${bblue}Running: Installing system packages${reset}\n"
	install_system_packages

	install_golang_version

	echo -e "${bblue}Running: Installing Python requirements${reset}\n"
	mkdir -p ${HOME}/.gf
	mkdir -p "$dir"
	mkdir -p ${HOME}/.config/notify/
	mkdir -p ${HOME}/.config/nuclei/
	mkdir -p ${HOME}/.config/subfinder/
	touch "${dir}/.github_tokens"
	touch "${dir}/.gitlab_tokens"

	eval pipx ensurepath
	source "${HOME}/.bashrc" 2>/dev/null || source "${HOME}/.zshrc" 2>/dev/null || true

	install_tools

	echo -e "\n${bblue}Running: Downloading required files${reset}\n"

	# Download required files with error handling
	declare -A downloads=(
	    ["notify_provider_config"]="https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw ${HOME}/.config/notify/provider-config.yaml"
	    ["subfinder_config"]="https://gist.githubusercontent.com/six2dez/58f7c6218fc4e80d532c7bb1083239a5/raw ${HOME}/.config/subfinder/provider-config.yaml"
	    ["subdomains_huge"]="https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt ${dir}/subdomains_huge.txt"
	    ["trusted_resolvers"]="https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw ${dir}/trusted_resolvers.txt"
	    ["resolvers"]="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt ${dir}/resolvers.txt"
	    ["subs_wordlist"]="https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw ${dir}/subs_wordlist.txt"
	    ["permutations_list"]="https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw ${dir}/permutations_list.txt"
	    ["fuzz_wordlist"]="https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt ${dir}/fuzz_wordlist.txt"
	    ["lfi_wordlist"]="https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw ${dir}/lfi_wordlist.txt"
	    ["ssti_wordlist"]="https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw ${dir}/ssti_wordlist.txt"
	    ["headers_inject"]="https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw ${dir}/headers_inject.txt"
		["jsluice_patterns"]="https://gist.githubusercontent.com/six2dez/2aafa8dc2b682bb0081684e71900e747/raw ${dir}/jsluice_patterns.json"
	)
	
	for key in "${!downloads[@]}"; do
	    url="${downloads[$key]% *}"
	    destination="${downloads[$key]#* }"
	
	    # Skip download if file already exists
	    if [[ -f "$destination" ]]; then
	        echo -e "[${yellow}SKIPPING${reset}] $key as it already exists at $destination.${reset}"
	        continue
	    fi
	
	    wget -q -O "$destination" "$url" || {
	        echo -e "${red}[!] Failed to download $key from $url.${reset}"
	        continue
	    }
	    echo -e "${yellow}Downloaded $key${reset}"
	done

	echo -e "${bblue}Running: Performing last configurations${reset}\n"

	# Strip all Go binaries and copy to /usr/local/bin
	strip -s "${GOPATH}/bin/"* &>/dev/null || true
	$SUDO cp "${GOPATH}/bin/"* /usr/local/bin/ &>/dev/null || true

	# Final reminders
	echo -e "${yellow}Remember to set your API keys:\n- subfinder (${HOME}/.config/subfinder/provider-config.yaml)\n- GitHub (${HOME}/Tools/.github_tokens)\n- GitLab (${HOME}/Tools/.gitlab_tokens)\n- notify (${HOME}/.config/notify/provider-config.yaml)\n- DeepSeek API (config/config.toml)\n${reset}"
	echo -e "${bgreen}Finished!${reset}\n"
	echo -e "${bgreen}#######################################################################${reset}"
	echo -e "${bgreen}OpenManus-BugHunting installation completed successfully!${reset}"
	echo -e "${bgreen}#######################################################################${reset}"
	echo -e "${yellow}To get started:${reset}"
	echo -e "${yellow}1. Configure your API keys in the respective config files${reset}"
	echo -e "${yellow}2. Run: python3 main.py --target example.com --mode comprehensive${reset}"
	echo -e "${yellow}3. Check the documentation for advanced usage${reset}"
}

# Function to display additional help
function show_additional_help() {
	echo "Usage: $0 [OPTION]"
	echo "OpenManus-BugHunting installer script."
	echo ""
	echo "  -h, --help       Display this help and exit."
	echo "  --tools          Install only the tools (useful for upgrading)."
	echo ""
	echo "  ****             Without any arguments, the script will install"
	echo "                   all dependencies and requirements."
	exit 0
}

# Function to handle installation arguments
function handle_install_arguments() {
	echo -e "\n${bgreen}OpenManus-BugHunting installer script${reset}\n"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			show_additional_help
			;;
		--tools)
			install_tools
			exit 0
			;;
		*)
			echo -e "${bred}Error: Invalid argument '$1'${reset}"
			echo "Use -h or --help for usage information."
			exit 1
			;;
		esac
	done

	echo -e "${yellow}This may take some time. Grab a coffee!${reset}\n"

	# Determine if the script is run as root
	if [[ "$(id -u)" -eq 0 ]]; then
		SUDO=""
	else
		if ! sudo -n true 2>/dev/null; then
			echo -e "${bred}It is strongly recommended to add your user to sudoers.${reset}"
			echo -e "${bred}This will avoid prompts for sudo password during installation and scans.${reset}"
			echo -e "${bred}Run the following command to add your user to sudoers:${reset}"
			echo -e "${bred}echo \"${USER}  ALL=(ALL:ALL) NOPASSWD: ALL\" | sudo tee /etc/sudoers.d/openmanus${reset}\n"
		fi
		SUDO="sudo"
	fi
}

# Invoke main functions
handle_install_arguments "$@"
initial_setup