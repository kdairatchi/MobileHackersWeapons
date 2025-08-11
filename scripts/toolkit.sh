#!/bin/bash

# Mobile Bug Bounty Toolkit - Complete Installation & Menu Script

# Author: Security Researcher

# Version: 2.0

# Description: Comprehensive mobile security testing toolkit installer and menu

# Colors for output

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
BLUE=’\033[0;34m’
PURPLE=’\033[0;35m’
CYAN=’\033[0;36m’
WHITE=’\033[1;37m’
NC=’\033[0m’ # No Color

# Banner

print_banner() {
clear
echo -e “${CYAN}”
echo “╔═══════════════════════════════════════════════════════════════════════╗”
echo “║                    MOBILE BUG BOUNTY TOOLKIT                          ║”
echo “║                   Complete Security Testing Suite                     ║”
echo “║                        Version 2.0                                    ║”
echo “╚═══════════════════════════════════════════════════════════════════════╝”
echo -e “${NC}”
}

# Logging function

log() {
echo -e “${GREEN}[$(date ‘+%Y-%m-%d %H:%M:%S’)] $1${NC}”
}

error() {
echo -e “${RED}[ERROR] $1${NC}”
}

warn() {
echo -e “${YELLOW}[WARNING] $1${NC}”
}

# Check if running as root

check_root() {
if [[ $EUID -eq 0 ]]; then
warn “Running as root. Some tools may not work properly.”
read -p “Continue anyway? (y/N): “ -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
exit 1
fi
fi
}

# Detect OS

detect_os() {
if [[ “$OSTYPE” == “linux-gnu”* ]]; then
if command -v apt-get &> /dev/null; then
OS=“ubuntu”
PKG_MANAGER=“apt-get”
elif command -v yum &> /dev/null; then
OS=“centos”
PKG_MANAGER=“yum”
elif command -v pacman &> /dev/null; then
OS=“arch”
PKG_MANAGER=“pacman”
fi
elif [[ “$OSTYPE” == “darwin”* ]]; then
OS=“macos”
PKG_MANAGER=“brew”
else
error “Unsupported operating system”
exit 1
fi
log “Detected OS: $OS”
}

# Install dependencies

install_dependencies() {
log “Installing system dependencies…”

```
case $OS in
    ubuntu)
        sudo apt-get update
        sudo apt-get install -y curl wget git python3 python3-pip nodejs npm openjdk-11-jdk \
            android-tools-adb android-tools-fastboot unzip zip p7zip-full \
            build-essential libssl-dev libffi-dev python3-dev \
            ruby ruby-dev sqlite3 libsqlite3-dev
        ;;
    centos)
        sudo yum update -y
        sudo yum install -y curl wget git python3 python3-pip nodejs npm java-11-openjdk \
            android-tools unzip zip p7zip \
            gcc openssl-devel libffi-devel python3-devel \
            ruby ruby-devel sqlite sqlite-devel
        ;;
    arch)
        sudo pacman -Sy --noconfirm curl wget git python python-pip nodejs npm jdk11-openjdk \
            android-tools unzip zip p7zip \
            base-devel openssl libffi \
            ruby sqlite
        ;;
    macos)
        if ! command -v brew &> /dev/null; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install curl wget git python3 node openjdk@11 \
            android-platform-tools p7zip \
            ruby sqlite
        ;;
esac
```

}

# Create directory structure

create_directories() {
log “Creating directory structure…”

```
TOOLKIT_DIR="$HOME/mobile-bugbounty-toolkit"
mkdir -p "$TOOLKIT_DIR"/{tools,apks,reports,wordlists,scripts,logs}

# Set paths
TOOLS_DIR="$TOOLKIT_DIR/tools"
APKS_DIR="$TOOLKIT_DIR/apks"
REPORTS_DIR="$TOOLKIT_DIR/reports"
WORDLISTS_DIR="$TOOLKIT_DIR/wordlists"
SCRIPTS_DIR="$TOOLKIT_DIR/scripts"
LOGS_DIR="$TOOLKIT_DIR/logs"

echo "export MOBILE_TOOLKIT_PATH=$TOOLKIT_DIR" >> ~/.bashrc
export MOBILE_TOOLKIT_PATH="$TOOLKIT_DIR"
```

}

# Install Android tools

install_android_tools() {
log “Installing Android security tools…”

```
cd "$TOOLS_DIR"

# APKTool
if [ ! -f "apktool.jar" ]; then
    log "Installing APKTool..."
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar
    chmod +x apktool apktool.jar
    sudo mv apktool /usr/local/bin/
    sudo mv apktool.jar /usr/local/bin/
fi

# Dex2jar
if [ ! -d "dex2jar" ]; then
    log "Installing dex2jar..."
    wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-2.4.zip
    unzip dex-tools-2.4.zip && mv dex-tools-2.4 dex2jar
    chmod +x dex2jar/*.sh
    rm dex-tools-2.4.zip
fi

# JD-GUI
if [ ! -f "jd-gui.jar" ]; then
    log "Installing JD-GUI..."
    wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O jd-gui.jar
fi

# JADX
if [ ! -d "jadx" ]; then
    log "Installing JADX..."
    wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
    unzip jadx-1.4.7.zip -d jadx
    chmod +x jadx/bin/*
    rm jadx-1.4.7.zip
fi

# MobSF
if [ ! -d "Mobile-Security-Framework-MobSF" ]; then
    log "Installing MobSF..."
    git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
    cd Mobile-Security-Framework-MobSF
    pip3 install -r requirements.txt
    cd ..
fi

# Frida
log "Installing Frida..."
pip3 install frida-tools

# Objection
log "Installing Objection..."
pip3 install objection

# ADB Enhanced
log "Setting up ADB..."
if command -v adb &> /dev/null; then
    adb version
fi
```

}

# Install iOS tools

install_ios_tools() {
log “Installing iOS security tools…”

```
cd "$TOOLS_DIR"

# iOS tools (mainly for macOS)
if [[ "$OS" == "macos" ]]; then
    # libimobiledevice
    brew install libimobiledevice
    brew install ideviceinstaller
    brew install ios-deploy
    
    # class-dump
    if [ ! -f "class-dump" ]; then
        log "Installing class-dump..."
        curl -L https://github.com/nygard/class-dump/releases/download/3.5/class-dump-3.5.tar.gz | tar xz
        cd class-dump-3.5
        make && sudo cp class-dump /usr/local/bin/
        cd ..
        rm -rf class-dump-3.5
    fi
    
    # Hopper (trial version)
    warn "Consider installing Hopper Disassembler from App Store for iOS binary analysis"
    
    # iFunBox alternative - 3uTools
    warn "Consider installing 3uTools for iOS device management"
else
    warn "iOS tools are primarily available on macOS. Some cross-platform tools installed."
fi

# Cross-platform iOS tools
pip3 install pymobiledevice3
```

}

# Install static analysis tools

install_static_analysis_tools() {
log “Installing static analysis tools…”

```
cd "$TOOLS_DIR"

# QARK
if [ ! -d "qark" ]; then
    log "Installing QARK..."
    git clone https://github.com/linkedin/qark.git
    cd qark
    pip3 install -r requirements.txt
    pip3 install .
    cd ..
fi

# Semgrep
log "Installing Semgrep..."
pip3 install semgrep

# Bandit (for Python code analysis)
log "Installing Bandit..."
pip3 install bandit

# NodeJsScan
if [ ! -d "NodeJsScan" ]; then
    log "Installing NodeJsScan..."
    git clone https://github.com/ajinabraham/NodeJsScan.git
    cd NodeJsScan
    pip3 install -r requirements.txt
    cd ..
fi
```

}

# Install dynamic analysis tools

install_dynamic_analysis_tools() {
log “Installing dynamic analysis tools…”

```
# Burp Suite Community (requires manual download)
warn "Please download Burp Suite Community from: https://portswigger.net/burp/communitydownload"

# OWASP ZAP
if [[ "$OS" == "ubuntu" ]]; then
    sudo snap install zaproxy --classic
elif [[ "$OS" == "macos" ]]; then
    brew install --cask owasp-zap
fi

# Charles Proxy (requires license)
warn "Consider installing Charles Proxy for SSL/TLS interception"

# Wireshark
case $OS in
    ubuntu)
        sudo apt-get install -y wireshark
        ;;
    macos)
        brew install --cask wireshark
        ;;
esac
```

}

# Install network analysis tools

install_network_tools() {
log “Installing network analysis tools…”

```
# Nmap
case $OS in
    ubuntu)
        sudo apt-get install -y nmap
        ;;
    macos)
        brew install nmap
        ;;
esac

# Masscan
if [ ! -d "masscan" ]; then
    log "Installing Masscan..."
    git clone https://github.com/robertdavidgraham/masscan
    cd masscan
    make && sudo make install
    cd ..
fi

# SSLyze
pip3 install sslyze

# Subfinder
if [ ! -f "/usr/local/bin/subfinder" ]; then
    log "Installing Subfinder..."
    wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
    unzip subfinder_2.6.3_linux_amd64.zip
    sudo mv subfinder /usr/local/bin/
    rm subfinder_2.6.3_linux_amd64.zip
fi
```

}

# Download wordlists

download_wordlists() {
log “Downloading wordlists…”

```
cd "$WORDLISTS_DIR"

# SecLists
if [ ! -d "SecLists" ]; then
    git clone https://github.com/danielmiessler/SecLists.git
fi

# Custom mobile wordlists
cat > mobile_paths.txt << 'EOF'
```

/admin
/administrator
/api
/api/v1
/api/v2
/backup
/config
/data
/db
/debug
/dev
/internal
/logs
/mobile
/private
/secret
/temp
/test
/upload
/uploads
/.git
/.svn
/.env
/config.xml
/AndroidManifest.xml
/Info.plist
EOF

```
cat > mobile_files.txt << 'EOF'
```

config.xml
AndroidManifest.xml
Info.plist
database.db
app.db
users.db
cache.db
preferences.xml
shared_prefs.xml
keychain.plist
.env
.config
backup.sql
dump.sql
debug.log
error.log
crash.log
EOF
}

# Install additional utilities

install_utilities() {
log “Installing additional utilities…”

```
# HTTPie
pip3 install httpie

# jq
case $OS in
    ubuntu)
        sudo apt-get install -y jq
        ;;
    macos)
        brew install jq
        ;;
esac

# xmlstarlet
case $OS in
    ubuntu)
        sudo apt-get install -y xmlstarlet
        ;;
    macos)
        brew install xmlstarlet
        ;;
esac
```

}

# Create helper scripts

create_helper_scripts() {
log “Creating helper scripts…”

```
cd "$SCRIPTS_DIR"

# APK Analysis Script
cat > apk_analyzer.sh << 'EOF'
```

#!/bin/bash
if [ “$#” -ne 1 ]; then
echo “Usage: $0 <path_to_apk>”
exit 1
fi

APK_PATH=”$1”
APK_NAME=$(basename “$APK_PATH” .apk)
ANALYSIS_DIR=”$MOBILE_TOOLKIT_PATH/reports/${APK_NAME}_analysis”

mkdir -p “$ANALYSIS_DIR”

echo “Starting APK analysis for: $APK_NAME”
echo “Results will be saved to: $ANALYSIS_DIR”

# APKTool

echo “Running APKTool…”
apktool d “$APK_PATH” -o “$ANALYSIS_DIR/apktool_output” -f

# dex2jar

echo “Running dex2jar…”
$MOBILE_TOOLKIT_PATH/tools/dex2jar/d2j-dex2jar.sh “$APK_PATH” -o “$ANALYSIS_DIR/${APK_NAME}.jar”

# JADX

echo “Running JADX…”
$MOBILE_TOOLKIT_PATH/tools/jadx/bin/jadx -d “$ANALYSIS_DIR/jadx_output” “$APK_PATH”

# Basic info extraction

echo “Extracting basic information…”
aapt dump badging “$APK_PATH” > “$ANALYSIS_DIR/app_info.txt” 2>/dev/null || echo “aapt not available”

echo “Analysis complete! Check results in: $ANALYSIS_DIR”
EOF
chmod +x apk_analyzer.sh

```
# Frida Script Generator
cat > generate_frida_script.py << 'EOF'
```

#!/usr/bin/env python3
import sys

def generate_basic_frida_script(package_name):
script = f’’’
Java.perform(function() {{
console.log(“Starting Frida script for {package_name}”);

```
// Hook common crypto functions
var Cipher = Java.use("javax.crypto.Cipher");
Cipher.doFinal.overload("[B").implementation = function(input) {{
    console.log("Cipher.doFinal called with input: " + Java.use("android.util.Base64").encodeToString(input, 0));
    var result = this.doFinal(input);
    console.log("Cipher.doFinal result: " + Java.use("android.util.Base64").encodeToString(result, 0));
    return result;
}};

// Hook SharedPreferences
var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
SharedPreferencesImpl.getString.implementation = function(key, defValue) {{
    var result = this.getString(key, defValue);
    console.log("SharedPreferences.getString: " + key + " = " + result);
    return result;
}};

// Hook SQLite operations
try {{
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, args) {{
        console.log("SQLite Query: " + sql);
        if (args) {{
            console.log("SQLite Args: " + args);
        }}
        return this.rawQuery(sql, args);
    }};
}} catch(e) {{
    console.log("SQLite hooks failed: " + e);
}}

console.log("Frida hooks installed successfully");
```

}});
‘’’
return script

if **name** == “**main**”:
if len(sys.argv) != 2:
print(“Usage: python3 generate_frida_script.py <package_name>”)
sys.exit(1)

```
package_name = sys.argv[1]
script = generate_basic_frida_script(package_name)

filename = f"frida_{package_name.replace('.', '_')}.js"
with open(filename, 'w') as f:
    f.write(script)

print(f"Frida script generated: {filename}")
```

EOF
chmod +x generate_frida_script.py
}

# Main installation function

install_all() {
print_banner
log “Starting Mobile Bug Bounty Toolkit installation…”

```
detect_os
create_directories
install_dependencies
install_android_tools
install_ios_tools
install_static_analysis_tools
install_dynamic_analysis_tools
install_network_tools
download_wordlists
install_utilities
create_helper_scripts

log "Installation completed successfully!"
log "Toolkit installed at: $TOOLKIT_DIR"
echo
echo "To use the toolkit, run: $0 --menu"
```

}

# Device connection functions

check_android_device() {
if command -v adb &> /dev/null; then
DEVICES=$(adb devices | grep -v “List of devices” | grep “device$” | wc -l)
if [ “$DEVICES” -gt 0 ]; then
echo -e “${GREEN}Android device(s) connected: $DEVICES${NC}”
adb devices
return 0
else
echo -e “${YELLOW}No Android devices connected${NC}”
return 1
fi
else
error “ADB not installed”
return 1
fi
}

check_ios_device() {
if command -v idevice_id &> /dev/null; then
DEVICES=$(idevice_id -l | wc -l)
if [ “$DEVICES” -gt 0 ]; then
echo -e “${GREEN}iOS device(s) connected: $DEVICES${NC}”
idevice_id -l
return 0
else
echo -e “${YELLOW}No iOS devices connected${NC}”
return 1
fi
else
error “libimobiledevice not installed (iOS tools)”
return 1
fi
}

# APK Analysis Menu

apk_analysis_menu() {
while true; do
clear
print_banner
echo -e “${CYAN}APK Analysis Menu${NC}”
echo “1. Analyze APK with all tools”
echo “2. APKTool - Decompile APK”
echo “3. dex2jar - Convert to JAR”
echo “4. JADX - Decompile to Java”
echo “5. Extract APK information”
echo “6. Generate Frida script”
echo “7. Static analysis with QARK”
echo “8. Back to main menu”
echo

```
    read -p "Select option [1-8]: " choice
    
    case $choice in
        1)
            read -p "Enter APK path: " apk_path
            if [ -f "$apk_path" ]; then
                "$SCRIPTS_DIR/apk_analyzer.sh" "$apk_path"
                read -p "Press Enter to continue..."
            else
                error "APK file not found"
                read -p "Press Enter to continue..."
            fi
            ;;
        2)
            read -p "Enter APK path: " apk_path
            read -p "Enter output directory: " output_dir
            apktool d "$apk_path" -o "$output_dir" -f
            read -p "Press Enter to continue..."
            ;;
        3)
            read -p "Enter APK path: " apk_path
            "$TOOLS_DIR/dex2jar/d2j-dex2jar.sh" "$apk_path"
            read -p "Press Enter to continue..."
            ;;
        4)
            read -p "Enter APK path: " apk_path
            read -p "Enter output directory: " output_dir
            "$TOOLS_DIR/jadx/bin/jadx" -d "$output_dir" "$apk_path"
            read -p "Press Enter to continue..."
            ;;
        5)
            read -p "Enter APK path: " apk_path
            aapt dump badging "$apk_path"
            read -p "Press Enter to continue..."
            ;;
        6)
            read -p "Enter package name: " package_name
            cd "$SCRIPTS_DIR"
            python3 generate_frida_script.py "$package_name"
            read -p "Press Enter to continue..."
            ;;
        7)
            read -p "Enter APK path: " apk_path
            qark --apk "$apk_path"
            read -p "Press Enter to continue..."
            ;;
        8)
            break
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Dynamic Analysis Menu

dynamic_analysis_menu() {
while true; do
clear
print_banner
echo -e “${CYAN}Dynamic Analysis Menu${NC}”
echo “1. Start Frida server”
echo “2. Connect with Objection”
echo “3. List running processes”
echo “4. Hook specific app”
echo “5. SSL Kill Switch”
echo “6. Root detection bypass”
echo “7. Back to main menu”
echo

```
    read -p "Select option [1-7]: " choice
    
    case $choice in
        1)
            echo "Starting Frida server on device..."
            echo "Make sure frida-server is running on your device"
            frida-ps -U
            read -p "Press Enter to continue..."
            ;;
        2)
            read -p "Enter package name: " package_name
            objection -g "$package_name" explore
            ;;
        3)
            frida-ps -U
            read -p "Press Enter to continue..."
            ;;
        4)
            read -p "Enter package name: " package_name
            read -p "Enter script path (or press Enter for basic hooks): " script_path
            if [ -z "$script_path" ]; then
                frida -U -l "$SCRIPTS_DIR/frida_${package_name//./_}.js" "$package_name"
            else
                frida -U -l "$script_path" "$package_name"
            fi
            ;;
        5)
            echo "SSL Kill Switch - Use with Objection:"
            echo "objection -g <package> explore"
            echo "Then run: android sslpinning disable"
            read -p "Press Enter to continue..."
            ;;
        6)
            echo "Root Detection Bypass - Use with Objection:"
            echo "objection -g <package> explore"
            echo "Then run: android root disable"
            read -p "Press Enter to continue..."
            ;;
        7)
            break
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Network Analysis Menu

network_analysis_menu() {
while true; do
clear
print_banner
echo -e “${CYAN}Network Analysis Menu${NC}”
echo “1. Scan target IP/domain”
echo “2. SSL/TLS analysis”
echo “3. Subdomain enumeration”
echo “4. Port scanning”
echo “5. HTTP headers analysis”
echo “6. API endpoint discovery”
echo “7. Back to main menu”
echo

```
    read -p "Select option [1-7]: " choice
    
    case $choice in
        1)
            read -p "Enter target (IP/domain): " target
            nmap -sV -sC "$target"
            read -p "Press Enter to continue..."
            ;;
        2)
            read -p "Enter target domain: " target
            sslyze "$target"
            read -p "Press Enter to continue..."
            ;;
        3)
            read -p "Enter domain: " domain
            subfinder -d "$domain"
            read -p "Press Enter to continue..."
            ;;
        4)
            read -p "Enter target: " target
            read -p "Enter port range (e.g., 1-1000): " ports
            nmap -p "$ports" "$target"
            read -p "Press Enter to continue..."
            ;;
        5)
            read -p "Enter URL: " url
            curl -I "$url"
            read -p "Press Enter to continue..."
            ;;
        6)
            read -p "Enter base URL: " base_url
            echo "Using common API paths from wordlist..."
            while read -r path; do
                response=$(curl -s -o /dev/null -w "%{http_code}" "$base_url$path")
                if [ "$response" != "404" ]; then
                    echo "$base_url$path - $response"
                fi
            done < "$WORDLISTS_DIR/mobile_paths.txt"
            read -p "Press Enter to continue..."
            ;;
        7)
            break
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Main menu

main_menu() {
while true; do
print_banner
echo -e “${WHITE}Main Menu${NC}”
echo
echo “Device Status:”
check_android_device
check_ios_device
echo
echo “Analysis Options:”
echo “1. APK Analysis”
echo “2. Dynamic Analysis (Runtime)”
echo “3. Network Analysis”
echo “4. Static Code Analysis”
echo “5. Reporting Tools”
echo “6. Utilities”
echo “7. Update Tools”
echo “8. Install/Setup”
echo “9. Exit”
echo

```
    read -p "Select option [1-9]: " choice
    
    case $choice in
        1)
            apk_analysis_menu
            ;;
        2)
            dynamic_analysis_menu
            ;;
        3)
            network_analysis_menu
            ;;
        4)
            echo "Static analysis options:"
            echo "1. Semgrep scan"
            echo "2. Bandit scan"
            echo "3. NodeJS scan"
            read -p "Select [1-3]: " static_choice
            case $static_choice in
                1)
                    read -p "Enter source directory: " src_dir
                    semgrep --config=auto "$src_dir"
                    ;;
                2)
                    read -p "Enter Python source directory: " src_dir
                    bandit -r "$src_dir"
                    ;;
                3)
                    read -p "Enter NodeJS source directory: " src_dir
                    cd "$TOOLS_DIR/NodeJsScan"
                    python3 nodejsscan.py -d "$src_dir"
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        5)
            echo "Opening reports directory..."
            if command -v xdg-open &> /dev/null; then
                xdg-open "$REPORTS_DIR"
            elif command -v open &> /dev/null; then
                open "$REPORTS_DIR"
            else
                echo "Reports directory: $REPORTS_DIR"
            fi
            read -p "Press Enter to continue..."
            ;;
        6)
            echo "Utility options:"
            echo "1. Start HTTP server"
            echo "2. Base64 encode/decode"
            echo "3. JSON formatter"
            read -p "Select [1-3]: " util_choice
            case $util_choice in
                1)
                    read -p "Enter directory to serve: " serve_dir
                    read -p "Enter port (default 8000): " port
                    port=${port:-8000}
                    echo "Starting HTTP server on port $port"
                    cd "$serve_dir" && python3 -m http.server "$port"
                    ;;
                2)
                    read -p "Enter text to encode: " text
                    echo "Base64: $(echo -n "$text" | base64)"
                    ;;
                3)
                    read -p "Enter JSON string: " json_str
                    echo "$json_str" | jq .
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        7)
            log "Updating tools..."
            cd "$TOOLS_DIR"
            git -C Mobile-Security-Framework-MobSF pull
            pip3 install --upgrade frida-tools objection
            read -p "Press Enter to continue..."
            ;;
        8)
            install_all
            read -p "Press Enter to continue..."
            ;;
        9)
            log "Goodbye!"
            exit 0
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Main execution

main() {
case “${1:-}” in
–install)
install_all
;;
–menu)
if [ ! -d “$HOME/mobile-bugbounty-toolkit” ]; then
error “Toolkit not installed. Run with –install first.”
exit 1
fi
export MOBILE_TOOLKIT_PATH=”$HOME/mobile-bugbounty-toolkit”
TOOLKIT_DIR=”$MOBILE_TOOLKIT_PATH”
TOOLS_DIR=”$TOOLKIT_DIR/tools”
SCRIPTS_DIR=”$TOOLKIT_DIR/scripts”
REPORTS_DIR=”$TOOLKIT_DIR/reports”
WORDLISTS_DIR=”$TOOLKIT_DIR/wordlists”
APKS_DIR=”$TOOLKIT_DIR/apks”
main_menu
;;
*)
echo “Mobile Bug Bounty Toolkit”
echo “Usage: $0 [–install|–menu]”
echo “  –install  Install all tools and dependencies”
echo “  –menu     Launch interactive menu”
echo
echo “First time? Run: $0 –install”
;;
esac
}

# APK Search and Download functions

search_apk_apkpure() {
local app_name=”$1”
log “Searching APKPure for: $app_name”

```
# Create search URL
local search_url="https://apkpure.com/search?q=${app_name// /+}"

echo "Search URL: $search_url"
echo "Opening browser for manual download..."

if command -v xdg-open &> /dev/null; then
    xdg-open "$search_url"
elif command -v open &> /dev/null; then
    open "$search_url"
else
    echo "Please manually visit: $search_url"
fi
```

}

search_apk_apkmirror() {
local app_name=”$1”
log “Searching APKMirror for: $app_name”

```
local search_url="https://www.apkmirror.com/?s=${app_name// /+}"

echo "Search URL: $search_url"
echo "Opening browser for manual download..."

if command -v xdg-open &> /dev/null; then
    xdg-open "$search_url"
elif command -v open &> /dev/null; then
    open "$search_url"
else
    echo "Please manually visit: $search_url"
fi
```

}

download_apk_fdroid() {
local package_name=”$1”
log “Searching F-Droid for: $package_name”

```
# F-Droid API endpoint
local api_url="https://f-droid.org/api/v1/packages/$package_name"

if command -v curl &> /dev/null; then
    local response=$(curl -s "$api_url")
    if echo "$response" | grep -q "packageName"; then
        log "Found package on F-Droid"
        local download_url="https://f-droid.org/repo/${package_name}_$(echo "$response" | jq -r '.suggestedVersionCode').apk"
        echo "Download URL: $download_url"
        
        read -p "Download to $APKS_DIR? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            wget -P "$APKS_DIR" "$download_url"
        fi
    else
        warn "Package not found on F-Droid"
    fi
else
    error "curl not available"
fi
```

}

# APK Installation functions

install_apk_to_device() {
local apk_path=”$1”

```
if [ ! -f "$apk_path" ]; then
    error "APK file not found: $apk_path"
    return 1
fi

# Check if device is connected
if ! check_android_device > /dev/null 2>&1; then
    error "No Android device connected"
    return 1
fi

log "Installing APK: $(basename "$apk_path")"
adb install "$apk_path"

if [ $? -eq 0 ]; then
    log "APK installed successfully"
else
    error "APK installation failed"
fi
```

}

# iOS App Search functions (for jailbroken devices)

search_cydia_package() {
local package_name=”$1”
log “Searching Cydia packages for: $package_name”

```
# Common Cydia repo search URLs
local repos=(
    "https://cydia.saurik.com/api/macciti"
    "https://repo.chariz.com"
    "https://repo.packix.com"
)

echo "Popular Cydia repositories:"
for repo in "${repos[@]}"; do
    echo "- $repo"
done

echo
echo "To search and install packages:"
echo "1. Open Cydia on your jailbroken iOS device"
echo "2. Search for: $package_name"
echo "3. Install directly from Cydia"
```

}

# iOS IPA management

manage_ipa_files() {
while true; do
clear
print_banner
echo -e “${CYAN}iOS IPA Management${NC}”
echo “1. List IPA files”
echo “2. Install IPA (requires jailbreak/sideload tool)”
echo “3. Extract IPA contents”
echo “4. Analyze IPA structure”
echo “5. Search for IPA online”
echo “6. Back to main menu”
echo

```
    read -p "Select option [1-6]: " choice
    
    case $choice in
        1)
            echo "IPA files in $APKS_DIR:"
            find "$APKS_DIR" -name "*.ipa" -exec basename {} \;
            read -p "Press Enter to continue..."
            ;;
        2)
            echo "Available IPA files:"
            find "$APKS_DIR" -name "*.ipa" -exec basename {} \;
            read -p "Enter IPA filename: " ipa_name
            ipa_path="$APKS_DIR/$ipa_name"
            
            if [ -f "$ipa_path" ]; then
                echo "Installation options:"
                echo "1. Cydia Impactor (deprecated)"
                echo "2. AltStore (requires AltServer)"
                echo "3. Sideloadly"
                echo "4. 3uTools"
                echo "5. Manual installation instructions"
                
                read -p "Select method [1-5]: " install_method
                case $install_method in
                    1)
                        warn "Cydia Impactor is deprecated. Consider using AltStore or Sideloadly."
                        ;;
                    2)
                        echo "To install with AltStore:"
                        echo "1. Install AltStore on your device"
                        echo "2. Open AltStore and sign in with Apple ID"
                        echo "3. Use AltServer to install: $ipa_path"
                        ;;
                    3)
                        echo "To install with Sideloadly:"
                        echo "1. Download Sideloadly from sideloadly.io"
                        echo "2. Connect your device"
                        echo "3. Drag and drop: $ipa_path"
                        ;;
                    4)
                        echo "To install with 3uTools:"
                        echo "1. Download 3uTools"
                        echo "2. Connect your device"
                        echo "3. Go to Apps > Install Local App"
                        echo "4. Select: $ipa_path"
                        ;;
                    5)
                        echo "Manual installation methods:"
                        echo "- Jailbroken device: Use AppSync Unified + Filza"
                        echo "- Developer account: Use Xcode"
                        echo "- Enterprise certificate: Contact app distributor"
                        ;;
                esac
            else
                error "IPA file not found"
            fi
            read -p "Press Enter to continue..."
            ;;
        3)
            echo "Available IPA files:"
            find "$APKS_DIR" -name "*.ipa" -exec basename {} \;
            read -p "Enter IPA filename: " ipa_name
            ipa_path="$APKS_DIR/$ipa_name"
            
            if [ -f "$ipa_path" ]; then
                extract_dir="$REPORTS_DIR/$(basename "$ipa_name" .ipa)_extracted"
                mkdir -p "$extract_dir"
                
                log "Extracting IPA contents..."
                unzip "$ipa_path" -d "$extract_dir"
                
                echo "IPA extracted to: $extract_dir"
                echo "Contents:"
                ls -la "$extract_dir"
            else
                error "IPA file not found"
            fi
            read -p "Press Enter to continue..."
            ;;
        4)
            echo "Available IPA files:"
            find "$APKS_DIR" -name "*.ipa" -exec basename {} \;
            read -p "Enter IPA filename: " ipa_name
            ipa_path="$APKS_DIR/$ipa_name"
            
            if [ -f "$ipa_path" ]; then
                log "Analyzing IPA structure..."
                
                # Extract and analyze
                temp_dir="/tmp/ipa_analysis_$$"
                mkdir -p "$temp_dir"
                unzip -q "$ipa_path" -d "$temp_dir"
                
                # Find the app bundle
                app_bundle=$(find "$temp_dir" -name "*.app" -type d | head -1)
                
                if [ -n "$app_bundle" ]; then
                    echo "App Bundle: $(basename "$app_bundle")"
                    echo
                    
                    # Info.plist analysis
                    if [ -f "$app_bundle/Info.plist" ]; then
                        echo "=== Info.plist Analysis ==="
                        if command -v plutil &> /dev/null; then
                            plutil -p "$app_bundle/Info.plist" | head -20
                        else
                            echo "Install plutil for plist analysis"
                        fi
                        echo
                    fi
                    
                    # Binary analysis
                    binary_name=$(basename "$app_bundle")
                    binary_path="$app_bundle/${binary_name%.*}"
                    
                    if [ -f "$binary_path" ]; then
                        echo "=== Binary Analysis ==="
                        file "$binary_path"
                        echo
                        
                        if command -v otool &> /dev/null; then
                            echo "=== Architecture Information ==="
                            otool -f "$binary_path"
                            echo
                            
                            echo "=== Linked Libraries ==="
                            otool -L "$binary_path" | head -10
                        fi
                    fi
                    
                    # Check for common security files
                    echo "=== Security Analysis ==="
                    [ -f "$app_bundle/embedded.mobileprovision" ] && echo "✓ Provisioning profile found"
                    [ -f "$app_bundle/_CodeSignature/CodeResources" ] && echo "✓ Code signature found"
                    
                    # URL schemes
                    if [ -f "$app_bundle/Info.plist" ] && command -v plutil &> /dev/null; then
                        echo
                        echo "=== URL Schemes ==="
                        plutil -p "$app_bundle/Info.plist" | grep -A 5 -B 5 "URLSchemes" || echo "No URL schemes found"
                    fi
                fi
                
                # Cleanup
                rm -rf "$temp_dir"
            else
                error "IPA file not found"
            fi
            read -p "Press Enter to continue..."
            ;;
        5)
            read -p "Enter app name to search: " app_name
            echo "iOS IPA search resources:"
            echo "1. AppDB: https://appdb.to"
            echo "2. iOSGods: https://iosgods.com"
            echo "3. AppValley: https://app.app-valley.vip"
            echo "4. TutuApp: https://tutuapp.uno"
            echo "5. Panda Helper: https://www.pandahelp.vip"
            echo
            warn "Be cautious with third-party app stores. Only download from trusted sources."
            read -p "Press Enter to continue..."
            ;;
        6)
            break
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Enhanced APK/App Manager Menu

app_manager_menu() {
while true; do
clear
print_banner
echo -e “${CYAN}APK/App Manager${NC}”
echo “1. Search and Download APKs”
echo “2. Install APK to Device”
echo “3. List Downloaded APKs”
echo “4. iOS IPA Management”
echo “5. Extract APK from Device”
echo “6. Backup Installed Apps”
echo “7. App Store Analysis”
echo “8. Bulk APK Operations”
echo “9. Back to main menu”
echo

```
    read -p "Select option [1-9]: " choice
    
    case $choice in
        1)
            echo "APK Search Options:"
            echo "1. Search APKPure"
            echo "2. Search APKMirror"
            echo "3. Search F-Droid"
            echo "4. Search multiple sources"
            
            read -p "Select search method [1-4]: " search_method
            read -p "Enter app name or package name: " app_query
            
            case $search_method in
                1)
                    search_apk_apkpure "$app_query"
                    ;;
                2)
                    search_apk_apkmirror "$app_query"
                    ;;
                3)
                    download_apk_fdroid "$app_query"
                    ;;
                4)
                    search_apk_apkpure "$app_query"
                    search_apk_apkmirror "$app_query"
                    download_apk_fdroid "$app_query"
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        2)
            echo "Available APK files:"
            find "$APKS_DIR" -name "*.apk" -exec basename {} \;
            echo
            read -p "Enter APK filename (or full path): " apk_input
            
            if [[ "$apk_input" = /* ]]; then
                apk_path="$apk_input"
            else
                apk_path="$APKS_DIR/$apk_input"
            fi
            
            install_apk_to_device "$apk_path"
            read -p "Press Enter to continue..."
            ;;
        3)
            echo "Downloaded APK files:"
            echo "Location: $APKS_DIR"
            echo
            find "$APKS_DIR" -name "*.apk" -exec ls -lh {} \; 2>/dev/null || echo "No APK files found"
            echo
            echo "Downloaded IPA files:"
            find "$APKS_DIR" -name "*.ipa" -exec ls -lh {} \; 2>/dev/null || echo "No IPA files found"
            read -p "Press Enter to continue..."
            ;;
        4)
            manage_ipa_files
            ;;
        5)
            if check_android_device > /dev/null 2>&1; then
                echo "Installed packages:"
                adb shell pm list packages | head -20
                echo "... (showing first 20)"
                echo
                read -p "Enter package name to extract: " package_name
                
                # Get APK path on device
                apk_path=$(adb shell pm path "$package_name" | cut -d':' -f2 | tr -d '\r')
                
                if [ -n "$apk_path" ]; then
                    output_file="$APKS_DIR/${package_name}.apk"
                    adb pull "$apk_path" "$output_file"
                    log "APK extracted to: $output_file"
                else
                    error "Package not found"
                fi
            else
                error "No Android device connected"
            fi
            read -p "Press Enter to continue..."
            ;;
        6)
            if check_android_device > /dev/null 2>&1; then
                backup_dir="$APKS_DIR/device_backup_$(date +%Y%m%d_%H%M%S)"
                mkdir -p "$backup_dir"
                
                log "Creating device app backup..."
                echo "This may take several minutes..."
                
                # Get all user-installed packages
                adb shell pm list packages -3 | cut -d':' -f2 | while read package; do
                    package=$(echo "$package" | tr -d '\r')
                    apk_path=$(adb shell pm path "$package" | cut -d':' -f2 | tr -d '\r')
                    if [ -n "$apk_path" ]; then
                        echo "Backing up: $package"
                        adb pull "$apk_path" "$backup_dir/${package}.apk" 2>/dev/null
                    fi
                done
                
                log "Backup completed: $backup_dir"
            else
                error "No Android device connected"
            fi
            read -p "Press Enter to continue..."
            ;;
        7)
            echo "App Store Analysis Options:"
            echo "1. Google Play Store link analysis"
            echo "2. App permissions comparison"
            echo "3. Version history check"
            echo "4. Similar apps discovery"
            
            read -p "Select analysis type [1-4]: " analysis_type
            read -p "Enter package name: " package_name
            
            case $analysis_type in
                1)
                    play_store_url="https://play.google.com/store/apps/details?id=$package_name"
                    echo "Google Play Store URL: $play_store_url"
                    
                    if command -v xdg-open &> /dev/null; then
                        xdg-open "$play_store_url"
                    elif command -v open &> /dev/null; then
                        open "$play_store_url"
                    fi
                    ;;
                2)
                    echo "Analyzing app permissions..."
                    if check_android_device > /dev/null 2>&1; then
                        adb shell dumpsys package "$package_name" | grep permission
                    else
                        echo "Connect device for live permission analysis"
                    fi
                    ;;
                3)
                    echo "Version history resources:"
                    echo "- APKMirror: https://www.apkmirror.com/apk/search/?q=$package_name"
                    echo "- APKPure: https://apkpure.com/search?q=$package_name"
                    ;;
                4)
                    echo "Similar apps discovery:"
                    echo "Use Google Play Store 'Similar' section or:"
                    echo "- App Annie: https://www.appannie.com"
                    echo "- SimilarWeb: https://www.similarweb.com"
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        8)
            echo "Bulk APK Operations:"
            echo "1. Batch install multiple APKs"
            echo "2. Batch analysis of APKs"
            echo "3. Clean up old APKs"
            echo "4. Generate APK inventory"
            
            read -p "Select operation [1-4]: " bulk_op
            
            case $bulk_op in
                1)
                    if check_android_device > /dev/null 2>&1; then
                        echo "Installing all APKs in $APKS_DIR..."
                        find "$APKS_DIR" -name "*.apk" -exec adb install {} \;
                    else
                        error "No Android device connected"
                    fi
                    ;;
                2)
                    echo "Analyzing all APKs..."
                    find "$APKS_DIR" -name "*.apk" | while read apk; do
                        echo "Analyzing: $(basename "$apk")"
                        "$SCRIPTS_DIR/apk_analyzer.sh" "$apk"
                    done
                    ;;
                3)
                    read -p "Delete APKs older than how many days? " days
                    find "$APKS_DIR" -name "*.apk" -mtime +$days -delete
                    log "Cleaned up APKs older than $days days"
                    ;;
                4)
                    inventory_file="$REPORTS_DIR/apk_inventory_$(date +%Y%m%d).txt"
                    echo "Generating APK inventory..."
                    echo "APK Inventory - $(date)" > "$inventory_file"
                    echo "=========================" >> "$inventory_file"
                    find "$APKS_DIR" -name "*.apk" -exec ls -lh {} \; >> "$inventory_file"
                    log "Inventory saved to: $inventory_file"
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        9)
            break
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Enhanced main menu with app manager

enhanced_main_menu() {
while true; do
print_banner
echo -e “${WHITE}Main Menu${NC}”
echo
echo “Device Status:”
check_android_device
check_ios_device
echo
echo “Analysis Options:”
echo “1. APK Analysis”
echo “2. Dynamic Analysis (Runtime)”
echo “3. Network Analysis”
echo “4. Static Code Analysis”
echo “5. APK/App Manager”
echo “6. Reporting Tools”
echo “7. Utilities”
echo “8. Update Tools”
echo “9. Install/Setup”
echo “10. Exit”
echo

```
    read -p "Select option [1-10]: " choice
    
    case $choice in
        1)
            apk_analysis_menu
            ;;
        2)
            dynamic_analysis_menu
            ;;
        3)
            network_analysis_menu
            ;;
        4)
            echo "Static analysis options:"
            echo "1. Semgrep scan"
            echo "2. Bandit scan"
            echo "3. NodeJS scan"
            read -p "Select [1-3]: " static_choice
            case $static_choice in
                1)
                    read -p "Enter source directory: " src_dir
                    semgrep --config=auto "$src_dir"
                    ;;
                2)
                    read -p "Enter Python source directory: " src_dir
                    bandit -r "$src_dir"
                    ;;
                3)
                    read -p "Enter NodeJS source directory: " src_dir
                    cd "$TOOLS_DIR/NodeJsScan"
                    python3 nodejsscan.py -d "$src_dir"
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        5)
            app_manager_menu
            ;;
        6)
            echo "Opening reports directory..."
            if command -v xdg-open &> /dev/null; then
                xdg-open "$REPORTS_DIR"
            elif command -v open &> /dev/null; then
                open "$REPORTS_DIR"
            else
                echo "Reports directory: $REPORTS_DIR"
            fi
            read -p "Press Enter to continue..."
            ;;
        7)
            echo "Utility options:"
            echo "1. Start HTTP server"
            echo "2. Base64 encode/decode"
            echo "3. JSON formatter"
            echo "4. Hash calculator"
            echo "5. Certificate analyzer"
            read -p "Select [1-5]: " util_choice
            case $util_choice in
                1)
                    read -p "Enter directory to serve: " serve_dir
                    read -p "Enter port (default 8000): " port
                    port=${port:-8000}
                    echo "Starting HTTP server on port $port"
                    cd "$serve_dir" && python3 -m http.server "$port"
                    ;;
                2)
                    echo "1. Encode  2. Decode"
                    read -p "Select [1-2]: " enc_choice
                    if [ "$enc_choice" = "1" ]; then
                        read -p "Enter text to encode: " text
                        echo "Base64: $(echo -n "$text" | base64)"
                    else
                        read -p "Enter base64 to decode: " b64_text
                        echo "Decoded: $(echo "$b64_text" | base64 -d)"
                    fi
                    ;;
                3)
                    read -p "Enter JSON string: " json_str
                    echo "$json_str" | jq .
                    ;;
                4)
                    read -p "Enter file path: " file_path
                    if [ -f "$file_path" ]; then
                        echo "MD5:    $(md5sum "$file_path" | cut -d' ' -f1)"
                        echo "SHA1:   $(sha1sum "$file_path" | cut -d' ' -f1)"
                        echo "SHA256: $(sha256sum "$file_path" | cut -d' ' -f1)"
                    else
                        error "File not found"
                    fi
                    ;;
                5)
                    read -p "Enter certificate file path: " cert_path
                    if [ -f "$cert_path" ]; then
                        openssl x509 -in "$cert_path" -text -noout
                    else
                        error "Certificate file not found"
                    fi
                    ;;
            esac
            read -p "Press Enter to continue..."
            ;;
        8)
            log "Updating tools..."
            cd "$TOOLS_DIR"
            git -C Mobile-Security-Framework-MobSF pull 2>/dev/null || echo "MobSF update skipped"
            pip3 install --upgrade frida-tools objection semgrep bandit
            read -p "Press Enter to continue..."
            ;;
        9)
            install_all
            read -p "Press Enter to continue..."
            ;;
        10)
            log "Goodbye!"
            exit 0
            ;;
        *)
            error "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
done
```

}

# Replace main_menu function call with enhanced version

main() {
case “${1:-}” in
–install)
install_all
;;
–menu)
if [ ! -d “$HOME/mobile-bugbounty-toolkit” ]; then
error “Toolkit not installed. Run with –install first.”
exit 1
fi
export MOBILE_TOOLKIT_PATH=”$HOME/mobile-bugbounty-toolkit”
TOOLKIT_DIR=”$MOBILE_TOOLKIT_PATH”
TOOLS_DIR=”$TOOLKIT_DIR/tools”
SCRIPTS_DIR=”$TOOLKIT_DIR/scripts”
REPORTS_DIR=”$TOOLKIT_DIR/reports”
WORDLISTS_DIR=”$TOOLKIT_DIR/wordlists”
APKS_DIR=”$TOOLKIT_DIR/apks”
enhanced_main_menu
;;
*)
echo “Mobile Bug Bounty Toolkit”
echo “Usage: $0 [–install|–menu]”
echo “  –install  Install all tools and dependencies”
echo “  –menu     Launch interactive menu”
echo
echo “First time? Run: $0 –install”
;;
esac
}

# Execute main function

main “$@”