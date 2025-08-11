#!/bin/bash

# Function to install MobSF
install_mobsf() {
    echo "Installing MobSF..."
    # MobSF installation steps (example for Linux)
    # Requires Python3, git, etc.
    sudo apt update
    sudo apt install -y python3 python3-pip git default-jdk
    pip3 install MobSF
    echo "MobSF installation complete."
}

# Function to install Apktool
install_apktool() {
    echo "Installing Apktool..."
    # Apktool installation steps
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O apktool.jar
    chmod +x apktool
    sudo mv apktool /usr/local/bin/
    sudo mv apktool.jar /usr/local/bin/
    echo "Apktool installation complete."
}

# Function to install Frida
install_frida() {
    echo "Installing Frida..."
    # Frida installation steps
    pip3 install frida-tools
    echo "Frida installation complete."
}

# Function to install ADB
install_adb() {
    echo "Installing ADB..."
    # ADB installation steps
    sudo apt install -y android-tools-adb android-tools-fastboot
    echo "ADB installation complete."
}

# Function to install Objection
install_objection() {
    echo "Installing Objection..."
    # Objection installation steps
    pip3 install objection
    echo "Objection installation complete."
}

# Function to install Burp Suite Community Edition (placeholder - manual download/install)
install_burpsuite() {
    echo "Burp Suite Community Edition needs to be downloaded and installed manually from PortSwigger website."
    echo "Please visit: https://portswigger.net/burp/communitydownload"
}

# Function to install mitmproxy
install_mitmproxy() {
    echo "Installing mitmproxy..."
    pip3 install mitmproxy
    echo "mitmproxy installation complete."
}

# Function to install Wireshark
install_wireshark() {
    echo "Installing Wireshark..."
    sudo apt install -y wireshark
    sudo dpkg-reconfigure wireshark-common
    sudo usermod -a -G wireshark $USER
    echo "Wireshark installation complete. Please log out and log back in for changes to take effect."
}

# Function to install Ghidra (placeholder - manual download/install)
install_ghidra() {
    echo "Ghidra needs to be downloaded and installed manually from GitHub releases."
    echo "Please visit: https://github.com/NationalSecurityAgency/ghidra/releases"
}

# Function to install VS Code
install_vscode() {
    echo "Installing Visual Studio Code..."
    sudo apt update
    sudo apt install -y software-properties-common apt-transport-https wget
    wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main"
    sudo apt update
    sudo apt install -y code
    echo "Visual Studio Code installation complete."
}

# Main installation function to be called from the menu
install_tool() {
    case "$1" in
        "MobSF") install_mobsf ;;
        "Apktool") install_apktool ;;
        "Frida") install_frida ;;
        "ADB") install_adb ;;
        "Objection") install_objection ;;
        "Burp Suite") install_burpsuite ;;
        "mitmproxy") install_mitmproxy ;;
        "Wireshark") install_wireshark ;;
        "Ghidra") install_ghidra ;;
        "VS Code") install_vscode ;;
        *)
            echo "Unknown tool: $1"
            ;;
    esac
}


