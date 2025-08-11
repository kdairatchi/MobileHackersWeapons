#!/bin/bash

# Source the installation script
source /home/ubuntu/install_tools.sh

# Function to display the main menu
display_main_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  Mobile Bug Bounty Script Menu"
    echo "---------------------------------------------------"
    echo "1. Install Tools"
    echo "2. APK/iOS App Search and Install"
    echo "3. Exit"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " main_choice
}

# Function to display the Install Tools submenu
display_install_tools_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  Install Tools Menu"
    echo "---------------------------------------------------"
    echo "1. Android Tools"
    echo "2. iOS Tools"
    echo "3. Network Tools"
    echo "4. Generic Tools"
    echo "5. Back to Main Menu"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " install_choice
}

# Function to display Android Tools submenu
display_android_tools_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  Android Tools"
    echo "---------------------------------------------------"
    echo "1. MobSF"
    echo "2. Apktool"
    echo "3. Frida"
    echo "4. ADB"
    echo "5. Objection"
    echo "6. Back to Install Tools Menu"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " android_choice
}

# Function to display iOS Tools submenu
display_ios_tools_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  iOS Tools"
    echo "---------------------------------------------------"
    echo "1. Frida"
    echo "2. MobSF"
    echo "3. Objection"
    echo "4. Xcode Command Line Tools (Manual)"
    echo "5. Sideloadly (Manual)"
    echo "6. Back to Install Tools Menu"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " ios_choice
}

# Function to display Network Tools submenu
display_network_tools_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  Network Tools"
    echo "---------------------------------------------------"
    echo "1. Burp Suite (Manual)"
    echo "2. mitmproxy"
    echo "3. Wireshark"
    echo "4. ZAP (Manual)"
    echo "5. Back to Install Tools Menu"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " network_choice
}

# Function to display Generic Tools submenu
display_generic_tools_menu() {
    clear
    echo "---------------------------------------------------"
    echo "  Generic Tools"
    echo "---------------------------------------------------"
    echo "1. Ghidra (Manual)"
    echo "2. VS Code"
    echo "3. Back to Install Tools Menu"
    echo "---------------------------------------------------"
    read -p "Enter your choice: " generic_choice
}

# Main loop
while true;
do
    display_main_menu

    case $main_choice in
        1)
            while true;
            do
                display_install_tools_menu
                case $install_choice in
                    1)
                        while true;
                        do
                            display_android_tools_menu
                            case $android_choice in
                                1) install_tool "MobSF" ;;
                                2) install_tool "Apktool" ;;
                                3) install_tool "Frida" ;;
                                4) install_tool "ADB" ;;
                                5) install_tool "Objection" ;;
                                6) break ;;
                                *)
                                    echo "Invalid choice. Please try again."
                                    sleep 2
                                    ;;
                            esac
                            read -p "Press Enter to continue..." # Pause after installation
                        done
                        ;;
                    2)
                        while true;
                        do
                            display_ios_tools_menu
                            case $ios_choice in
                                1) install_tool "Frida" ;;
                                2) install_tool "MobSF" ;;
                                3) install_tool "Objection" ;;
                                4) echo "Please install Xcode Command Line Tools manually: xcode-select --install" ;;
                                5) echo "Please download and install Sideloadly manually from: https://sideloadly.io/" ;;
                                6) break ;;
                                *)
                                    echo "Invalid choice. Please try again."
                                    sleep 2
                                    ;;
                            esac
                            read -p "Press Enter to continue..." # Pause after installation
                        done
                        ;;
                    3)
                        while true;
                        do
                            display_network_tools_menu
                            case $network_choice in
                                1) install_tool "Burp Suite" ;;
                                2) install_tool "mitmproxy" ;;
                                3) install_tool "Wireshark" ;;
                                4) echo "Please download and install OWASP ZAP manually from: https://www.zaproxy.org/download/" ;;
                                5) break ;;
                                *)
                                    echo "Invalid choice. Please try again."
                                    sleep 2
                                    ;;
                            esac
                            read -p "Press Enter to continue..." # Pause after installation
                        done
                        ;;
                    4)
                        while true;
                        do
                            display_generic_tools_menu
                            case $generic_choice in
                                1) install_tool "Ghidra" ;;
                                2) install_tool "VS Code" ;;
                                3) break ;;
                                *)
                                    echo "Invalid choice. Please try again."
                                    sleep 2
                                    ;;
                            esac
                            read -p "Press Enter to continue..." # Pause after installation
                        done
                        ;;
                    5) break ;;
                    *)
                        echo "Invalid choice. Please try again."
                        sleep 2
                        ;;
                esac
            done
            ;;
        2)
            python3 /home/ubuntu/app_manager.py
            read -p "Press Enter to continue..." # Pause after app manager
            ;;
        3)
            echo "Exiting. Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please try again."
            sleep 2
            ;;
    esac
done


