#!/bin/bash

# install_AP.sh
# Automated Bridge Mode Access Point setup script for Raspberry Pi OS (Debian-based Linux).
# Configures Ethernet and USB WiFi adapter into a bridge, with the main router providing DHCP.

# --- Configuration Variables ---
# These defaults will be prompted to change by the user.
AP_ID="raspberry_ap_001"
MQTT_BROKER_IP=""
AP_SSID="RaspberryPi_AP"
AP_PASSWORD="" # IMPORTANT: Must be at least 8 characters for WPA2
AP_CHANNEL="auto" # 'auto' or specific number (e.g., 6, 11 for 2.4GHz; 36, 40 for 5GHz)
AP_BAND="g"       # 'g' for 2.4GHz (802.11g/n), 'a' for 5GHz (802.11a/n/ac)

# Interface names (usually eth0 for built-in Ethernet, wlan0/wlan1 for WiFi)
UPLINK_IFACE="eth0"
WIFI_IFACE="" # This will be detected/prompted, crucial!
BRIDGE_IFACE="br0" # Name of the new bridge interface

# Python virtual environment path for MQTT scripts
PYTHON_VENV_AP="/opt/ap_mqtt_venv"

# --- Functions ---

print_header() {
    echo ""
    echo "========================================================"
    echo " Raspberry Pi OS Bridge Mode AP Installer Script"
    echo "========================================================"
    echo "This script configures a Raspberry Pi running Raspberry Pi OS"
    echo "to act as a WiFi Access Point in bridge mode (dumb AP)."
    echo "Your main router will provide DHCP leases to all clients (wired and wireless)."
    echo ""
}

print_help() {
    echo "Usage: sudo bash $0"
    echo ""
    echo "IMPORTANT:"
    echo "  - Run this script on a Raspberry Pi running Raspberry Pi OS."
    echo "  - Ensure the Pi has internet access via Ethernet for package installation."
    echo "  - You will be prompted for key settings."
    echo "  - This script makes significant changes to network configuration and firewall."
    echo "    BACKUP YOUR PI'S SD CARD BEFORE PROCEEDING IF YOU HAVE CRITICAL DATA."
    echo ""
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        echo "Please use 'sudo bash $0'."
        exit 1
    fi
}

check_internet_access() {
    echo "Checking internet access..."
    # Attempt a quick update check without actual update
    apt update > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Could not update apt lists. Internet access might be down."
        echo "Please ensure your Raspberry Pi has internet connectivity via Ethernet."
        read -p "Press Enter to continue anyway (might fail if packages are needed) or Ctrl+C to exit..."
    else
        echo "Internet access confirmed (apt update successful)."
    # Add a check for pinging a common host to confirm actual internet access
        ping -c 3 google.com > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Warning: apt update worked, but could not ping google.com. Internet might be flaky."
            read -p "Press Enter to continue anyway or Ctrl+C to exit..."
        fi
    fi
}

prompt_for_settings() {
    echo "--- Configure Your Access Point ---"

    read -p "Enter a unique ID for this Access Point (e.g., pi_ap_living_room): [${AP_ID}] " input_ap_id
    AP_ID=${input_ap_id:-$AP_ID}

    read -p "Enter the IP address of your MQTT Broker (e.g., 192.168.1.100): " input_mqtt_ip
    while [[ -z "$input_mqtt_ip" ]]; do
        echo "MQTT Broker IP cannot be empty."
        read -p "Enter the IP address of your MQTT Broker: " input_mqtt_ip
    done
    MQTT_BROKER_IP=$input_mqtt_ip

    read -p "Enter the SSID (WiFi Network Name): [${AP_SSID}] " input_ssid
    AP_SSID=${input_ssid:-$AP_SSID}

    read -sp "Enter the WiFi Password (min 8 characters, leave empty for an OPEN network): " input_password
    echo ""
    AP_PASSWORD=${input_password:-$AP_PASSWORD}
    if [[ -z "$AP_PASSWORD" ]]; then
        echo "Warning: No password entered. WiFi will be OPEN (unsecured)."
        read -p "Are you sure you want an open WiFi network? (y/N): " confirm_open
        if [[ ! "$confirm_open" =~ ^[Yy]$ ]]; then
            echo "Please re-run the script and enter a password."
            exit 1
        fi
    elif [[ ${#AP_PASSWORD} -lt 8 ]]; then
        echo "Error: WiFi password must be at least 8 characters long for WPA2."
        exit 1
    fi

    echo "Choose WiFi Band:"
    echo "  1) 2.4GHz (g/n)"
    echo "  2) 5GHz (a/n/ac)"
    read -p "Enter choice (1 or 2): [1] " band_choice
    case $band_choice in
        2) AP_BAND="a" ;; # 'a' mode covers 802.11a/n/ac
        *) AP_BAND="g" ;; # 'g' mode covers 802.11g/n
    esac
    echo "Selected WiFi Band: ${AP_BAND}"

    read -p "Enter WiFi Channel ('auto' for automatic, or a specific number like 1, 6, 11, 36, etc.): [${AP_CHANNEL}] " input_channel
    AP_CHANNEL=${input_channel:-$AP_CHANNEL}

    echo ""
    echo "--- Summary of Settings ---"
    echo "AP ID: ${AP_ID}"
    echo "MQTT Broker IP: ${MQTT_BROKER_IP}"
    echo "SSID: ${AP_SSID}"
    echo "Password: ${AP_PASSWORD:+******** (set)}"
    echo "WiFi Band: ${AP_BAND}"
    echo "WiFi Channel: ${AP_CHANNEL}"
    echo "AP will be in Bridge Mode (Main Router provides DHCP leases)."
    echo ""
    read -p "Are these settings correct? (y/N): " confirm_settings
    if [[ ! "$confirm_settings" =~ ^[Yy]$ ]]; then
        echo "Exiting. Please re-run the script to set up again."
        exit 1
    fi
}

detect_wifi_interface() {
    echo "Detecting USB WiFi adapter..."
    echo "Attempting to load common WiFi firmware. This might take a moment..."
    # Install common firmware packages that often contain blobs for WiFi adapters
    apt install -y firmware-realtek firmware-misc-nonfree || true
    sleep 5 # Give time for firmware/drivers to load

    # List actual wlan interfaces (excluding virtual ones)
    local all_wlan_ifaces=()
    while IFS= read -r line; do
        all_wlan_ifaces+=("$line")
    done < <(ls /sys/class/net/ | grep -E '^wlan[0-9]+$')

    # Filter out built-in Pi WiFi if it's likely (heuristic: usually wlan0 and links to 'platform')
    local filtered_wlan_ifaces=()
    for iface in "${all_wlan_ifaces[@]}"; do
        # Check if interface exists in sysfs and its device symlink does NOT contain 'platform'
        # 'platform' usually indicates onboard devices
        if [[ -e "/sys/class/ieee80211/phy${iface//wlan/}" ]]; then
            device_path="$(readlink "/sys/class/ieee80211/phy${iface//wlan/}/device")"
            if [[ "$device_path" =~ "platform" ]]; then
                echo "Skipping likely built-in WiFi interface: ${iface}"
                continue # Skip built-in
            fi
        fi
        filtered_wlan_ifaces+=("$iface")
    done

    NUM_WIFI_DEVICES="${#filtered_wlan_ifaces[@]}"

    if [ "$NUM_WIFI_DEVICES" -eq 0 ]; then
        echo "Error: No suitable USB WiFi interfaces detected for AP mode after driver attempts."
        echo "Please verify your USB WiFi adapter is plugged in, and check 'lsusb' and 'dmesg' for its chipset."
        echo "You may need to manually install specific firmware or kernel modules for it (e.g., 'sudo apt install firmware-YOUR_CHIPSET_NAME' or compile driver)."
        exit 1
    elif [ "$NUM_WIFI_DEVICES" -eq 1 ]; then
        WIFI_IFACE="${filtered_wlan_ifaces[0]}"
        echo "Detected single WiFi interface: ${WIFI_IFACE}"
    else
        echo "Multiple suitable WiFi interfaces detected:"
        for iface in "${filtered_wlan_ifaces[@]}"; do
            echo "  - ${iface}"
        done
        read -p "Please enter the name of the USB WiFi interface to use for the AP \(e.g., wlan0, wlan1\): " user_wifi_iface
        WIFI_IFACE=${user_wifi_iface:-"${filtered_wlan_ifaces[0]}"} # Default to first if empty
        echo "Using WiFi interface: ${WIFI_IFACE}"
    fi

    # Final crucial check: ensure WIFI_IFACE is populated
    if [ -z "$WIFI_IFACE" ]; then
        echo "Error: No WiFi interface selected or detected for AP. Exiting."
        exit 1
    fi

    # Bring up the interface if it's down
    echo "Bringing up ${WIFI_IFACE}..."
    ip link set dev "${WIFI_IFACE}" up
    sleep 1 # Give it a moment to come up
}

install_packages() {
    echo "Installing necessary packages (hostapd, bridge-utils, python3, etc.)..."
    # bridge-utils for brctl
    apt update
    apt install -y hostapd bridge-utils python3 python3-pip python3-venv jq bc netfilter-persistent iptables-persistent
    if [ $? -ne 0 ]; then
        echo "Error installing core packages. Please check your internet connection."
        exit 1
    fi

    # Ensure hostapd user and group exist (added for robustness)
    echo "Ensuring hostapd user and group exist..."
    if ! id -g hostapd >/dev/null 2>&1; then
        echo "Creating hostapd group..."
        addgroup --system hostapd
    fi
    if ! id -u hostapd >/dev/null 2>&1; then
        echo "Creating hostapd user..."
        adduser --system --no-create-home --ingroup hostapd --disabled-password --shell /usr/sbin/nologin hostapd
    fi

    # Create Python virtual environment and install paho-mqtt
    echo "Creating Python virtual environment at ${PYTHON_VENV_AP} and installing paho-mqtt..."
    mkdir -p "$PYTHON_VENV_AP"
    python3 -m venv "$PYTHON_VENV_AP"
    source "$PYTHON_VENV_AP/bin/activate" # Activate venv for pip install
    pip install paho-mqtt
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install paho-mqtt into virtual environment. Python scripts may not work correctly."
        deactivate # Deactivate venv if install failed
        exit 1
    fi
    deactivate # Deactivate venv after installation

    echo "Packages installed and Python virtual environment set up."
}

configure_network() {
    echo "Configuring network interfaces for bridge mode (${UPLINK_IFACE}, ${WIFI_IFACE}, and ${BRIDGE_IFACE})..."

    # --- dhcpcd.conf (Primary network configuration for most Raspberry Pi OS versions) ---
    cp /etc/dhcpcd.conf /etc/dhcpcd.conf.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/dhcpcd.conf to /etc/dhcpcd.conf.bak.$(date +%Y%m%d%H%M%S)"

    # Clear any existing configuration for eth0 and the WiFi interface in dhcpcd.conf
    # We want dhcpcd to manage the bridge interface, not the individual ports.
    sed -i "/^interface ${UPLINK_IFACE}/{:a;N;/^$/!ba;s/interface ${UPLINK_IFACE}.*?\n//M}" /etc/dhcpcd.conf || true
    sed -i "/^interface ${WIFI_IFACE}/{:a;N;/^$/!ba;s/interface ${WIFI_IFACE}.*?\n//M}" /etc/dhcpcd.conf || true

    # Configure the bridge interface (br0) to get DHCP from the main router
    echo "" >> /etc/dhcpcd.conf
    echo "# Bridge interface for AP mode (gets DHCP from main router)" >> /etc/dhcpcd.conf
    echo "interface ${BRIDGE_IFACE}" >> /etc/dhcpcd.conf
    echo "    nohook wpa_supplicant" >> /etc/dhcpcd.conf # No wpa_supplicant on bridge

    # --- sysctl.conf (Enable IP Forwarding for bridge filtering) ---
    # Although not strictly needed for basic bridging, it can be useful for some bridge
    # filtering or future advanced features. Keep it enabled.
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/sysctl.conf to /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)"
    sed -i '/^#net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf # Uncomment if commented
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf # Add if not present
    sysctl -p # Apply changes immediately
    echo "IP forwarding enabled."

    # --- Create the bridge ---
    echo "Creating bridge interface ${BRIDGE_IFACE}..."
    ip link add name "${BRIDGE_IFACE}" type bridge
    ip link set dev "${BRIDGE_IFACE}" up
    sleep 1 # Give it a moment to come up

    # Add interfaces to the bridge
    echo "Adding ${UPLINK_IFACE} and ${WIFI_IFACE} to bridge ${BRIDGE_IFACE}..."
    ip link set dev "${UPLINK_IFACE}" master "${BRIDGE_IFACE}"
    ip link set dev "${UPLINK_IFACE}" up # Ensure uplink is up

    # The WiFi interface needs to be manually set up after hostapd starts,
    # or hostapd will add it to the bridge itself.
    # For hostapd directly binding to the bridge, we just need to bring it up.
    ip link set dev "${WIFI_IFACE}" up

    # Kill any lingering wpa_supplicant processes on the AP interface
    echo "Killing any wpa_supplicant processes on ${WIFI_IFACE}..."
    pkill -f "wpa_supplicant.*-i${WIFI_IFACE}" || true
    sleep 1

    # Restart dhcpcd service to apply changes (to get IP on br0)
    echo "Restarting dhcpcd.service to get IP for ${BRIDGE_IFACE}..."
    if systemctl is-active --quiet dhcpcd; then
        systemctl restart dhcpcd
    else
        echo "Warning: dhcpcd.service not found or not active. Skipping restart."
        echo "Please ensure dhcpcd is installed and running if you encounter network issues."
    fi
    sleep 5 # Give dhcpcd time to acquire an IP
    echo "Network configuration for bridge mode updated."
}

configure_iptables() {
    echo "Configuring IPTables (no NAT in bridge mode, basic firewall for bridge)..."

    # Crucial check: ensure interfaces are valid before applying iptables rules
    if [ -z "$UPLINK_IFACE" ] || [ -z "$WIFI_IFACE" ] || [ -z "$BRIDGE_IFACE" ]; then
        echo "Error: Network interfaces not properly identified. Cannot configure iptables."
        exit 1
    fi

    # Clear existing rules (DANGEROUS if not understood, but necessary for clean setup)
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Allow traffic over the bridge (standard for bridge mode)
    # This might not be strictly necessary as default FORWARD policy is ACCEPT, but good for clarity.
    iptables -A FORWARD -i "${BRIDGE_IFACE}" -j ACCEPT
    iptables -A FORWARD -o "${BRIDGE_IFACE}" -j ACCEPT

    # Optional: Basic firewall for the AP itself (e.g., allow SSH from LAN)
    # Assuming SSH runs on the IP of br0, this is typically handled by default INPUT ACCEPT.
    # If you later want to restrict access to the AP, you'd add more specific INPUT rules.

    # Save iptables rules so they persist across reboots
    netfilter-persistent save
    echo "IPTables rules configured and saved."
}

configure_hostapd() {
    echo "Configuring hostapd for the Access Point..."

    # Ensure hostapd config directory exists
    mkdir -p /etc/hostapd

    # hostapd.conf content
    cat << 'EOF_HOSTAPD_CONF' > /etc/hostapd/hostapd.conf
interface=${WIFI_IFACE} # Hostapd manages the wifi interface itself, and it is added to the bridge.
bridge=${BRIDGE_IFACE} # Specify the bridge interface
driver=nl80211
ssid=${AP_SSID}
hw_mode=${AP_BAND} # 'g' for 2.4GHz, 'a' for 5GHz
channel=${AP_CHANNEL}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${AP_PASSWORD}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
EOF_HOSTAPD_CONF
    # Append specific 802.11n/ac settings based on band
    if [ "${AP_BAND}" == "g" ]; then
        echo "ieee80211n=1" >> /etc/hostapd/hostapd.conf
        echo "ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]" >> /etc/hostapd/hostapd.conf
    elif [ "${AP_BAND}" == "a" ]; then
        echo "ieee80211n=1" >> /etc/hostapd/hostapd.conf
        echo "ieee80211ac=1" >> /etc/hostapd/hostapd.conf # Enable 802.11ac for 5GHz
        echo "ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]" >> /etc/hostapd/hostapd.conf
        echo "vht_capab=[VHT20][VHT40][VHT80]" >> /etc/hostapd/hostapd.conf # Consider VHT80 for 5GHz if supported
        echo "vht_oper_chwidth=1" >> /etc/hostapd/hostapd.conf # For VHT80 (width of 80MHz)
    fi

    # Point hostapd service to the new config file
    sed -i 's/^#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/' /etc/default/hostapd

    # Disable default hostapd.service and enable ours.
    # We will use a custom systemd service for better management.
    systemctl stop hostapd || true
    systemctl disable hostapd || true

    echo "hostapd configuration complete."
}

disable_dnsmasq() {
    echo "Disabling dnsmasq (not needed in bridge mode)..."
    # Ensure dnsmasq is stopped and disabled
    systemctl stop dnsmasq || true
    systemctl disable dnsmasq || true
    # Remove any custom dnsmasq config we might have created previously
    rm -f /etc/dnsmasq.conf
    rm -f /etc/dnsmasq.d/*ap_dhcp.conf
    echo "dnsmasq disabled."
}

create_mqtt_scripts() {
    echo "Creating Python MQTT client scripts for reporting and command listening..."

    # Python interpreter path from the virtual environment
    PYTHON_VENV_EXE="${PYTHON_VENV_AP}/bin/python"

    # Create the connected device reporter script (with signal strength and heartbeat)
    # NO SINGLE QUOTES AROUND EOF_REPORT_STATUS_SCRIPT to allow variable substitution
    cat << EOF_REPORT_STATUS_SCRIPT > /usr/local/bin/report_ap_status.py
#!/usr/bin/env python3

import paho.mqtt.client as mqtt
import json
import subprocess
import time
import sys
import re
import os # Import os module to get env variable

# Retrieve AP_ID and MQTT_BROKER_IP from environment variables passed by systemd
AP_ID = os.environ.get('AP_ID', 'default_ap_id')
MQTT_BROKER_IP = os.environ.get('MQTT_BROKER_IP', '127.0.0.1')
WIFI_IFACE = os.environ.get('WIFI_IFACE', 'wlan0')
UPLINK_IFACE = os.environ.get('UPLINK_IFACE', 'eth0')
BRIDGE_IFACE = os.environ.get('BRIDGE_IFACE', 'br0')

def run_command(cmd, log_error=True):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if log_error:
            print(f"Error executing command '{cmd}': {e.stderr.strip()}", file=sys.stderr)
        return None
    except FileNotFoundError:
        if log_error:
            print(f"Command '{cmd.split()[0]}' not found.", file=sys.stderr)
        return None

def report_status():
    connected_devices = 0
    avg_signal = "N/A"
    current_ip = "unknown"

    # Get connected devices and signal strength from hostapd_cli
    hostapd_status = run_command(f"hostapd_cli -i {WIFI_IFACE} all_sta")
    if hostapd_status:
        sta_lines = hostapd_status.splitlines()
        mac_addresses = [line.split()[0] for line in sta_lines if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', line.split()[0])]
        connected_devices = len(mac_addresses)

        total_signal = 0
        signal_count = 0
        for mac in mac_addresses:
            sta_info = run_command(f"hostapd_cli -i {WIFI_IFACE} sta {mac}")
            if sta_info:
                signal_match = re.search(r'signal:\s*([-]?\d+)\s*dBm', sta_info)
                if signal_match:
                    total_signal += int(signal_match.group(1))
                    signal_count += 1
        if signal_count > 0:
            avg_signal = f"{total_signal / signal_count:.2f}"

    # Get current IP address of the AP's bridge interface
    current_ip = run_command(f"ip -4 addr show {BRIDGE_IFACE} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -1")
    if not current_ip:
        current_ip = "unknown" # Fallback if bridge IP isn't found

    # Publish to MQTT
    client.publish(f"ap/{AP_ID}/status", "online")
    client.publish(f"ap/{AP_ID}/connected_devices", str(connected_devices))
    client.publish(f"ap/{AP_ID}/wifi_strength", str(avg_signal))
    client.publish(f"ap/{AP_ID}/ip_address", current_ip)

# --- MQTT Client ---
client = mqtt.Client()

def on_connect(client, userdata, flags, rc):
    print(f"MQTT Connected with result code {rc}", file=sys.stderr)
    if rc == 0:
        client.subscribe(f"ap/{AP_ID}/set_config")
        client.subscribe(f"ap/{AP_ID}/reboot_command")
        report_status() # Initial report after connecting
    else:
        print(f"Failed to connect, return code {rc}", file=sys.stderr)

def on_message(client, userdata, msg):
    print(f"Received message on topic {msg.topic}", file=sys.stderr)
    try:
        if msg.topic == f"ap/{AP_ID}/set_config":
            payload = json.loads(msg.payload.decode())
            new_ssid = payload.get('ssid')
            new_password = payload.get('password')
            new_channel = payload.get('channel')
            new_band = payload.get('band') # 'g' or 'a'

            hostapd_conf_path = "/etc/hostapd/hostapd.conf"
            config_changed = False

            if new_ssid is not None:
                run_command(f"sed -i 's/^ssid=.*$/ssid={new_ssid}/' {hostapd_conf_path}")
                config_changed = True
            if new_password is not None:
                if new_password: # Set WPA2
                    run_command(f"sed -i '/^wpa_passphrase=/d' {hostapd_conf_path}") # Remove existing
                    run_command(f"echo 'wpa=2' >> {hostapd_conf_path}") # Ensure WPA2 is set
                    run_command(f"echo 'wpa_passphrase={new_password}' >> {hostapd_conf_path}")
                    run_command(f"echo 'wpa_key_mgmt=WPA-PSK' >> {hostapd_conf_path}")
                    run_command(f"echo 'wpa_pairwise=TKIP CCMP' >> {hostapd_conf_path}")
                    run_command(f"echo 'rsn_pairwise=CCMP' >> {hostapd_conf_path}")
                    # Remove open network config if it was present
                    run_command(f"sed -i '/^encryption=none/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^auth_algs=/d' {hostapd_conf_path}")
                    run_command(f"echo 'auth_algs=1' >> {hostapd_conf_path}") # Add default auth_algs
                else: # Set Open Network
                    run_command(f"sed -i '/^wpa_passphrase=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa_key_mgmt=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa_pairwise=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^rsn_pairwise=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^encryption=none/d' {hostapd_conf_path}") # Remove any existing open config
                    run_command(f"sed -i '/^auth_algs=/d' {hostapd_conf_path}")
                    run_command(f"echo 'auth_algs=1' >> {hostapd_conf_path}") # Ensure it's not present for open
                config_changed = True
            if new_channel is not None:
                run_command(f"sed -i 's/^channel=.*$/channel={new_channel}/' {hostapd_conf_path}")
                config_changed = True
            if new_band is not None:
                run_command(f"sed -i 's/^hw_mode=.*$/hw_mode={new_band}/' {hostapd_conf_path}")
                # Update 802.11n/ac settings based on band
                if new_band == 'g':
                    run_command(f"sed -i '/ieee80211ac/d' {hostapd_conf_path}")
                    if "ieee80211n=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211n=1' >> {hostapd_conf_path}")
                    if "ht_capab=" not in open(hostapd_conf_path).read():
                         run_command(f"echo 'ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]' >> {hostapd_conf_path}")
                elif new_band == 'a':
                    if "ieee80211n=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211n=1' >> {hostapd_conf_path}")
                    if "ieee80211ac=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211ac=1' >> {hostapd_conf_path}")
                    if "ht_capab=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]' >> {hostapd_conf_path}")
                    if "vht_capab=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'vht_capab=[VHT20][VHT40][VHT80]' >> {hostapd_conf_path}")
                    if "vht_oper_chwidth=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'vht_oper_chwidth=1' >> {hostapd_conf_path}")
                config_changed = True

            if config_changed:
                print("Hostapd config updated. Restarting hostapd...", file=sys.stderr)
                run_command("systemctl restart hostapd-custom.service") # Use custom service name
                print("Hostapd restarted.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "SUCCESS: Configuration applied.")
            else:
                print("No valid configuration parameters received.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "ERROR: No valid config parameters.")

        elif msg.topic == f"ap/{AP_ID}/reboot_command":
            print("Received reboot command. Initiating reboot...", file=sys.stderr)
            client.publish(f"ap/{AP_ID}/reboot_ack", "Rebooting...")
            time.sleep(1) # Give MQTT time to send ack
            run_command("reboot")

    except json.JSONDecodeError:
        print("Error: Invalid JSON payload.", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", "ERROR: Invalid JSON.")
    except Exception as e:
        print(f"An error occurred processing command: {e}", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", f"ERROR: {str(e)}")

def main():
    try:
        client.on_connect = on_connect
        client.on_message = on_message
        print(f"Connecting to MQTT broker at {MQTT_BROKER_IP}...", file=sys.stderr)
        client.connect(MQTT_BROKER_IP, MQTT_PORT, 60)
        client.loop_forever()
    except Exception as e:
        print(f"Could not connect to MQTT broker: {e}", file=sys.stderr)
        print("Ensure the MQTT broker is running and reachable from this AP. Retrying in 10s...", file=sys.stderr)
        time.sleep(10)
        sys.exit(1) # Exit to allow systemd to restart

if __name__ == "__main__":
    main()
EOF_REPORT_STATUS_SCRIPT

    # Create the command listener script
    # NO SINGLE QUOTES AROUND EOF_LISTEN_COMMANDS_SCRIPT to allow variable substitution
    cat << EOF_LISTEN_COMMANDS_SCRIPT > /usr/local/bin/listen_for_ap_commands.py
#!/usr/bin/env python3

import paho.mqtt.client as mqtt
import json
import subprocess
import time
import sys
import re
import os # Import os module to get env variable

# Retrieve AP_ID and MQTT_BROKER_IP from environment variables passed by systemd
AP_ID = os.environ.get('AP_ID', 'default_ap_id')
MQTT_BROKER_IP = os.environ.get('MQTT_BROKER_IP', '127.0.0.1')
WIFI_IFACE = os.environ.get('WIFI_IFACE', 'wlan0') # Note: WIFI_IFACE used in Python script for hostapd_cli

def run_command(cmd, log_error=True):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if log_error:
            print(f"Error executing command '{cmd}': {e.stderr.strip()}", file=sys.stderr)
        return None
    except FileNotFoundError:
        if log_error:
            print(f"Command '{cmd.split()[0]}' not found.", file=sys.stderr)
        return None

def on_connect(client, userdata, flags, rc):
    print(f"MQTT Connected with result code {rc}", file=sys.stderr)
    if rc == 0:
        client.subscribe(f"ap/{AP_ID}/set_config")
        client.subscribe(f"ap/{AP_ID}/reboot_command")
    else:
        print(f"Failed to connect, return code {rc}", file=sys.stderr)

def on_message(client, userdata, msg):
    print(f"Received message on topic {msg.topic}", file=sys.stderr)
    try:
        if msg.topic == f"ap/{AP_ID}/set_config":
            payload = json.loads(msg.payload.decode())
            new_ssid = payload.get('ssid')
            new_password = payload.get('password')
            new_channel = payload.get('channel')
            new_band = payload.get('band') # 'g' or 'a'

            hostapd_conf_path = "/etc/hostapd/hostapd.conf"
            config_changed = False

            if new_ssid is not None:
                run_command(f"sed -i 's/^ssid=.*$/ssid={new_ssid}/' {hostapd_conf_path}")
                config_changed = True
            if new_password is not None:
                if new_password: # Set WPA2
                    run_command(f"sed -i '/^wpa_passphrase=/d' {hostapd_conf_path}") # Remove existing
                    run_command(f"echo 'wpa=2' >> {hostapd_conf_path}") # Ensure WPA2 is set
                    run_command(f"echo 'wpa_passphrase={new_password}' >> {hostapd_conf_path}")
                    run_command(f"echo 'wpa_key_mgmt=WPA-PSK' >> {hostapd_conf_path}")
                    run_command(f"echo 'wpa_pairwise=TKIP CCMP' >> {hostapd_conf_path}")
                    run_command(f"echo 'rsn_pairwise=CCMP' >> {hostapd_conf_path}")
                    # Remove open network config if it was present
                    run_command(f"sed -i '/^encryption=none/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^auth_algs=/d' {hostapd_conf_path}")
                    run_command(f"echo 'auth_algs=1' >> {hostapd_conf_path}") # Add default auth_algs
                else: # Set Open Network
                    run_command(f"sed -i '/^wpa_passphrase=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa_key_mgmt=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^wpa_pairwise=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^rsn_pairwise=/d' {hostapd_conf_path}")
                    run_command(f"sed -i '/^encryption=none/d' {hostapd_conf_path}") # Remove any existing open config
                    run_command(f"sed -i '/^auth_algs=/d' {hostapd_conf_path}")
                    run_command(f"echo 'auth_algs=1' >> {hostapd_conf_path}") # Ensure it's not present for open
                config_changed = True
            if new_channel is not None:
                run_command(f"sed -i 's/^channel=.*$/channel={new_channel}/' {hostapd_conf_path}")
                config_changed = True
            if new_band is not None:
                run_command(f"sed -i 's/^hw_mode=.*$/hw_mode={new_band}/' {hostapd_conf_path}")
                # Update 802.11n/ac settings based on band
                if new_band == 'g':
                    run_command(f"sed -i '/ieee80211ac/d' {hostapd_conf_path}")
                    if "ieee80211n=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211n=1' >> {hostapd_conf_path}")
                    if "ht_capab=" not in open(hostapd_conf_path).read():
                         run_command(f"echo 'ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]' >> {hostapd_conf_path}")
                elif new_band == 'a':
                    if "ieee80211n=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211n=1' >> {hostapd_conf_path}")
                    if "ieee80211ac=1" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ieee80211ac=1' >> {hostapd_conf_path}")
                    if "ht_capab=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'ht_capab=[HT40][SHORT-GI-40][DSSS_CCK-40]' >> {hostapd_conf_path}")
                    if "vht_capab=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'vht_capab=[VHT20][VHT40][VHT80]' >> {hostapd_conf_path}")
                    if "vht_oper_chwidth=" not in open(hostapd_conf_path).read():
                        run_command(f"echo 'vht_oper_chwidth=1' >> {hostapd_conf_path}")
                config_changed = True

            if config_changed:
                print("Hostapd config updated. Restarting hostapd...", file=sys.stderr)
                run_command("systemctl restart hostapd-custom.service") # Use custom service name
                print("Hostapd restarted.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "SUCCESS: Configuration applied.")
            else:
                print("No valid configuration parameters received.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "ERROR: No valid config parameters.")

        elif msg.topic == f"ap/{AP_ID}/reboot_command":
            print("Received reboot command. Initiating reboot...", file=sys.stderr)
            client.publish(f"ap/{AP_ID}/reboot_ack", "Rebooting...")
            time.sleep(1) # Give MQTT time to send ack
            run_command("reboot")

    except json.JSONDecodeError:
        print("Error: Invalid JSON payload.", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", "ERROR: Invalid JSON.")
    except Exception as e:
        print(f"An error occurred processing command: {e}", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", f"ERROR: {str(e)}")

def main():
    try:
        client.on_connect = on_connect
        client.on_message = on_message
        print(f"Connecting to MQTT broker at {MQTT_BROKER_IP}...", file=sys.stderr)
        client.connect(MQTT_BROKER_IP, MQTT_PORT, 60)
        client.loop_forever()
    except Exception as e:
        print(f"Could not connect to MQTT broker: {e}", file=sys.stderr)
        print("Ensure the MQTT broker is running and reachable from this AP. Retrying in 10s...", file=sys.stderr)
        time.sleep(10)
        sys.exit(1) # Exit to allow systemd to restart

if __name__ == "__main__":
    main()
EOF_LISTEN_COMMANDS_SCRIPT

    # --- Use install -m 755 for robustness ---
    install -m 755 /usr/local/bin/report_ap_status.py
    install -m 755 /usr/local/bin/listen_for_ap_commands.py

    echo "Creating systemd services for MQTT scripts, hostapd, and dnsmasq (disabled for bridge mode)..."

    # Systemd service for hostapd
    # Uses single quotes on EOF_HOSTAPD_SERVICE_UNIT to prevent shell variable substitution inside the unit file content
    # This is correct as systemd unit files have their own variable expansion logic (e.g., $MAINPID)
    cat << 'EOF_HOSTAPD_SERVICE_UNIT' > /etc/systemd/system/hostapd-custom.service
[Unit]
Description=Hostapd IEEE 802.11 Access Point and Authentication Server (Custom)
After=network.target

[Service]
Type=forking
PIDFile=/run/hostapd.pid
ExecStartPre=/bin/mkdir -p /run/hostapd
ExecStartPre=/bin/chown hostapd:hostapd /run/hostapd
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid /etc/hostapd/hostapd.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF_HOSTAPD_SERVICE_UNIT

    # Systemd service for AP status reporting
    # NO SINGLE QUOTES on EOF_REPORT_SERVICE_UNIT to allow shell variable substitution (${AP_ID}, ${MQTT_BROKER_IP}, etc.)
    cat << EOF_REPORT_SERVICE_UNIT > /etc/systemd/system/ap-status-reporter.service
[Unit]
Description=AP Status Reporter (MQTT Client)
After=network.target mosquitto.service hostapd-custom.service

[Service]
Environment="AP_ID=${AP_ID}"
Environment="MQTT_BROKER_IP=${MQTT_BROKER_IP}"
Environment="WIFI_IFACE=${WIFI_IFACE}"
Environment="UPLINK_IFACE=${UPLINK_IFACE}"
Environment="BRIDGE_IFACE=${BRIDGE_IFACE}"
ExecStart=${PYTHON_VENV_AP}/bin/python /usr/local/bin/report_ap_status.py
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ap-reporter

[Install]
WantedBy=multi-user.target
EOF_REPORT_SERVICE_UNIT

    # Systemd service for AP command listener
    # NO SINGLE QUOTES on EOF_LISTEN_SERVICE_UNIT to allow shell variable substitution
    cat << EOF_LISTEN_SERVICE_UNIT > /etc/systemd/system/ap-command-listener.service
[Unit]
Description=AP Command Listener (MQTT Client)
After=network.target mosquitto.service hostapd-custom.service

[Service]
Environment="AP_ID=${AP_ID}"
Environment="MQTT_BROKER_IP=${MQTT_BROKER_IP}"
Environment="WIFI_IFACE=${WIFI_IFACE}" # Note: WIFI_IFACE used in Python script for hostapd_cli
ExecStart=${PYTHON_VENV_AP}/bin/python /usr/local/bin/listen_for_ap_commands.py
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ap-listener

[Install]
WantedBy=multi-user.target
EOF_LISTEN_SERVICE_UNIT


    systemctl daemon-reload
    # Explicitly disable dnsmasq-custom.service if it was created before
    systemctl disable dnsmasq-custom.service || true
    rm -f /etc/systemd/system/dnsmasq-custom.service # Remove the service file if it exists

    systemctl enable hostapd-custom.service ap-status-reporter.service ap-command-listener.service
    systemctl start hostapd-custom.service ap-status-reporter.service ap-command-listener.service

    echo "All services configured and started."
}

reboot_system_prompt() {
    echo ""
    echo "========================================================"
    echo " AP Installation Complete!"
    echo "========================================================"
    echo "Your Raspberry Pi AP is configured. It is HIGHLY recommended"
    echo "to reboot the system now to ensure all changes take full effect,"
    echo "especially network and bridge configurations."
    echo ""
    echo "After reboot, ensure the Pi's Ethernet port is connected to your main router."
    echo "Your new WiFi network '${AP_SSID}' should appear, and clients should get IPs from your main router."
    echo ""
    echo "To test MQTT connectivity, ensure your MQTT broker is running on ${MQTT_BROKER_IP}."
    echo "The AP should start reporting connected devices and listen for config updates."
    echo ""
    read -p "Reboot now? (y/N): " confirm_reboot
    if [[ "$confirm_reboot" =~ ^[Yy]$ ]]; then
        echo "Rebooting in 5 seconds..."
        sleep 5
        reboot
    else
        echo "Please remember to manually reboot the Raspberry Pi later."
    fi
}

# --- Main Script Execution ---
print_header
check_root

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    print_help
fi

prompt_for_settings
detect_wifi_interface

# Ensure WiFi is unblocked via rfkill
echo "Ensuring WiFi is unblocked via rfkill..."
rfkill unblock wifi
rfkill unblock all
sleep 1 # Give a moment for rfkill to apply

install_packages
configure_network
configure_iptables
configure_hostapd
disable_dnsmasq # New step: disable/remove dnsmasq as it's not needed for DHCP
create_mqtt_scripts # This will also start services via systemd
reboot_system_prompt

echo "Script finished."
