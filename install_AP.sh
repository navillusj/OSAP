#!/bin/bash

# install_AP.sh
# Automated OpenWrt configuration script for a Raspberry Pi Access Point.
# Designed for an Ethernet uplink and a USB WiFi adapter for the AP.

# --- Configuration Variables ---
# These defaults will be prompted to change by the user.
AP_ID="raspberry_ap_001"
MQTT_BROKER_IP=""
DEFAULT_SSID="OpenWrt_AP"
DEFAULT_PASSWORD=""
WIFI_BAND="2g"            # 2g or 5g
WIFI_CHANNEL="auto"       # 'auto' or specific channel number (e.g., 1, 6, 11, 36, 40)
COUNTRY_CODE="AU"         # **CRITICAL for WiFi compliance (e.g., US, AU, GB, DE)**

# Global variables to store the detected WiFi interface names (set during configure_wireless)
USB_WIFI_RADIO=""    # e.g., radio0
AP_IFACE_NAME=""     # e.g., default_radio0

# --- Functions ---

print_header() {
    echo ""
    echo "========================================================"
    echo " OpenWrt Raspberry Pi AP Installer Script"
    echo "========================================================"
    echo "This script configures an OpenWrt-flashed Raspberry Pi"
    echo "as a WiFi Access Point using a USB WiFi adapter and its"
    echo "Ethernet port as the uplink."
    echo ""
}

print_help() {
    echo "Usage: $0"
    echo ""
    echo "IMPORTANT:"
    echo "  - Run this script on the OpenWrt-flashed Raspberry Pi."
    echo "  - Ensure the Pi has temporary internet access to download packages."
    echo "  - You will be prompted for key settings."
    echo ""
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        echo "Please use 'ssh root@<Your_Pi_IP>' or 'sudo -i' if already logged in."
        exit 1
    fi
}

check_internet_access() {
    echo "Checking internet access..."
    opkg update > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Could not update opkg lists. Internet access might be down."
        echo "Please ensure your Raspberry Pi has temporary internet connectivity (e.g., connect eth0 to a router with DHCP)."
        read -p "Press Enter to continue anyway (might fail if packages are needed) or Ctrl+C to exit..."
    else
        echo "Internet access confirmed (opkg update successful)."
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

    read -p "Enter the SSID (WiFi Network Name): [${DEFAULT_SSID}] " input_ssid
    DEFAULT_SSID=${input_ssid:-$DEFAULT_SSID}

    read -sp "Enter the WiFi Password (min 8 characters, leave empty for an OPEN network): " input_password
    echo ""
    DEFAULT_PASSWORD=${input_password:-$DEFAULT_PASSWORD}
    if [[ -z "$DEFAULT_PASSWORD" ]]; then
        echo "Warning: No password entered. WiFi will be OPEN (unsecured)."
        read -p "Are you sure you want an open WiFi network? (y/N): " confirm_open
        if [[ ! "$confirm_open" =~ ^[Yy]$ ]]; then
            echo "Please re-run the script and enter a password."
            exit 1
        fi
    elif [[ ${#DEFAULT_PASSWORD} -lt 8 ]]; then
        echo "Error: WiFi password must be at least 8 characters long."
        exit 1
    fi

    echo "Choose WiFi Band:"
    echo "  1) 2.4GHz (2g)"
    echo "  2) 5GHz (5g)"
    read -p "Enter choice (1 or 2): [1] " band_choice
    case $band_choice in
        2) WIFI_BAND="5g" ;;
        *) WIFI_BAND="2g" ;;
    esac
    echo "Selected WiFi Band: ${WIFI_BAND}"

    read -p "Enter WiFi Channel ('auto' for automatic, or a specific number like 1, 6, 11, 36, etc.): [${WIFI_CHANNEL}] " input_channel
    WIFI_CHANNEL=${input_channel:-$WIFI_CHANNEL}

    read -p "Enter your Country Code (e.g., US, AU, GB, DE). This is CRITICAL for legal operation: [${COUNTRY_CODE}] " input_country
    COUNTRY_CODE=${input_country:-$COUNTRY_CODE}
    if [[ ${#COUNTRY_CODE} -ne 2 ]]; then
        echo "Warning: Country code should be a 2-letter ISO code (e.g., US, AU). Incorrect code can cause issues or be illegal."
    fi

    echo ""
    echo "--- Summary of Settings ---"
    echo "AP ID: ${AP_ID}"
    echo "MQTT Broker IP: ${MQTT_BROKER_IP}"
    echo "SSID: ${DEFAULT_SSID}"
    echo "Password: ${DEFAULT_PASSWORD:+******** (set)}"
    echo "WiFi Band: ${WIFI_BAND}"
    echo "WiFi Channel: ${WIFI_CHANNEL}"
    echo "Country Code: ${COUNTRY_CODE}"
    echo ""
    read -p "Are these settings correct? (y/N): " confirm_settings
    if [[ ! "$confirm_settings" =~ ^[Yy]$ ]]; then
        echo "Exiting. Please re-run the script to set up again."
        exit 1
    fi
}

install_packages() {
    echo "Installing necessary packages..."
    opkg update
    opkg install mosquitto-client python3 python3-pip jq bc
    if [ $? -ne 0 ]; then
        echo "Error installing core packages. Please check internet connection and opkg repositories."
        exit 1
    fi
    pip install paho-mqtt
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to install paho-mqtt. Python scripts may not work."
    fi

    echo "Detecting and installing WiFi adapter drivers..."
    # Install common USB and WiFi drivers. User should verify if their specific chipset needs others.
    # List of common kmod- packages for USB WiFi chipsets:
    # kmod-mt7601u (for MediaTek MT7601U)
    # kmod-mt76x2u (for MediaTek MT7612U, MT7662U, etc. dual-band)
    # kmod-ath9k-htc (for Atheros AR9271)
    # kmod-rtl8812au, kmod-rtl8814au (various Realtek AC adapters)
    # kmod-rtl8xxxu (for older Realtek N adapters like RTL8192CU, RTL8188CUS)
    echo "Installing generic USB and common WiFi drivers. If your specific adapter doesn't work, you may need to manually install its specific 'kmod-*' package."
    opkg install kmod-usb-core kmod-usb-ohci kmod-usb-uhci kmod-usb2 kmod-usb3 || true # USB bus drivers
    opkg install kmod-mt7601u kmod-mt76x0u kmod-mt76x2u kmod-ath9k-htc kmod-rtl8812au kmod-rtl8814au kmod-rtl8192cu kmod-rtl8xxxu || true
    # The '|| true' allows the script to continue if a specific kmod isn't found/installed.

    echo "Packages installed."
}

configure_network() {
    echo "Configuring network interfaces (eth0 as DHCP uplink, disabling DHCP server)..."

    cp /etc/config/network /etc/config/network.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/config/network to /etc/config/network.bak.$(date +%Y%m%d%H%M%S)"

    # Set eth0 to DHCP client for the uplink and add to bridge
    uci set network.lan.proto='dhcp' # Change to DHCP client mode
    uci set network.lan.ipaddr='' # Clear static IP if any
    uci set network.lan.netmask=''
    uci set network.lan.gateway=''
    uci set network.lan.dns=''
    uci set network.lan.device='br-lan' # Ensure it's using the bridge
    uci add_list network.lan.device='eth0' # Add eth0 to the bridge (if not already there)

    # Ensure br-lan is defined if not already (common in RPi OpenWrt builds)
    if ! uci show network.br-lan &>/dev/null; then
        uci set network.br-lan=device
        uci set network.br-lan.type='bridge'
        uci add_list network.br-lan.ports='eth0'
    fi

    # Disable DHCP server on LAN
    cp /etc/config/dhcp /etc/config/dhcp.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/config/dhcp to /etc/config/dhcp.bak.$(date +%Y%m%d%H%M%S)"
    uci set dhcp.lan.ignore='1' # Disable DHCP server for the LAN interface

    uci commit network
    uci commit dhcp
    echo "Network configuration updated."
}

configure_wireless() {
    echo "Configuring wireless interface..."

    cp /etc/config/wireless /etc/config/wireless.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/config/wireless to /etc/config/wireless.bak.$(date +%Y%m%d%H%M%S)"

    # Identify the USB WiFi adapter
    # First, list all wifi-devices configured in UCI
    WIFI_DEVICES=$(uci show wireless | grep "wireless.@wifi-device" | awk -F'.' '{print $2}' | sed "s/'$//g")

    echo "Detecting USB WiFi adapter. This may take a moment..."
    sleep 5 # Give drivers a moment to load and devices to be recognized by UCI
    for dev in $WIFI_DEVICES; do
        DEVICE_PATH=$(uci get wireless.${dev}.path 2>/dev/null)
        # Prioritize devices explicitly identified as USB (e.g., in their path)
        if [[ "$DEVICE_PATH" == *"usb"* ]]; then
            USB_WIFI_RADIO="$dev"
            echo "Found potential USB WiFi device (USB path): ${USB_WIFI_RADIO}"
            break
        fi
    done

    # If no USB-specific path found, look for devices that are not 'platform' (onboard PCIe/SDIO)
    if [[ -z "$USB_WIFI_RADIO" ]]; then
        for dev in $WIFI_DEVICES; do
            DEVICE_PATH=$(uci get wireless.${dev}.path 2>/dev/null)
            if [[ "$DEVICE_PATH" != *"platform"* ]]; then # Assume anything not platform/PCI might be USB
                USB_WIFI_RADIO="$dev"
                echo "Found potential USB WiFi device (non-platform path): ${USB_WIFI_RADIO}"
                break
            fi
        done
    fi


    if [[ -z "$USB_WIFI_RADIO" ]]; then
        echo "Error: Could not automatically detect a suitable USB WiFi adapter."
        echo "Please identify your USB WiFi adapter's device name (e.g., 'radio0', 'radio1')"
        echo "by running 'iw dev' or checking '/etc/config/wireless' after driver installation."
        read -p "Enter WiFi device name manually (e.g., radio0): " manual_radio
        if [[ -z "$manual_radio" ]]; then
            echo "No WiFi device specified. Exiting wireless configuration."
            exit 1
        fi
        USB_WIFI_RADIO="$manual_radio"
    fi

    # Disable any existing wifi-iface configurations for the detected radio
    # This prevents conflicts with pre-existing client or AP modes
    uci show wireless | grep "wireless.${USB_WIFI_RADIO}.iface" | awk -F'.' '{print $3}' | sed "s/'$//g" | while read -r iface; do
        uci set wireless.${iface}.disabled='1'
        echo "Disabled existing wireless interface: ${iface}"
    done

    # Set up the chosen USB WiFi adapter as an Access Point
    uci set wireless.${USB_WIFI_RADIO}.disabled='0'
    uci set wireless.${USB_WIFI_RADIO}.country="${COUNTRY_CODE}"
    uci set wireless.${USB_WIFI_RADIO}.band="${WIFI_BAND}"
    uci set wireless.${USB_WIFI_RADIO}.channel="${WIFI_CHANNEL}"
    # Recommended HT modes: HT20 for 2.4GHz, VHT80 for 5GHz (if adapter supports)
    if [ "$WIFI_BAND" == "2g" ]; then
        uci set wireless.${USB_WIFI_RADIO}.htmode='HT20'
    elif [ "$WIFI_BAND" == "5g" ]; then
        uci set wireless.${USB_WIFI_RADIO}.htmode='VHT80' # Or HT20/HT40 if VHT80 not supported, check adapter specs
    fi

    # Add or modify the AP interface
    # Try to find an existing 'default_radioX' interface or create a new one
    AP_IFACE_NAME="default_${USB_WIFI_RADIO}"
    if ! uci show wireless.${AP_IFACE_NAME} &>/dev/null; then
        echo "Adding new WiFi interface: ${AP_IFACE_NAME}"
        uci add wireless wifi-iface
        uci set wireless.@wifi-iface[-1].device="${USB_WIFI_RADIO}"
        uci set wireless.@wifi-iface[-1].network='lan'
        # Retrieve the actual name assigned by UCI (e.g., @wifi-iface[0])
        AP_IFACE_NAME=$(uci show wireless | grep "wireless.@wifi-iface\[-1\].device='${USB_WIFI_RADIO}'" | head -n 1 | awk -F'.' '{print $2}' | sed "s/'$//g")
    else
        echo "Modifying existing WiFi interface: ${AP_IFACE_NAME}"
    fi

    uci set wireless.${AP_IFACE_NAME}.mode='ap'
    uci set wireless.${AP_IFACE_NAME}.ssid="${DEFAULT_SSID}"
    if [[ -n "$DEFAULT_PASSWORD" ]]; then
        uci set wireless.${AP_IFACE_NAME}.encryption='psk2' # WPA2-PSK
        uci set wireless.${AP_IFACE_NAME}.key="${DEFAULT_PASSWORD}"
    else
        uci delete wireless.${AP_IFACE_NAME}.key # Remove key if password is empty (open network)
        uci set wireless.${AP_IFACE_NAME}.encryption='none' # Set to open
    fi
    uci set wireless.${AP_IFACE_NAME}.disabled='0'

    uci commit wireless
    echo "Wireless configuration updated. Applying changes..."
    wifi reload # Reload WiFi configuration
    sleep 5 # Give it a moment to apply
    echo "Current WiFi device status:"
    iw dev

    echo ""
    echo "Attempting to restart network services... (may cause SSH disconnection)"
    /etc/init.d/network restart &
    sleep 10 # Give network time to restart
}

create_mqtt_scripts() {
    echo "Creating MQTT client scripts for reporting and command listening..."

    # Create the connected device reporter script (with signal strength and heartbeat)
    cat << EOF > /root/report_ap_status.sh
#!/bin/bash
AP_ID="${AP_ID}"
MQTT_BROKER_IP="${MQTT_BROKER_IP}"
WIFI_IFACE_NAME_IW="${USB_WIFI_RADIO}" # The 'iw' command uses the radio name (e.g., radio0) or interface name (e.g., wlan0)

# Function to get active wireless interface name (wlan0, wlan1 etc.) from the radio name
get_active_wifi_interface() {
    local radio_name="\$1"
    iw dev | awk -v radio="\$radio_name" '
        /Phy #/ {current_phy=$2}
        /Interface/ {
            iface_name=$2;
            getline; # device
            if ($2 == radio) {
                print iface_name;
                exit;
            }
        }
    '
}

report_status() {
    local active_iface=\$(get_active_wifi_interface "\${WIFI_IFACE_NAME_IW}")
    if [ -z "\$active_iface" ]; then
        echo "Warning: No active WiFi interface found for \${WIFI_IFACE_NAME_IW}. Cannot report stats."
        mosquitto_pub -h \${MQTT_BROKER_IP} -t "ap/\${AP_ID}/status" -m "offline"
        return
    fi

    CONNECTED_DEVICES=\$(iw dev "\$active_iface" station dump 2>/dev/null | grep Station | wc -l)

    # Calculate average signal strength
    TOTAL_SIGNAL=0
    COUNT_CLIENTS=0
    SIGNAL_VALUES=\$(iw dev "\$active_iface" station dump 2>/dev/null | grep "signal:" | awk '{print \$2}')
    for sig in \$SIGNAL_VALUES; do
        TOTAL_SIGNAL=\$((TOTAL_SIGNAL + sig))
        COUNT_CLIENTS=\$((COUNT_CLIENTS + 1))
    done

    AVG_SIGNAL="N/A"
    if [ \$COUNT_CLIENTS -gt 0 ]; then
        AVG_SIGNAL=\$(echo "scale=2; \$TOTAL_SIGNAL / \$COUNT_CLIENTS" | bc)
    fi

    # Report heartbeat and current status
    mosquitto_pub -h \${MQTT_BROKER_IP} -t "ap/\${AP_ID}/status" -m "online"
    mosquitto_pub -h \${MQTT_BROKER_IP} -t "ap/\${AP_ID}/connected_devices" -m "\${CONNECTED_DEVICES}"
    mosquitto_pub -h \${MQTT_BROKER_IP} -t "ap/\${AP_ID}/wifi_strength" -m "\${AVG_SIGNAL}"

    # Get current IP address of the AP's bridge interface (br-lan)
    CURRENT_IP=\$(ip -4 addr show br-lan | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [ -z "\$CURRENT_IP" ]; then
        CURRENT_IP="unknown"
    fi
    mosquitto_pub -h \${MQTT_BROKER_IP} -t "ap/\${AP_ID}/ip_address" -m "\${CURRENT_IP}"
}

report_status # Initial report
while true; do
    report_status
    sleep 30 # Report every 30 seconds
done
EOF
    chmod +x /root/report_ap_status.sh

    # Create the config update listener script (updated for channel, band, reboot)
    cat << EOF > /root/listen_for_ap_commands.py
#!/usr/bin/env python3

import paho.mqtt.client as mqtt
import json
import subprocess
import time
import sys

AP_ID = "${AP_ID}"
MQTT_BROKER_IP = "${MQTT_BROKER_IP}"
WIFI_IFACE_NAME_UCI = "${AP_IFACE_NAME}" # e.g., default_radio0 from UCI
WIFI_RADIO_NAME_UCI = "${USB_WIFI_RADIO}" # e.g., radio0 from UCI

def run_uci_command(args):
    try:
        cmd = ['uci'] + args
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"UCI command {' '.join(cmd)} output: {result.stdout.strip()}", file=sys.stderr)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running UCI command {' '.join(cmd)}: {e.stderr.strip()}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("Error: 'uci' command not found. Is OpenWrt fully set up?", file=sys.stderr)
        return None

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker.", file=sys.stderr)
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
            new_band = payload.get('band') # '2g' or '5g'

            config_updated = False

            if new_ssid is not None:
                print(f"Updating SSID to: {new_ssid}", file=sys.stderr)
                run_uci_command(['set', f'wireless.{WIFI_IFACE_NAME_UCI}.ssid={new_ssid}'])
                config_updated = True

            if new_password is not None:
                print(f"Updating Password: {'*' * len(new_password) if new_password else '(none)'}", file=sys.stderr)
                if new_password:
                    run_uci_command(['set', f'wireless.{WIFI_IFACE_NAME_UCI}.key={new_password}'])
                    run_uci_command(['set', f'wireless.{WIFI_IFACE_NAME_UCI}.encryption=psk2'])
                else:
                    run_uci_command(['delete', f'wireless.{WIFI_IFACE_NAME_UCI}.key'])
                    run_uci_command(['set', f'wireless.{WIFI_IFACE_NAME_UCI}.encryption=none'])
                config_updated = True

            if new_channel is not None:
                print(f"Updating Channel to: {new_channel}", file=sys.stderr)
                run_uci_command(['set', f'wireless.{WIFI_RADIO_NAME_UCI}.channel={new_channel}'])
                config_updated = True

            if new_band is not None:
                print(f"Updating Band to: {new_band}", file=sys.stderr)
                run_uci_command(['set', f'wireless.{WIFI_RADIO_NAME_UCI}.band={new_band}'])
                if new_band == '2g':
                    run_uci_command(['set', f'wireless.{WIFI_RADIO_NAME_UCI}.htmode=HT20'])
                elif new_band == '5g':
                    run_uci_command(['set', f'wireless.{WIFI_RADIO_NAME_UCI}.htmode=VHT80']) # or HT40
                config_updated = True

            if config_updated:
                run_uci_command(['commit', 'wireless'])
                print("Wireless configuration updated. Restarting WiFi...", file=sys.stderr)
                subprocess.run(['wifi', 'reload'], check=True) # Restart WiFi service
                print("WiFi restarted.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "SUCCESS: Configuration applied.")
            else:
                print("No valid configuration parameters received.", file=sys.stderr)
                client.publish(f"ap/{AP_ID}/config_ack", "ERROR: No valid config parameters.")

        elif msg.topic == f"ap/{AP_ID}/reboot_command":
            print("Received reboot command. Initiating reboot...", file=sys.stderr)
            client.publish(f"ap/{AP_ID}/reboot_ack", "Rebooting...")
            time.sleep(1) # Give MQTT time to send ack
            subprocess.run(['reboot'], check=True)

    except json.JSONDecodeError:
        print("Error: Invalid JSON payload.", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", "ERROR: Invalid JSON.")
    except Exception as e:
        print(f"An error occurred processing command: {e}", file=sys.stderr)
        client.publish(f"ap/{AP_ID}/config_ack", f"ERROR: {str(e)}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

print(f"Connecting to MQTT broker at {MQTT_BROKER_IP}...", file=sys.stderr)
try:
    client.connect(MQTT_BROKER_IP, 1883, 60)
    client.loop_forever()
except Exception as e:
    print(f"Could not connect to MQTT broker: {e}", file=sys.stderr)
    print("Ensure the MQTT broker is running and reachable from this AP. Retrying in 10s...", file=sys.stderr)
    time.sleep(10)
    # Attempt to restart the script, relying on init system if it's managed, or simple exit for rc.local
    sys.exit(1)
EOF
    chmod +x /root/listen_for_ap_commands.py

    echo "Setting up scripts to run on boot..."
    # Ensure only one instance of each is added to /etc/rc.local
    # This is a simple approach. For production, consider proper init.d scripts or systemd units.
    if ! grep -q "/root/report_ap_status.sh &" /etc/rc.local; then
        sed -i '/exit 0/i\/root\/report_ap_status.sh &\n\/usr\/bin\/env python3 \/root\/listen_for_ap_commands.py &\n' /etc/rc.local
        echo "Added MQTT scripts to /etc/rc.local to start on boot."
    else
        echo "MQTT scripts already in /etc/rc.local. Skipping addition."
    fi

    echo "Starting MQTT scripts now..."
    /root/report_ap_status.sh &
    /usr/bin/env python3 /root/listen_for_ap_commands.py &

    echo "MQTT client scripts created and started."
}

reboot_system_prompt() {
    echo ""
    echo "========================================================"
    echo " AP Installation Complete!"
    echo "========================================================"
    echo "Your Raspberry Pi AP is configured. It is HIGHLY recommended"
    echo "to reboot the system now to ensure all changes take effect."
    echo ""
    echo "After reboot, connect the Pi's Ethernet port to your main router."
    echo "Your new WiFi network '${DEFAULT_SSID}' should appear."
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
check_internet_access
install_packages
configure_network
configure_wireless # This function will set the global USB_WIFI_RADIO and AP_IFACE_NAME variables
create_mqtt_scripts
reboot_system_prompt

echo "Script finished."
