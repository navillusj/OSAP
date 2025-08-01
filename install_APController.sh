#!/bin/bash

# install_APController.sh
# Sets up the OpenWrt AP Controller on a Linux x86 server.
# Assumes Apache2 is already installed and running.

# --- Configuration Variables ---
# You MUST customize these before running the script
GITHUB_REPO_URL="https://github.com/navillusj/OSAP.git" # <--- YOUR REPO URL
GITHUB_REPO_BRANCH="main" # Or 'master' or your specific branch name

PYTHON_VENV_PATH="/opt/ap_controller_venv"
FLASK_APP_DIR="/opt/ap_controller_app"
APACHE_WEB_ROOT="/var/www/html/ap_controller_frontend" # Where your HTML/JS frontend will go
FLASK_PORT=5000 # Port for the Flask backend

# --- Functions ---

print_header() {
    echo "========================================================"
    echo " OpenWrt AP Controller Installer Script"
    echo "========================================================"
    echo "This script sets up the backend (Python Flask, SQLite) and MQTT broker."
    echo "It will also deploy your web frontend from GitHub."
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        echo "Please use 'sudo -i' or 'sudo bash $0'."
        exit 1
    fi
}

install_dependencies() {
    echo "Installing system dependencies (Mosquitto, Python3, pip, venv, git)..."
    apt update
    apt install -y mosquitto mosquitto-clients python3 python3-pip python3-venv sqlite3 git
    if [ $? -ne 0 ]; then
        echo "Error installing system dependencies. Please check your internet connection and apt repositories."
        exit 1
    fi
    echo "System dependencies installed."
}

configure_mosquitto() {
    echo "Configuring Mosquitto MQTT Broker..."

    # Backup existing mosquitto.conf
    cp /etc/mosquitto/mosquitto.conf /etc/mosquitto/mosquitto.conf.bak.$(date +%Y%m%d%H%M%S)
    echo "Backed up /etc/mosquitto/mosquitto.conf"

    # Comment out persistence_location in main mosquitto.conf to avoid duplicates
    echo "Commenting out persistence_location in main mosquitto.conf to avoid duplicates..."
    sed -i '/^persistence_location/s/^/#/' /etc/mosquitto/mosquitto.conf

    # Comment out log_dest file in main mosquitto.conf to avoid duplicates
    echo "Commenting out log_dest file in main mosquitto.conf to avoid duplicates..."
    sed -i '/^log_dest file/s/^/#/' /etc/mosquitto/mosquitto.conf

    # Minimal Mosquitto config for basic operation (NO AUTH/SSL by default for simplicity)
    # FOR PRODUCTION: STRONGLY RECOMMEND ADDING AUTHENTICATION AND SSL/TLS!
    echo "
listener 1883
allow_anonymous true # WARNING: ONLY FOR DEVELOPMENT! Secure with authentication in production!

# Persistence
persistence true
persistence_location /var/lib/mosquitto/

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_type all
" > /etc/mosquitto/conf.d/default.conf # Use conf.d for easier management

    systemctl restart mosquitto
    systemctl enable mosquitto
    echo "Mosquitto configured and restarted."
}

setup_flask_app() {
    echo "Setting up Python Flask backend application..."

    mkdir -p "$FLASK_APP_DIR"
    mkdir -p "$PYTHON_VENV_PATH"
    mkdir -p "$FLASK_APP_DIR/db" # Directory for SQLite database

    # Create Python virtual environment
    python3 -m venv "$PYTHON_VENV_PATH"
    source "$PYTHON_VENV_PATH/bin/activate"

    # Install Python packages
    pip install Flask paho-mqtt
    if [ $? -ne 0 ]; then
        echo "Error installing Python packages. Check internet connection."
        deactivate
        exit 1
    fi

    # Create a basic Flask app.py
    # This is a minimal example. You'd expand this with more complex logic.
    cat << EOF > "$FLASK_APP_DIR/app.py"
import os
from flask import Flask, request, jsonify
import paho.mqtt.client as mqtt
import json
import sqlite3
import time

app = Flask(__name__)

# --- Configuration ---
MQTT_BROKER_IP = "127.0.0.1" # Mosquitto runs on localhost
MQTT_PORT = 1883
FLASK_PORT = ${FLASK_PORT} # Define FLASK_PORT within app.py, using shell variable value
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'ap_controller.db')

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_points (
                ap_id TEXT PRIMARY KEY,
                ip_address TEXT,
                mac_address TEXT,
                last_checkin REAL, -- Use REAL for Unix timestamp floats
                status TEXT,
                location TEXT,
                current_ssid TEXT,
                current_password TEXT, -- Consider encryption for this field!
                connected_devices INTEGER DEFAULT 0,
                wifi_strength REAL,
                channel INTEGER,
                band TEXT,
                notes TEXT
            )
        ''')
        conn.commit()

# --- MQTT Client ---
mqtt_client = mqtt.Client()

def on_connect(client, userdata, flags, rc):
    print(f"MQTT Connected with result code {rc}")
    # Subscribe to all AP status topics
    client.subscribe("ap/+/status")
    client.subscribe("ap/+/connected_devices")
    client.subscribe("ap/+/wifi_strength")
    client.subscribe("ap/+/ip_address")
    client.subscribe("ap/+/config_ack")
    client.subscribe("ap/+/reboot_ack")

def on_message(client, userdata, msg):
    try:
        topic_parts = msg.topic.split('/')
        if len(topic_parts) < 3:
            print(f"Malformed topic: {msg.topic}")
            return

        ap_id = topic_parts[1]
        metric_type = topic_parts[2]
        payload = msg.payload.decode('utf-8')
        # print(f"Received from {ap_id} ({metric_type}): {payload}") # Uncomment for verbose logging

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            # Ensure AP exists in DB or add it
            cursor.execute("INSERT OR IGNORE INTO access_points (ap_id, status, last_checkin) VALUES (?, ?, ?)",
                           (ap_id, 'online', time.time()))

            update_fields = {}
            if metric_type == "status":
                update_fields['status'] = payload
                update_fields['last_checkin'] = time.time()
            elif metric_type == "connected_devices":
                update_fields['connected_devices'] = int(payload)
            elif metric_type == "wifi_strength":
                try:
                    update_fields['wifi_strength'] = float(payload)
                except ValueError:
                    update_fields['wifi_strength'] = None # Store as NULL if invalid
            elif metric_type == "ip_address":
                update_fields['ip_address'] = payload
            elif metric_type == "config_ack":
                print(f"AP {ap_id} config ACK: {payload}")
                # Future: Update a 'last_config_ack' field or status in DB
            elif metric_type == "reboot_ack":
                print(f"AP {ap_id} reboot ACK: {payload}")
                # Future: Update a 'last_reboot_ack' field or status in DB

            if update_fields:
                set_clause = ", ".join([f"{k} = ?" for k in update_fields.keys()])
                values = list(update_fields.values())
                values.append(ap_id)
                cursor.execute(f"UPDATE access_points SET {set_clause} WHERE ap_id = ?", values)
            conn.commit()

    except Exception as e:
        print(f"Error processing MQTT message: {e}")

mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect(MQTT_BROKER_IP, MQTT_PORT, 60)
mqtt_client.loop_start() # Start non-blocking loop in background

# --- Flask Routes ---
@app.route('/')
def index():
    # This route is mainly for internal testing of Flask. Apache will handle the actual /
    return "AP Controller Backend is running. Access frontend via Apache at the server's IP."

@app.route('/api/aps', methods=['GET', 'POST'])
def manage_aps():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row # Return rows as dictionaries
        cursor = conn.cursor()
        if request.method == 'POST':
            data = request.json
            ap_id = data.get('ap_id')
            location = data.get('location', '')
            notes = data.get('notes', '')
            if not ap_id:
                return jsonify({"error": "AP ID is required"}), 400
            try:
                cursor.execute("INSERT INTO access_points (ap_id, location, notes, status) VALUES (?, ?, ?, ?)",
                               (ap_id, location, notes, 'offline'))
                conn.commit()
                return jsonify({"message": f"AP {ap_id} added successfully"}), 201
            except sqlite3.IntegrityError:
                return jsonify({"error": f"AP with ID {ap_id} already exists"}), 409
        else: # GET
            cursor.execute("SELECT ap_id, ip_address, last_checkin, status, location, current_ssid, connected_devices, wifi_strength, channel, band FROM access_points")
            aps = [dict(row) for row in cursor.fetchall()]
            return jsonify(aps)

@app.route('/api/aps/<ap_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_single_ap(ap_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if request.method == 'GET':
            cursor.execute("SELECT * FROM access_points WHERE ap_id = ?", (ap_id,))
            ap = cursor.fetchone()
            if ap:
                return jsonify(dict(ap))
            return jsonify({"error": "AP not found"}), 404
        elif request.method == 'PUT':
            data = request.json
            update_fields = {}
            if 'location' in data: update_fields['location'] = data['location']
            if 'notes' in data: update_fields['notes'] = data['notes']
            # Only allow certain fields to be updated directly here, config is via MQTT
            if not update_fields:
                return jsonify({"error": "No valid fields to update"}), 400

            set_clause = ", ".join([f"{k} = ?" for k in update_fields.keys()])
            values = list(update_fields.values())
            values.append(ap_id)
            cursor.execute(f"UPDATE access_points SET {set_clause} WHERE ap_id = ?", values)
            conn.commit()
            return jsonify({"message": f"AP {ap_id} updated"}), 200
        elif request.method == 'DELETE':
            cursor.execute("DELETE FROM access_points WHERE ap_id = ?", (ap_id,))
            conn.commit()
            return jsonify({"message": f"AP {ap_id} deleted"}), 200

@app.route('/api/aps/<ap_id>/config', methods=['POST'])
def send_ap_config(ap_id):
    data = request.json
    ssid = data.get('ssid')
    password = data.get('password')
    channel = data.get('channel')
    band = data.get('band')

    if ssid is None and password is None and channel is None and band is None:
        return jsonify({"error": "No configuration parameters provided"}), 400

    config_payload = {}
    if ssid is not None: config_payload['ssid'] = ssid
    if password is not None: config_payload['password'] = password
    if channel is not None: config_payload['channel'] = channel
    if band is not None: config_payload['band'] = band

    mqtt_client.publish(f"ap/{ap_id}/set_config", json.dumps(config_payload))

    # Update current_ssid/password/channel/band in DB, assuming success
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        update_query = "UPDATE access_points SET "
        update_values = []
        if ssid is not None:
            update_query += "current_ssid = ?, "
            update_values.append(ssid)
        if password is not None:
            update_query += "current_password = ?, "
            update_values.append(password)
        if channel is not None:
            update_query += "channel = ?, "
            update_values.append(channel)
        if band is not None:
            update_query += "band = ?, "
            update_values.append(band)

        if update_values:
            update_query = update_query.rstrip(', ') + " WHERE ap_id = ?"
            update_values.append(ap_id)
            cursor.execute(update_query, tuple(update_values))
            conn.commit()

    return jsonify({"message": f"Configuration command sent to {ap_id}", "payload": config_payload}), 200

@app.route('/api/aps/bulk_config', methods=['POST'])
def bulk_config_aps():
    data = request.json
    ap_ids = data.get('ap_ids', [])
    ssid = data.get('ssid')
    password = data.get('password')
    channel = data.get('channel')
    band = data.get('band')

    if not ap_ids:
        return jsonify({"error": "No AP IDs provided for bulk update"}), 400
    if ssid is None and password is None and channel is None and band is None:
        return jsonify({"error": "No configuration parameters provided for bulk update"}), 400

    config_payload = {}
    if ssid is not None: config_payload['ssid'] = ssid
    if password is not None: config_payload['password'] = password
    if channel is not None: config_payload['channel'] = channel
    if band is not None: config_payload['band'] = band

    results = []
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        for ap_id in ap_ids:
            mqtt_client.publish(f"ap/{ap_id}/set_config", json.dumps(config_payload))
            # Update current_ssid/password/channel/band in DB, assuming success
            update_query = "UPDATE access_points SET "
            update_values = []
            if ssid is not None:
                update_query += "current_ssid = ?, "
                update_values.append(ssid)
            if password is not None:
                update_query += "current_password = ?, "
                update_values.append(password)
            if channel is not None:
                update_query += "channel = ?, "
                update_values.append(channel)
            if band is not None:
                update_query += "band = ?, "
                update_values.append(band)

            if update_values:
                update_query = update_query.rstrip(', ') + " WHERE ap_id = ?"
                update_values.append(ap_id)
                cursor.execute(update_query, tuple(update_values))
                conn.commit()
            results.append({"ap_id": ap_id, "status": "command sent"})
    return jsonify({"message": "Bulk configuration command sent", "results": results}), 200

@app.route('/api/aps/<ap_id>/reboot', methods=['POST'])
def reboot_ap(ap_id):
    mqtt_client.publish(f"ap/{ap_id}/reboot_command", "reboot")
    return jsonify({"message": f"Reboot command sent to {ap_id}"}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=FLASK_PORT, debug=True) # Run Flask directly for dev
EOF

    # Create a simple WSGI file for Apache
    cat << EOF > "$FLASK_APP_DIR/wsgi.py"
import sys
import os

# Add the application directory to the path
sys.path.insert(0, '$FLASK_APP_DIR')

from app import app as application
EOF

    # Initialize the database (creates the .db file and table)
    source "$PYTHON_VENV_PATH/bin/activate"
    # Change directory to Flask app directory before running Python command
    (cd "$FLASK_APP_DIR" && python -c "from app import init_db; init_db()")
    deactivate

    echo "Flask application setup complete."
}

deploy_frontend_files() {
    echo "Deploying frontend files from GitHub..."
    local TEMP_CLONE_DIR="/tmp/osap_clone_$(date +%s)"

    # Create frontend directory if it doesn't exist
    mkdir -p "$APACHE_WEB_ROOT"

    echo "Cloning repository: $GITHUB_REPO_URL branch: $GITHUB_REPO_BRANCH into $TEMP_CLONE_DIR"
    git clone --depth 1 --branch "$GITHUB_REPO_BRANCH" "$GITHUB_REPO_URL" "$TEMP_CLONE_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to clone the GitHub repository. Check URL, branch, and network connectivity."
        exit 1
    fi

    echo "Copying frontend files from $TEMP_CLONE_DIR/web/ to $APACHE_WEB_ROOT"
    if [ ! -d "$TEMP_CLONE_DIR/web" ]; then
        echo "Error: 'web/' directory not found in the cloned repository."
        echo "Please ensure your GitHub repo structure matches: OSAP/web/index.php, etc."
        rm -rf "$TEMP_CLONE_DIR"
        exit 1
    fi

    # Fix: Closing brace for this if statement was missing
    # Corrected below by ensuring the `if` is properly closed before the next line
    cp -r "$TEMP_CLONE_DIR/web/." "$APACHE_WEB_ROOT/"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to copy frontend files."
        rm -rf "$TEMP_CLONE_DIR"
        exit 1
    fi # <--- This `fi` was missing causing the syntax error on the next `}`
    # This `fi` closes the `if [ $? -ne 0 ]` block

    echo "Cleaning up temporary clone directory..."
    rm -rf "$TEMP_CLONE_DIR"
    echo "Frontend files deployed."
}

configure_apache() {
    echo "Configuring Apache2 for the controller frontend and backend proxy..."

    # Ensure Apache is configured to parse PHP files
    if ! dpkg -l | grep -q "libapache2-mod-php"; then
        echo "Installing libapache2-mod-php..."
        apt install -y libapache2-mod-php php-cli
    fi
    a2enmod php* || true # Enable PHP module (might be php7.x, php8.x)

    # Enable required Apache modules for proxying
    a2enmod proxy proxy_http
    if [ $? -ne 0 ]; then
        echo "Error enabling Apache proxy modules. Check Apache2 installation."
        exit 1
    fi

    # Create Apache VirtualHost config
    APACHE_CONF_FILE="/etc/apache2/sites-available/ap_controller.conf"
    APACHE_CONF_LINK="/etc/apache2/sites-enabled/ap_controller.conf"

    # Backup existing virtual host config if it exists
    if [ -f "$APACHE_CONF_FILE" ]; then
        cp "$APACHE_CONF_FILE" "$APACHE_CONF_FILE.bak.$(date +%Y%m%d%H%M%S)"
        echo "Backed up existing Apache config."
    fi

    cat << EOF > "$APACHE_CONF_FILE"
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $APACHE_WEB_ROOT

    ErrorLog \${APACHE_LOG_DIR}/ap_controller_error.log
    CustomLog \${APACHE_LOG_DIR}/ap_controller_access.log combined

    # Serve static frontend files (PHP, HTML, CSS, JS)
    <Directory $APACHE_WEB_ROOT>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # Proxy API requests to the Flask backend
    ProxyPass /api/ http://127.0.0.1:$FLASK_PORT/api/
    ProxyPassReverse /api/ http://127.0.0.1:$FLASK_PORT/api/

    # For PHP files, ensure handler is set
    <FilesMatch \.php$>
        SetHandler application/x-httpd-php
    </FilesMatch>

    # Optional: If you want to use mod_wsgi for Flask (more robust for production)
    # This requires libapache2-mod-wsgi-py3 to be installed.
    # WSGIScriptAlias /api $FLASK_APP_DIR/wsgi.py
    # <Directory $FLASK_APP_DIR>
    #     WSGIMode process-group
    #     WSGIProcessGroup ap_controller_app
    #     WSGIApplicationGroup %{GLOBAL}
    #     Require all granted
    # </Directory>
</VirtualHost>
EOF

    # Enable the new site
    a2ensite ap_controller.conf
    if [ $? -ne 0 ]; then
        echo "Error enabling Apache site. Check config file for syntax errors."
        exit 1
    fi

    # Restart Apache
    systemctl restart apache2
    echo "Apache2 configured and restarted."
}

ensure_www_data_user() {
    echo "Ensuring www-data user and group exist for Flask backend..."
    if ! id -g www-data >/dev/null 2>&1; then
        echo "Creating www-data group..."
        addgroup --system www-data
    fi
    if ! id -u www-data >/dev/null 2>&1; then
        echo "Creating www-data user..."
        adduser --system --no-create-home --ingroup www-data --disabled-password --shell /usr/sbin/nologin www-data
    fi
    echo "www-data user and group ensured."
}

create_systemd_service() {
    echo "Creating systemd service for Flask backend..."

    cat << EOF > /etc/systemd/system/ap_controller_backend.service
[Unit]
Description=AP Controller Flask Backend
After=network.target mosquitto.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=$FLASK_APP_DIR
ExecStart=$PYTHON_VENV_PATH/bin/python $FLASK_APP_DIR/app.py
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ap-controller-backend

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ap_controller_backend.service
    systemctl start ap_controller_backend.service
    echo "Flask backend systemd service created and started."
}

# --- Main Script Execution ---
print_header
check_root
install_dependencies
configure_mosquitto
setup_flask_app
deploy_frontend_files
configure_apache
ensure_www_data_user # <--- This function ensures www-data exists
create_systemd_service

echo "========================================================"
echo "AP Controller Installation Complete!"
echo "========================================================"
echo "Next steps:"
echo "1. Access your controller via web browser at your server's IP address."
echo "2. Remember to secure your Mosquitto broker (authentication, SSL/TLS) for production!"
echo "   Refer to Mosquitto documentation for details: https://mosquitto.org/documentation/"
echo "3. Consider using 'mod_wsgi' for a more robust Flask deployment with Apache2."
echo ""
