<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AP Controller Settings</title>
    <link rel="stylesheet" href="style.css">
    <script>
        // Function to fetch existing APs for the update form
        async function loadExistingAPs() {
            try {
                const response = await fetch('/api/aps');
                const aps = await response.json();

                const selectAP = document.getElementById('ap_id_select');
                const bulkAPsSelect = document.getElementById('bulk_ap_ids');

                selectAP.innerHTML = '<option value="">-- Select AP --</option>';
                bulkAPsSelect.innerHTML = ''; // Clear for bulk select

                aps.forEach(ap => {
                    const option = document.createElement('option');
                    option.value = ap.ap_id;
                    option.textContent = `${ap.ap_id} (${ap.location || 'N/A'}) - ${ap.current_ssid || 'N/A'}`;
                    selectAP.appendChild(option);

                    // Add to bulk select
                    const bulkOption = document.createElement('option');
                    bulkOption.value = ap.ap_id;
                    bulkOption.textContent = ap.ap_id;
                    bulkAPsSelect.appendChild(bulkOption);
                });
            } catch (error) {
                console.error('Error loading APs:', error);
            }
        }

        // Function to populate config form when an AP is selected
        async function populateAPConfig() {
            const apId = document.getElementById('ap_id_select').value;
            if (!apId) {
                document.getElementById('update-ap-form').reset();
                return;
            }
            try {
                const response = await fetch(`/api/aps/${apId}`);
                const ap = await response.json();

                if (ap) {
                    document.getElementById('update_ssid').value = ap.current_ssid || '';
                    document.getElementById('update_channel').value = ap.channel || 'auto';
                    document.getElementById('update_band').value = ap.band || '2g';
                    // Do NOT pre-fill password for security reasons
                    document.getElementById('update_password').value = '';
                }
            } catch (error) {
                console.error('Error fetching AP config:', error);
            }
        }

        // Function to handle API requests
        async function sendAPIRequest(url, method, data) {
            const response = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });
            return response.json();
        }

        // Handle Add AP form submission
        async function handleAddAP(event) {
            event.preventDefault();
            const ap_id = document.getElementById('add_ap_id').value;
            const location = document.getElementById('add_location').value;
            const notes = document.getElementById('add_notes').value;

            const result = await sendAPIRequest('/api/aps', 'POST', { ap_id, location, notes });
            alert(result.message || result.error);
            if (!result.error) {
                document.getElementById('add-ap-form').reset();
                loadExistingAPs(); // Reload AP list
            }
        }

        // Handle Update AP config form submission
        async function handleUpdateAPConfig(event) {
            event.preventDefault();
            const ap_id = document.getElementById('ap_id_select').value;
            if (!ap_id) {
                alert('Please select an Access Point to update.');
                return;
            }

            const ssid = document.getElementById('update_ssid').value;
            const password = document.getElementById('update_password').value;
            const channel = document.getElementById('update_channel').value;
            const band = document.getElementById('update_band').value;

            // Only send non-empty fields to avoid overwriting with empty strings
            const configPayload = {};
            if (ssid !== '') configPayload.ssid = ssid;
            if (password !== '') configPayload.password = password; // Send empty string for password to clear it
            if (channel !== '') configPayload.channel = channel;
            if (band !== '') configPayload.band = band;


            const result = await sendAPIRequest(`/api/aps/${ap_id}/config`, 'POST', configPayload);
            alert(result.message || result.error);
            if (!result.error) {
                // You might want to reload current AP data or clear the password field
                document.getElementById('update_password').value = ''; // Clear password field for security
                loadExistingAPs(); // Refresh options if SSID changed
            }
        }

        // Handle Bulk Change form submission
        async function handleBulkChange(event) {
            event.preventDefault();
            const selectedOptions = Array.from(document.getElementById('bulk_ap_ids').selectedOptions);
            const ap_ids = selectedOptions.map(option => option.value);

            if (ap_ids.length === 0) {
                alert('Please select at least one Access Point for bulk update.');
                return;
            }

            const bulk_ssid = document.getElementById('bulk_ssid').value;
            const bulk_password = document.getElementById('bulk_password').value;
            const bulk_channel = document.getElementById('bulk_channel').value;
            const bulk_band = document.getElementById('bulk_band').value;

            const bulkPayload = {};
            if (bulk_ssid !== '') bulkPayload.ssid = bulk_ssid;
            if (bulk_password !== '') bulkPayload.password = bulk_password; // Send empty string for password to clear it
            if (bulk_channel !== '') bulkPayload.channel = bulk_channel;
            if (bulk_band !== '') bulkPayload.band = bulk_band;

            if (Object.keys(bulkPayload).length === 0) {
                alert('Please enter at least one field (SSID, Password, Channel, or Band) for bulk update.');
                return;
            }

            const result = await sendAPIRequest('/api/aps/bulk_config', 'POST', { ap_ids, ...bulkPayload });
            alert(result.message || result.error);
            if (!result.error) {
                document.getElementById('bulk-change-form').reset();
            }
        }

        // Handle Reboot AP command
        async function handleRebootAP(event) {
            event.preventDefault();
            const ap_id = document.getElementById('ap_id_select').value;
            if (!ap_id) {
                alert('Please select an Access Point to reboot.');
                return;
            }

            if (confirm(`Are you sure you want to reboot AP: ${ap_id}?`)) {
                const result = await sendAPIRequest(`/api/aps/${ap_id}/reboot`, 'POST', {});
                alert(result.message || result.error);
            }
        }


        // Event listeners
        document.addEventListener('DOMContentLoaded', () => {
            loadExistingAPs();
            document.getElementById('add-ap-form').addEventListener('submit', handleAddAP);
            document.getElementById('ap_id_select').addEventListener('change', populateAPConfig);
            document.getElementById('update-ap-form').addEventListener('submit', handleUpdateAPConfig);
            document.getElementById('bulk-change-form').addEventListener('submit', handleBulkChange);
            document.getElementById('reboot_ap_button').addEventListener('click', handleRebootAP);
        });
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>AP Controller Settings</h1>
            <nav>
                <a href="index.php">Dashboard</a>
                <a href="settings.php" class="active">Settings</a>
            </nav>
        </header>

        <main>
            <section class="card">
                <h2>Add New Access Point</h2>
                <form id="add-ap-form">
                    <div class="form-group">
                        <label for="add_ap_id">AP ID (Unique Identifier):</label>
                        <input type="text" id="add_ap_id" name="ap_id" required>
                    </div>
                    <div class="form-group">
                        <label for="add_location">Location (e.g., Living Room):</label>
                        <input type="text" id="add_location" name="location">
                    </div>
                    <div class="form-group">
                        <label for="add_notes">Notes:</label>
                        <textarea id="add_notes" name="notes" rows="3"></textarea>
                    </div>
                    <button type="submit">Add AP</button>
                </form>
            </section>

            <section class="card">
                <h2>Update Individual Access Point Configuration</h2>
                <form id="update-ap-form">
                    <div class="form-group">
                        <label for="ap_id_select">Select AP:</label>
                        <select id="ap_id_select" name="ap_id_select" required>
                            <option value="">-- Select AP --</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="update_ssid">New SSID:</label>
                        <input type="text" id="update_ssid" name="ssid">
                    </div>
                    <div class="form-group">
                        <label for="update_password">New Password (leave empty to keep current, type for open network):</label>
                        <input type="password" id="update_password" name="password">
                    </div>
                    <div class="form-group">
                        <label for="update_channel">Channel:</label>
                        <input type="text" id="update_channel" name="channel" placeholder="auto or specific number">
                    </div>
                    <div class="form-group">
                        <label for="update_band">Band:</label>
                        <select id="update_band" name="band">
                            <option value="2g">2.4GHz</option>
                            <option value="5g">5GHz</option>
                        </select>
                    </div>
                    <button type="submit">Update AP Config</button>
                    <button type="button" id="reboot_ap_button" class="button-danger">Reboot AP</button>
                </form>
            </section>

            <section class="card">
                <h2>Bulk Configuration Changes</h2>
                <form id="bulk-change-form">
                    <div class="form-group">
                        <label for="bulk_ap_ids">Select APs (Ctrl/Cmd + Click to select multiple):</label>
                        <select id="bulk_ap_ids" name="bulk_ap_ids[]" multiple size="5" required>
                            </select>
                    </div>
                    <div class="form-group">
                        <label for="bulk_ssid">New SSID (leave empty to not change):</label>
                        <input type="text" id="bulk_ssid" name="bulk_ssid">
                    </div>
                    <div class="form-group">
                        <label for="bulk_password">New Password (leave empty to not change, type for open network):</label>
                        <input type="password" id="bulk_password" name="bulk_password">
                    </div>
                     <div class="form-group">
                        <label for="bulk_channel">New Channel (leave empty to not change):</label>
                        <input type="text" id="bulk_channel" name="bulk_channel" placeholder="auto or specific number">
                    </div>
                    <div class="form-group">
                        <label for="bulk_band">New Band (leave empty to not change):</label>
                        <select id="bulk_band" name="bulk_band">
                            <option value="">-- No Change --</option>
                            <option value="2g">2.4GHz</option>
                            <option value="5g">5GHz</option>
                        </select>
                    </div>
                    <button type="submit">Apply Bulk Changes</button>
                </form>
            </section>
        </main>

        <footer>
            <p>&copy; <?php echo date("Y"); ?> Open Source AP Controller</p>
        </footer>
    </div>
</body>
</html>
