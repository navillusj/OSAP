<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AP Controller Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <script>
        // Function to fetch and update AP data
        async function fetchAPData() {
            try {
                const response = await fetch('/api/aps'); // Assuming Flask API is proxied under /api/
                const aps = await response.json();

                const apListBody = document.getElementById('ap-list-body');
                apListBody.innerHTML = ''; // Clear existing rows

                if (aps.length === 0) {
                    apListBody.innerHTML = '<tr><td colspan="8">No Access Points found. Go to Settings to add some.</td></tr>';
                    return;
                }

                aps.forEach(ap => {
                    const row = apListBody.insertRow();
                    const statusClass = ap.status === 'online' ? 'status-online' : 'status-offline';
                    const lastCheckinTime = ap.last_checkin ? new Date(ap.last_checkin * 1000).toLocaleString() : 'N/A';
                    const wifiStrength = ap.wifi_strength !== null ? `${ap.wifi_strength} dBm` : 'N/A';

                    row.innerHTML = `
                        <td>${ap.ap_id}</td>
                        <td><span class="${statusClass}"></span> ${ap.status}</td>
                        <td>${ap.ip_address || 'N/A'}</td>
                        <td>${ap.current_ssid || 'N/A'}</td>
                        <td>${ap.connected_devices || 0}</td>
                        <td>${wifiStrength}</td>
                        <td>${ap.channel || 'N/A'}</td>
                        <td>${ap.band || 'N/A'}</td>
                        <td>${lastCheckinTime}</td>
                    `;
                });
            } catch (error) {
                console.error('Error fetching AP data:', error);
                document.getElementById('ap-list-body').innerHTML = '<tr><td colspan="8" class="error-message">Error loading AP data. Is the backend running?</td></tr>';
            }
        }

        // Fetch data on page load and every 10 seconds
        document.addEventListener('DOMContentLoaded', fetchAPData);
        setInterval(fetchAPData, 10000); // Update every 10 seconds
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>AP Controller Dashboard</h1>
            <nav>
                <a href="index.php" class="active">Dashboard</a>
                <a href="settings.php">Settings</a>
            </nav>
        </header>

        <main>
            <h2>Access Point Status</h2>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>AP ID</th>
                            <th>Status</th>
                            <th>IP Address</th>
                            <th>Current SSID</th>
                            <th>Connected Devices</th>
                            <th>WiFi Strength</th>
                            <th>Channel</th>
                            <th>Band</th>
                            <th>Last Check-in</th>
                        </tr>
                    </thead>
                    <tbody id="ap-list-body">
                        <tr><td colspan="9">Loading AP data...</td></tr>
                    </tbody>
                </table>
            </div>
        </main>

        <footer>
            <p>&copy; <?php echo date("Y"); ?> Open Source AP Controller</p>
        </footer>
    </div>
</body>
</html>
