# Enterprise Lab Setup Guide (3-VM Distributed Topology)

This document outlines the configuration to deploy **SentinAI NetGuard** across a realistic 3-Node Network (SOC Simulation).

## 1. Network Topology

| Role | OS | IP Address (Example) | Function |
| :--- | :--- | :--- | :--- |
| **Node A (Server)** | Ubuntu Server 22.04 | `192.168.1.100` | Hosts the Application Stack (Docker) & Intelligence Engine. |
| **Node B (Analyst)** | Windows 10/11 | `192.168.1.101` | SOC Analyst Station. Accesses the Dashboard. |
| **Node C (Traffic)** | Ubuntu Client | `192.168.1.102` | Network Actor (Simulated Source). |

---

## 2. Server Deployment (Node A)

**Goal**: Host the Dockerized Application.

1.  **Transfer Code**:
    *   Copy the entire `Final project` folder to this machine (e.g., via `scp` or Git).
    *   `cd /opt/sentinai-netguard`

2.  **Install Docker & Compose**:
    ```bash
    sudo apt update
    sudo apt install -y docker.io docker-compose-plugin
    ```

3.  **Launch Stack**:
    ```bash
    sudo docker-compose up -d --build
    ```

4.  **Start Simulation**:
    *   The "Live Detection" engine runs alongside the backend. You need to trigger it inside the backend container.
    ```bash
    # Enter the backend container
    sudo docker-compose exec backend bash

    # Run the continuous monitor (detached, or in a screen/tmux session)
    python3 backend/run_live_detection.py
    ```
    *(Leave this running to generate live alerts)*

5.  **Firewall Configuration**:
    *   Ensure ports `80` (Frontend) and `8000` (API) are open.
    ```bash
    sudo ufw allow 80/tcp
    sudo ufw allow 8000/tcp
    sudo ufw reload
    ```

---

## 3. Analyst Station (Node B - Windows)

**Goal**: Monitor the Grid.

1.  **Browser Access**:
    *   Open Chrome/Edge.
    *   Navigate to: `http://192.168.1.100` (Server IP).
2.  **Verification**:
    *   Login (`admin` / `admin`).
    *   You should see the Dashboard loading.
    *   The **"Total Threats"** counter should be increasing dynamically as the simulation runs on the Server.

---

## 4. Traffic Actor (Node C - Ubuntu)

**Goal**: Verify Network Connectivity (Optional: Generate real load).

*Since the detection logic currently uses a **Synthetic Generator** inside the server, this node acts as a verification client.*

1.  **Connectivity Check**:
    ```bash
    curl -I http://192.168.1.100
    # Should return HTTP/1.1 200 OK
    ```

2.  **API Interaction (Advanced)**:
    *   You can manually query the API from this terminal.
    ```bash
    # Get recent threats
    curl http://192.168.1.100/api/threats | jq .
    ```

---

## Troubleshooting

-   **"Site Can't Be Reached"** on Windows:
    -   Ping the server: `ping 192.168.1.100`.
    -   Check Server Firewall: `sudo ufw status`.
-   **No Threats Appearing**:
    -   Did you start the `run_live_detection.py` script inside the backend container? (Step 2.4).
