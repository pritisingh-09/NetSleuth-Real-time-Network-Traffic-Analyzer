

# 🕵️‍♀️ NetSleuth: Real-time Network Traffic Analyzer

**NetSleuth** is a Python-based real-time network traffic analyzer designed to inspect, capture, and visualize packet-level network data on local interfaces. Whether you're a student, cybersecurity enthusiast, or network administrator, this tool helps you monitor, debug, and understand traffic flow with ease.

---

## ⚙️ Features

- 📡 Live packet sniffing from local network interfaces  
- 🔍 Real-time display of:
  - IP addresses
  - Protocols (TCP, UDP, ICMP)
  - Packet size
  - Port numbers
- 📊 Optional logging for later analysis
- 🐍 Python-powered, simple and fast

---

## 🧰 Tech Stack

- Python 3.x  
- [Scapy](https://scapy.readthedocs.io/) – for packet sniffing  
- [socket](https://docs.python.org/3/library/socket.html) – for hostname/IP resolution  
- Terminal-based display (customizable)

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/pritisingh-09/NetSleuth-Real-time-Network-Traffic-Analyzer.git
cd NetSleuth-Real-time-Network-Traffic-Analyzer
````

### 2. Create a Virtual Environment (Optional but Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

> If `requirements.txt` doesn't exist, install manually:

```bash
pip install scapy
```

---

## ▶️ Usage

```bash
sudo python netsleuth.py
```

> ⚠️ Requires `sudo` (admin privileges) to access network interfaces.

---

## 🧪 Sample Output

```
[UDP] 192.168.1.2:5353 → 224.0.0.251:5353 | Length: 78 bytes  
[TCP] 192.168.1.5:443 → 192.168.1.20:52648 | Length: 60 bytes  
[ICMP] 192.168.1.3 → 192.168.1.1 | Echo request  
```

---

## 🛡️ License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🙋‍♀️ Author

**Priti Singh**
📫 [GitHub Profile](https://github.com/pritisingh-09)
