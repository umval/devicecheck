<img width="983" height="507" alt="image" src="https://github.com/user-attachments/assets/e60b588e-1a9a-4099-a446-e052f4f24976" />

🔍 ScanNet - Network Device Scanner

A simple Python script to scan devices on your local network using ARP.
Displays IP, MAC, and hostname if available.

---

⚙️ Requirements

- 🐍 Python 3.10+
- 📦 Libraries:
    pip install scapy colorama mac-vendor-lookup

- 🧰 Npcap (Windows only)
  → https://npcap.com/#download
  ✅ During install: check “WinPcap API-compatible Mode”

---

🚀 Usage

    python show_device.py

Scans your LAN and prints active devices like this:

IP               MAC               Name
-------------------------------------------------------------
192.168.1.1      aa:bb:cc:dd:ee:ff  livebox.home
192.168.1.42     01:23:45:67:89:ab  android.local

---

📡 Note

- Works best on local networks (192.168.x.x)
- May require admin rights depending on your system

---

👤 Made for fun & learning — #umval
