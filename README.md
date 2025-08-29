# ussdiscovery 🚀

*Because starships and network gear both deserve discovery protocols…*  

`ussdiscovery` is a Go utility that listens and probes for devices on your LAN using multiple vendor discovery mechanisms.  
It’s named after the **USS Discovery** (Star Trek) and **Ubiquiti Discovery Protocol**.

---

## ✨ Features

- 🔎 **Ubiquiti** device discovery (UDP/10001)  
- 📡 **MikroTik** discovery (UDP/5678)  
- 📞 **Grandstream** discovery (UDP/10000)  
- 🌐 **SSDP** (UPnP / multicast 239.255.255.250:1900)  
- 🔍 **WS-Discovery** (multicast 239.255.255.250:3702)  
- 🚦 Keeps a cache of “seen” devices, so only new or changed devices are printed  
- 🛠 Written in **pure Go**, no dependencies beyond the standard library  

---

## 📥 Installation

```bash
git clone https://github.com/yourname/ussdiscovery.git
cd ussdiscovery
go build -o ussdiscovery
