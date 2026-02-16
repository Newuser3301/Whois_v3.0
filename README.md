# 🔍 v3.1
### WHOIS & DNS Analyzer (GUI)

🛡️ **Red Team / Pentest Reconnaissance Tool**
A powerful **WHOIS, DNS and attack surface analyzer** written in Python + PyQt6.
Designed for **quick recon**, **detection of weak configurations** and **report generation** across domains.

---

## 🚀 Features

✅ **WHOIS Analysis**
- Registrar, IANA ID
- Creation / Expiry / Update date
- Name Servers
- DNSSEC status
- Abuse contact (email / phone)
- RAW WHOIS output (socket + fallback)

🌐 **DNS Analysis**
- A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, CAA
- TTL view
- Scan all records in one click

⚔️ **Attack Vector Analysis**
- Lack of DNSSEC
- Domain transfer protection
- SPF / DMARC / Email spoofing risks
- Cloudflare origin IP exposure
- Open registry risks
- Real-world recon mindset 👀

📊 **Reports**
- JSON export
- TXT report
- Live preview
- Clipboard copy

🖥️ **GUI (PyQt6)**
- Dark red-team theme
- Multi-tab interface
- Threaded scan (no UI freeze)
- Progress bar + status feedback

---

## 🧰 Technologies

- **Python 3**
- **PyQt6**
- `python-whois`
- `dnspython`
- `socket`, `subprocess`
- `regex`, `json`

---

## 📦 Installation

```bash
git clone https://github.com/USERNAME/pentest-recon.git
cd pentest-recon
pip install -r requirements.txt
```

### `requirements.txt`

```txt
python-whois
dnspython
PyQt6
```

---

## ▶️ Launch

```bash
python3 whois1.py
```

🧠 Enter domain → **RECON START** → see results in tabs.

---

## 📸 Interface

- 📋 WHOIS information
- 🌐 DNS records
- ⚔️ Attack vectors
- 📄 RAW output
- 📊 Report preview

(if necessary, you can add a screenshot later 😉)

---

## ⚠️ Warning

> This tool is for **educational and legal pentest / security audit** purposes only.
> Unauthorized scanning — **at your own risk**.

---

## 🧠 Red Team Note

This tool:
- does not exploit ❌
- does not auto-hack ❌
- **shows attack surface** ✅

Real pentest — starts with recon 🔥

---

## 📜 License

MIT License
Free to use, modify, improve 🚀

---

##

If you find a feature, improvement or bug — open a PR ✌️
