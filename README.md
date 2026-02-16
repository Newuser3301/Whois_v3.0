# 🔍  v3.1  
### WHOIS & DNS Analyzer (GUI)

🛡️ **Red Team / Pentest Reconnaissance Tool**  
Python + PyQt6 asosida yozilgan kuchli **WHOIS, DNS va attack surface analizatori**.  
Domenlar bo‘yicha **tezkor recon**, **zaif konfiguratsiyalarni aniqlash** va **hisobot yaratish** uchun mo‘ljallangan.

---

## 🚀 Xususiyatlar

✅ **WHOIS tahlili**
- Registrar, IANA ID
- Creation / Expiry / Update date
- Name Server’lar
- DNSSEC holati
- Abuse contact (email / phone)
- RAW WHOIS output (socket + fallback)

🌐 **DNS analiz**
- A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, CAA
- TTL ko‘rinishi
- Barcha record’larni bir bosishda skanerlash

⚔️ **Attack Vector Analysis**
- DNSSEC yo‘qligi
- Domain transfer protection
- SPF / DMARC / Email spoofing risklari
- Cloudflare origin IP exposure
- Open registrar risklari
- Real-world recon mindset 👀

📊 **Hisobotlar**
- JSON export
- TXT report
- Live preview
- Clipboard copy

🖥️ **GUI (PyQt6)**
- Dark red-team theme
- Multi-tab interface
- Threaded scan (UI freeze yo‘q)
- Progress bar + status feedback

---

## 🧰 Texnologiyalar

- **Python 3**
- **PyQt6**
- `python-whois`
- `dnspython`
- `socket`, `subprocess`
- `regex`, `json`

---

## 📦 O‘rnatish

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

## ▶️ Ishga tushirish

```bash
python3 whois1.py
```

🧠 Domen kiriting → **RECON START** → natijalarni tab’larda ko‘ring.

---

## 📸 Interface

- 📋 WHOIS ma’lumotlari
- 🌐 DNS records
- ⚔️ Attack vektorlar
- 📄 RAW output
- 📊 Report preview

(kerak bo‘lsa keyin screenshot qo‘shib qo‘yasan 😉)

---

## ⚠️ Ogohlantirish

> Ushbu tool **faqat ta’limiy va qonuniy pentest / security audit** maqsadlarida ishlatiladi.  
> Ruxsatsiz skanerlash — **sizning javobgarligingizda**.

---

## 🧠 Red Team Eslatma

Bu tool:
- exploit qilmaydi ❌  
- auto-hack qilmaydi ❌  
- **attack surface ko‘rsatadi** ✅  

Haqiqiy pentest — recon’dan boshlanadi 🔥

---

## 📜 Litsenziya

MIT License  
Free to use, modify, improve 🚀

---

## ✨ Muallif

👤 **Red Team / SEM AI style**  
Agar feature, improvement yoki bug topsang — PR och ✌️
