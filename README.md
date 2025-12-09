# 🕵️‍♂️ WEBWHISPER

Advanced Domain Discovery Engine with automated deduplication, CT-log intelligence, clean UI, auto-saving, and instant export support.

Designed for security researchers, OSINT analysts, and bug bounty hunters who need continuous unique domain discovery without noise or repetition.

## 📸 Overview

WebWhisper is a CT-log-powered domain discovery tool that fetches real, freshly-issued domains from Certificate Transparency logs (crt.sh).
It guarantees zero duplicates, automatic saving, and a simple, efficient localhost dashboard.

### Key Highlights:

- ⚡ Fast real-time domain discovery (Certificate Transparency based)
- 🧠 Built-in deduplication with SQLite persistence
- 📝 Auto-saves each scan to clean .txt files
- 🌐 Beautiful local web UI (Flask)
- 🧪 Offline sampling mode from stored DB
- 📤 Exports complete DB to .txt with one click
- 🎯 Perfect for reconnaissance, OSINT, and automation workflows

## ✨ Features

- ✅ Fetch real domains from Certificate Transparency logs
- 🔁 Never repeats a domain (SHA-256 deduplication)
- 📂 Auto-save every scan to timestamped .txt files
- 🖥️ Modern, clean Flask-based web interface
- 📡 Multi-TLD scanning with custom limits
- 🧰 Offline mode — sample DB without network
- 📦 Export complete database to TXT
- 🧼 Clean domain normalization (wildcard removal, lowercasing)
- 🎚 Configurable max-fetch limits
- 📊 Live results viewer
- 🎛 Easy to extend for automation

## 🧱 Requirements

- 🐍 Python 3.8+
- 🌐 Internet connection (for CT log fetching)
- 📦 Dependencies from requirements.txt

### dependencies:

```
flask==3.0.2
requests==2.31.0
```

## 📦 Installation

### 1️⃣ Download the script

- `webwhisper_app.py`
- `requirements.txt`

Put both into the same folder.

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Start the tool:

```bash
python webwhisper_app.py
```

### Open the dashboard:

```
http://127.0.0.1:5000
```

## 🧠 How It Works

### 1️⃣ Certificate Transparency Fetching

WebWhisper queries crt.sh:

```
https://crt.sh/?q=%.com&output=json
```

It receives freshly registered or recently renewed domains, not outdated lists.

### 2️⃣ Cleaning & Normalization

WebWhisper processes each result:

- Removes wildcards (`*.example.com` → `example.com`)
- Converts to lowercase
- Ensures domain is valid
- Removes duplicates in-memory

### 3️⃣ Deduplication (Guaranteed)

Each domain is fingerprinted using:

```
SHA-256(domain)
```

Stored inside:

```
webwhisper_domains.db
```

Before returning a domain:

```
if fingerprint in DB → skip
else → save + return
```

This guarantees:

- 🟢 No duplicates ever
- 🟢 Persistence across sessions
- 🟢 Perfect continuity in long-term reconnaissance

### 4️⃣ Auto-Saving

Every scan automatically produces:

```
scan_YYYYMMDD_HHMMSS.txt
```

Saved in the same directory as the script.

### 5️⃣ User Interface (Flask Dashboard)

The UI supports:

- Run full scan
- View results live
- Download results
- Sample DB
- Export entire DB
- Zero configuration startup

## ⚙️ Command-Line / UI Controls

Available from the UI:

| Control | Description |
|---------|-------------|
| Count | How many unique domains to return |
| TLDs | com,net,org etc. |
| Max per TLD | Controls CT-log fetch size |
| Sample DB | Pull random old results offline |
| Export DB | Save all domains to .txt |
| Download results | Save current scan |

## 📂 File Output

**Scan results:**
- `scan_20250210_154200.txt`
- `scan_20250210_154918.txt`

**Database export:**
- `webwhisper_db.txt`

**Individual result download:**
- `scan_results.txt`

## ⚖️ Legal & Ethical Use

⚠️ **IMPORTANT:**
WebWhisper is designed for OSINT, research, and allowed reconnaissance ONLY.

You must follow:

- Local laws and regulations
- Target's policies
- Bug bounty program rules
- Ethical usage practices

Misuse is strictly discouraged.

## 🤝 Contributing

Contributions are welcome — improvements, UI upgrades, features, and optimizations.
Submit pull requests or open GitHub issues.

## 🚨 Support

For help or suggestions, open an issue or contact the project owner.

## ⚖️ License

MIT License © 2025 Vipin Giri

Use responsibly.

## 📌 Version

WebWhisper v1.0.0
