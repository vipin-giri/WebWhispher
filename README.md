# WEBWHISPER

Advanced Domain Discovery Engine with live verification, automated deduplication, CT-log intelligence, colorful CLI, auto-saving, and real-time status checking.

Designed for security researchers, OSINT analysts, and bug bounty hunters who need continuous unique domain discovery with live HTTP 200 verification.

## Overview

WebWhisper is a CT-log-powered domain discovery tool that fetches real, freshly-issued domains from Certificate Transparency logs (crt.sh) and verifies they're live with HTTP 200 responses.
It guarantees zero duplicates, automatic saving, and instant live domain verification.

### Key Highlights:

- Fast real-time domain discovery (Certificate Transparency based)
- Live domain verification (HTTP 200 status checking)
- Built-in deduplication with SQLite persistence
- Auto-saves each scan to timestamped .txt files
- Beautiful colorized terminal output
- 30+ default TLDs for comprehensive coverage
- Offline sampling mode from stored DB
- Multi-threaded live checking (20 concurrent threads)
- Perfect for reconnaissance, OSINT, and bug bounty hunting

##  Features

- Fetch real domains from Certificate Transparency logs
- Verify domains are live with HTTP 200 status
- Never repeats a domain (SHA-256 deduplication)
- Auto-save every scan to timestamped .txt files (YYYYMMDD_HHMMSS_domains.txt)
- Clean, colorized terminal interface with progress indicators
- Multi-TLD scanning (30+ TLDs by default)
- Offline mode — sample DB without network
- Clean domain normalization (wildcard removal, lowercasing)
- Fast concurrent checking (20 parallel connections)
- Configurable max-fetch limits
- Real-time progress display with ✓/✗ indicators
- Easy to extend for automation

##  Requirements

-  Python 3.8+
-  Internet connection (for CT log fetching and live verification)
-  Dependencies from requirements.txt

### Dependencies:

```
requests==2.31.0
urllib3==2.1.0
```

##  Installation

###  Download the script

- `scanner.py`
- `requirements.txt`

Put both into the same folder.

###  Install dependencies

```bash
pip install -r requirements.txt
```

###  Make executable (optional)

```bash
chmod +x scanner.py
```

##  Usage

### Basic usage (25 live domains with all default TLDs):

```bash
python scanner.py
```

### Get specific number of live domains:

```bash
python scanner.py --count 100
```

### Get 1000 live domains:

```bash
python scanner.py --count 1000
```

### Use specific TLDs only:

```bash
python scanner.py --count 500 --tlds com,net,org
```

### Skip live verification (faster, may return offline domains):

```bash
python scanner.py --count 1000 --no-verify
```

### Use cached domains only (offline mode):

```bash
python scanner.py --count 50 --use-cache-only
```
##  Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--count` | `-n` | Number of unique live domains to return | 25 |
| `--tlds` | | Comma-separated TLD list | 30 common TLDs |
| `--no-verify` | | Skip live verification (faster) | False |
| `--use-cache-only` | | Use DB cache only, no remote fetch | False |

### Default TLDs (30 total):
com, net, org, io, co, uk, de, fr, ca, au, jp, cn, in, br, ru, nl, it, es, se, no, pl, be, ch, at, dk, fi, cz, pt, gr, nz

##  File Output

**Auto-saved scan results:**
- `20241209_154200_domains.txt`
- `20241209_154918_domains.txt`
- `20241209_160532_domains.txt`

**SQLite Database:**
- `webwhisper_db.db` (stores all seen domains with SHA-256 fingerprints)

##  How It Works

1. **Fetch** - Queries crt.sh Certificate Transparency logs for specified TLDs
2. **Deduplicate** - Checks SQLite DB to ensure domain hasn't been seen before
3. **Verify** - Tests each domain with HTTP/HTTPS requests for 200 status
4. **Store** - Marks verified domains as seen in database
5. **Save** - Auto-saves results to timestamped .txt file

## Pro Tips

### For maximum results:
```bash
python scanner.py --count 1000 --tlds com,net,org,io,co,uk,de,fr,ca,au
```

### For speed (skip verification):
```bash
python scanner.py --count 5000 --no-verify
```

### For testing offline:
```bash
python scanner.py --count 100 --use-cache-only
```

### Reset database:
```bash
rm webwhisper_db.db
```

##  Expected Results

- **Live verification enabled**: Typically 20-40% of domains return HTTP 200
- **Processing speed**: ~20 domains/second with live checking
- **Without verification**: Much faster, but may include offline domains

##  Important Notes

- **Rate limiting**: Script includes 1-second delay between crt.sh requests
- **SSL verification**: Disabled for domains with certificate issues
- **Timeout**: 5 seconds per domain for live checking
- **Concurrent threads**: 20 parallel connections for speed
- **First run**: Slower as it builds the database cache

##  Legal & Ethical Use

 **IMPORTANT:**
WebWhisper is designed for OSINT, research, and authorized reconnaissance ONLY.

You must follow:

- Local laws and regulations
- Target's policies and terms of service
- Bug bounty program rules
- Ethical hacking guidelines
- Responsible disclosure practices

**The tool performs HTTP requests to discovered domains. Ensure you have permission for any further security testing.**

Misuse is strictly discouraged and may be illegal.

##  Contributing

Contributions are welcome — improvements, features, optimizations, and bug fixes.

Areas for contribution:
- Additional data sources beyond crt.sh
- Enhanced filtering options
- Export formats (JSON, CSV)
- Web interface
- Performance optimizations

Submit pull requests or open GitHub issues.

##  Troubleshooting

### "No domains found"
- Check internet connection
- Try different TLDs: `--tlds com,net,org`
- Increase count: `--count 500`

### "crt.sh timeout"
- crt.sh may be rate-limiting or down
- Wait a few minutes and retry
- Use `--use-cache-only` to work offline

### "Too slow"
- Use `--no-verify` to skip live checking
- Reduce count
- Use fewer TLDs

### Database corruption
```bash
rm webwhisper_db.db
python scanner.py --count 100
```

##  Support

For help, bug reports, or feature requests:
- Open a GitHub issue
- Contact the project maintainer

##  Use Cases

-  Bug bounty reconnaissance
-  OSINT investigations
-  Security research
-  Domain monitoring
-  Threat intelligence gathering
-  Educational purposes
-  Automation pipelines

##  Acknowledgments

- Certificate Transparency project
- crt.sh for CT log access
- Open source security community

---

##  Version

**WebWhisper v1.0.0**

---

##  License

MIT License © 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Use responsibly.

**Made with  for the security research community**

*Happy hunting! 🎯*
