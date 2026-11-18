# Setup / Standard Recon Pipeline

> Reference content for the `web2-recon` skill. Originally SETUP / STANDARD RECON PIPELINE of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---
