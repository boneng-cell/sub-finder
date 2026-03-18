import subprocess
import json
import requests
import sys
import os

domain = sys.argv[1]
api_key = sys.argv[2] if len(sys.argv) > 2 else None

results = set()
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().splitlines()
    except:
        return []

print(f"[+] Collecting subdomains for {domain}")
results.update(run(f"subfinder -d {domain} -silent"))
results.update(run(f"assetfinder --subs-only {domain}"))
results.update(run(f"amass enum -passive -d {domain}"))
if api_key:
    os.environ["PD_API_KEY"] = api_key
    results.update(run(f"chaos -d {domain} -silent"))
try:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = requests.get(url, timeout=10)
    data = json.loads(r.text)
    for entry in data:
        for sub in entry['name_value'].split('\n'):
            results.add(sub)
except:
    pass
cleaned = set()
for sub in results:
    sub = sub.lower().replace("*.", "").strip().strip(".")
    if domain in sub:
        cleaned.add(sub)
with open("all_subs.txt", "w") as f:
    for sub in sorted(cleaned):
        f.write(sub + "\n")
print(f"[✓] Done: {len(cleaned)} subdomains saved")
