import subprocess
import json
import requests
import sys
import os

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().splitlines()
    except:
        return []

def enumerate_subdomains(domain):
    print(f"[+] Collecting subdomains for {domain}")
    results = set()
    results.update(run_cmd(f"subfinder -d {domain} -silent"))
    results.update(run_cmd(f"assetfinder --subs-only {domain}"))
    results.update(run_cmd(f"amass enum -passive -d {domain}"))
    if os.getenv('PD_API_KEY'):
        results.update(run_cmd(f"chaos -d {domain} -silent"))
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        data = r.json()
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
    print(f"[✓] Found {len(cleaned)} subdomains")
    return len(cleaned)

def run_httpx():
    excluded_status_codes = {304, 400, 404, 408, 410, 429, 502, 503, 504}
    if not os.path.exists("all_subs.txt"):
        return False
    with open("all_subs.txt", "r") as f:
        urls = f.read().splitlines()
    print(f"[*] Scanning {len(urls)} URLs with httpx")
    cmd = ["httpx", "-l", "all_subs.txt", "-json", "-silent"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    files = {200: open("200.txt","w"), 300: open("300.txt","w"), 400: open("400.txt","w"), 500: open("500.txt","w")}
    for line in process.stdout:
        try:
            data = json.loads(line.strip())
            url = data.get("url")
            code = data.get("status_code")
            if not url or code is None or code in excluded_status_codes:
                continue
            if 200 <= code < 300:
                files[200].write(url+"\n")
            elif 300 <= code < 400:
                files[300].write(url+"\n")
            elif 400 <= code < 500:
                files[400].write(url+"\n")
            elif 500 <= code < 600:
                files[500].write(url+"\n")
        except:
            continue
    for f in files.values():
        f.close()
    for code in [200,300,400,500]:
        if os.path.exists(f"{code}.txt"):
            with open(f"{code}.txt","r") as f:
                print(f"  {code}.txt: {len(f.read().splitlines())} URLs")
    return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python sub_scan.py <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    sub_count = enumerate_subdomains(domain)
    if sub_count > 0:
        run_httpx()
        print(f"[✓] Done: all_subs.txt, 200.txt, 300.txt, 400.txt, 500.txt")

if __name__ == "__main__":
    main()
