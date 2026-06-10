import subprocess
import os
import sys
import argparse
import json
from datetime import datetime

class OWASPScanner:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.targets_file = os.path.join(output_dir, f"targets_{self.timestamp}.txt")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def prepare_targets(self, list_file=None, url=None, postman_file=None):
        targets = []
        nmap_targets = []

        if list_file:
            with open(list_file, "r") as f:
                for line in f:
                    t = line.strip()
                    if t:
                        targets.append(t)
                        nmap_targets.append(self.get_hostname(t))
        
        if url:
            targets.append(url)
            nmap_targets.append(self.get_hostname(url))
            
        if postman_file:
            print(f"[*] Parsing Postman Collection: {postman_file}")
            pm_urls = self.parse_postman(postman_file)
            targets.extend(pm_urls)
            for t in pm_urls:
                nmap_targets.append(self.get_hostname(t))
            
        # Write unique targets to temporary files
        self.nuclei_targets = os.path.join(self.output_dir, f"nuclei_targets_{self.timestamp}.txt")
        self.nmap_targets_file = os.path.join(self.output_dir, f"nmap_targets_{self.timestamp}.txt")

        with open(self.nuclei_targets, "w") as f:
            for t in sorted(list(set(targets))):
                f.write(t + "\n")
        
        with open(self.nmap_targets_file, "w") as f:
            for t in sorted(list(set(nmap_targets))):
                if t: f.write(t + "\n")
        
        return len(targets)

    def get_hostname(self, url):
        # Simple extraction of hostname from URL
        if "://" in url:
            hostname = url.split("://")[1].split("/")[0].split(":")[0]
        else:
            hostname = url.split("/")[0].split(":")[0]
        return hostname

    def parse_postman(self, file_path):
        urls = []
        variables = {}
        
        def resolve_vars(text):
            if not isinstance(text, str): return text
            for k, v in variables.items():
                text = text.replace(f"{{{{{k}}}}}", v)
            return text

        def extract_urls(data):
            if isinstance(data, dict):
                if "url" in data:
                    url_obj = data["url"]
                    if isinstance(url_obj, str):
                        urls.append(resolve_vars(url_obj))
                    elif isinstance(url_obj, dict) and "raw" in url_obj:
                        urls.append(resolve_vars(url_obj["raw"]))
                for key in data:
                    if key != "variable": # Don't recurse into variable definitions here
                        extract_urls(data[key])
            elif isinstance(data, list):
                for item in data:
                    extract_urls(item)
        
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                # First, get variables
                for var in data.get("variable", []):
                    variables[var["key"]] = var["value"]
                
                extract_urls(data)
        except Exception as e:
            print(f"[!] Error parsing Postman file: {e}")
        
        return urls

    def run_command(self, cmd, description):
        print(f"[*] Starting: {description}")
        try:
            # Using shell=True for convenience with complex tool calls, 
            # but we should be careful with input in a real-world scenario.
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                print(f"  > {line.strip()}")
            process.wait()
            return process.returncode == 0
        except Exception as e:
            print(f"[!] Error running {description}: {e}")
            return False

    def scan(self, fast_mode=True):
        print(f"\n[+] Starting OWASP Top 10 Scan")
        print(f"[*] Targets for Discovery: {self.nmap_targets_file}")
        print(f"[*] Targets for Vuln Scan: {self.nuclei_targets}")
        
        # 1. Nmap Service Discovery
        nmap_out = os.path.join(self.output_dir, f"nmap_{self.timestamp}.xml")
        nmap_cmd = f"nmap -iL {self.nmap_targets_file} -sV -T4 -oX {nmap_out}"
        if fast_mode:
            nmap_cmd += " --top-ports 100"
        self.run_command(nmap_cmd, "Nmap Service Discovery")

        # 2. Nuclei OWASP Scan (The Heavy Lifter)
        nuclei_out = os.path.join(self.output_dir, f"nuclei_{self.timestamp}.log")
        nuclei_json = os.path.join(self.output_dir, f"nuclei_{self.timestamp}.json")
        
        tags = "owasp,injection,xss,sqli,rce,lfi,ssrf,misconfig,exposure,auth,cve"
        # Adding -fuzz for API testing if we have full URLs from Postman
        nuclei_cmd = f"nuclei -l {self.nuclei_targets} -t /root/.local/nuclei-templates -tags {tags} -o {nuclei_out} -jle {nuclei_json} -silent"
        self.run_command(nuclei_cmd, "Nuclei OWASP Template Scan")

        # 3. Nikto Scan (Optional/Fast)
        if not fast_mode:
            nikto_out = os.path.join(self.output_dir, f"nikto_{self.timestamp}.txt")
            nikto_cmd = f"cat {self.nmap_targets_file} | xargs -I % nikto -h % -o {nikto_out}"
            self.run_command(nikto_cmd, "Nikto Web Server Scan")

        print(f"\n[+] Scan Complete. Results saved in {self.output_dir}")
        self.summarize_results(nuclei_json)

    def summarize_results(self, nuclei_json):
        print("\n" + "="*50)
        print("VULNERABILITY SUMMARY")
        print("="*50)
        
        if not os.path.exists(nuclei_json):
            print("[!] No findings or nuclei results file not found.")
            return

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings = []

        with open(nuclei_json, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    sev = data.get("info", {}).get("severity", "info").lower()
                    severity_counts[sev] += 1
                    findings.append({
                        "id": data.get("template-id"),
                        "name": data.get("info", {}).get("name"),
                        "url": data.get("matched-at"),
                        "severity": sev
                    })
                except:
                    continue

        for sev, count in severity_counts.items():
            if count > 0:
                print(f"[{sev.upper()}] : {count} findings")
        
        if findings:
            print("\nTop Findings:")
            for f in findings[:10]: # Show top 10
                print(f" - {f['severity'].upper()}: {f['name']} ({f['url']})")
        else:
            print("No significant vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OWASP Top 10 Automated Scanner")
    parser.add_argument("-l", "--list", help="File containing list of IPs or Domains")
    parser.add_argument("-u", "--url", help="Single target URL or IP")
    parser.add_argument("-p", "--postman", help="Postman collection JSON file for API scanning")
    parser.add_argument("-o", "--output", default="scan_reports", help="Output directory for reports")
    parser.add_argument("--deep", action="store_true", help="Run deep scan (includes nikto and all ports)")

    args = parser.parse_args()

    if not (args.list or args.url or args.postman):
        parser.print_help()
        sys.exit(1)

    scanner = OWASPScanner(args.output)
    count = scanner.prepare_targets(list_file=args.list, url=args.url, postman_file=args.postman)

    if count == 0:
        print("[!] No targets found to scan.")
        sys.exit(1)

    scanner.scan(fast_mode=not args.deep)