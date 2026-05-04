import os
import requests
import sqlite3
import re
import marshal
import hashlib
import json
import shutil
import time
from rich.console import Console
from rich.color import Color
from rich.text import Text
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

# --- CONFIGURATION ---
DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "intelligence.db")
HASHSET_PATH = os.path.join(DATA_DIR, "cve_hashset.bin")
SIG_PATH = os.path.join(DATA_DIR, "signatures.json")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

NVD_API_KEY = "9ec14cc6-0037-4982-a960-e9c38e435ae3"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# --- ASCII BANNER ---
BANNER = r"""

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠤⠤⠤⠤⣄⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⡊⠉⠉⣉⣱⡷⠶⢢⣠⢴⣶⡝⠒⠉⢉⣭⡽⠟⢉⣀⡀⠹⢭⠒⢤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠔⢚⣩⡽⠿⠊⢉⣉⡂⣀⣩⠭⢴⠟⠋⠉⠉⠉⠛⠳⢦⣬⣤⡴⠞⠛⠁⠛⠳⣾⣧⠀⠟⠀⠉⠲⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀██████╗ ██╗   ██╗██╗██╗     ██████╗ ██╗███╗   ██╗ ██████╗
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⢚⠁⠀⠰⠋⢡⠄⠀⠞⣫⢟⡥⠒⠉⠹⣿⡀⠀⠀⢦⡀⠀⠀⠀⠈⠻⡧⡀⠀⠀⠀⠀⠈⠻⣗⡶⠶⠶⢤⡀⠱⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀██╔══██╗██║   ██║██║██║     ██╔══██╗██║████╗  ██║██╔════╝
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢮⣤⡾⠀⠀⣠⡴⠋⠀⡠⣚⠥⠒⢛⡲⠄⠀⠈⢻⡆⠀⠀⠻⣦⣀⠀⠀⠀⣿⠻⣦⣀⣴⠶⠂⠀⠘⣷⡄⠀⠀⢀⣴⡿⠈⠢⡀⠀⠀⠀⠀⠀⠀██████╔╝██║   ██║██║██║     ██║  ██║██║██╔██╗ ██║██║  ███╗
⠀⠀⠀⠀⠀⠀⠀⡠⠖⣉⣁⡀⠀⢀⣾⠋⠴⢿⣽⠋⠀⠞⢉⣉⣽⣳⣄⣀⠀⠋⠀⠀⠀⠈⠙⣷⡄⠀⠁⠀⠙⢤⣯⡀⠀⠀⠀⣼⡇⠀⡾⠋⠁⠀⠳⣄⠘⢆⠀⠀⠀⠀⠀██╔══██╗██║   ██║██║██║     ██║  ██║██║██║╚██╗██║██║   ██║
⠀⠀⠀⠀⠀⡰⠋⠰⠛⢻⡞⢉⣠⣼⡇⢀⣴⠟⠛⠒⣴⠟⠋⠉⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⣸⡇⠀⠀⠳⣄⠀⠉⢿⣄⠀⢰⣿⣧⡀⠀⣴⠶⠶⣦⡼⢧⠈⢣⠀⠀⠀⠀██████╔╝╚██████╔╝██║███████╗██████╔╝██║██║ ╚████║╚██████╔╝
⠀⠀⠀⢀⡞⣡⣶⡄⠀⡟⣳⠿⠋⠙⡍⡽⠁⣀⣤⣤⣿⡄⠀⠀⠀⠀⡿⡉⣀⣀⣤⣤⣤⣴⠾⠥⠽⣦⣄⠀⠉⠻⢶⡼⢻⠀⠈⠇⠘⡷⡄⠘⠂⠀⢀⡍⠻⣷⣄⡇⠀⠀⠀╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝
⠀⠀⠀⠘⣺⠏⢸⢃⣼⠟⢁⡤⠀⣠⢟⡷⠟⢋⣉⣤⡿⠇⠀⠀⠀⢰⣣⠞⠋⠉⠉⠁⡀⠀⠀⠀⠀⠀⠙⢷⣄⠀⠀⢹⣾⠀⠀⠀⠀⢸⡇⠀⣀⡀⣾⠀⠀⠈⢻⡁⢦⠀⠀
⠀⠀⣠⢚⣵⣄⠈⣼⡇⠀⢸⠧⢞⡵⠋⠠⠚⠉⠉⠀⠀⢀⡇⠀⣰⣟⣁⣀⠀⠀⠀⠀⠉⠒⠶⣤⣤⣀⠀⠀⠙⠀⠀⢸⡇⢰⣟⠛⢶⡋⣇⠀⠉⠻⡟⡄⠀⢀⢀⣿⠀⢧⠀         #    ###       #     #    #    #######
⠀⣰⠃⢸⠁⣿⠀⠸⣧⠀⢸⢣⠋⠀⣠⣤⠶⢶⢒⣤⣔⣻⠣⢼⠟⠁⠀⠙⢷⡄⠀⠀⢀⠀⠀⠀⠈⠓⢟⢦⠀⠀⠀⢸⡇⠈⠻⣦⡀⠈⠻⣷⣄⠀⠘⣿⠀⠸⣿⣇⣀⢸⠀        # #    #        #  #  #   # #   #
⠀⡇⠀⠀⣼⠇⠀⢀⣿⠀⣇⣇⣴⠟⠋⢠⣾⠟⠉⠀⠀⠈⠳⣼⠀⠀⠀⠀⠀⠳⠀⠀⠈⢳⣄⠀⠀⠀⢸⣼⠀⠀⠀⠈⡟⢆⠀⠈⢻⡀⠀⠈⢻⣆⠀⣻⠃⠀⠀⢹⡟⠻⡀       #   #   #        #  #  #  #   #  #
⠀⢧⡆⣼⠏⠀⣾⠟⠁⢰⠃⡵⠃⢀⣴⡿⠁⠀⡀⠀⠀⠀⠀⠹⣧⡀⠰⣦⡀⠀⠀⠀⠀⠀⣻⢦⣀⣠⡾⣇⠀⠀⢀⣰⠟⠙⢷⣄⠀⠀⠀⠀⠀⣿⠀⠉⢠⠄⠀⣼⡇⠀⢧      #     #  #        #  #  # #     # #####
⢀⠞⢡⡟⠀⠀⣿⠀⢀⡏⡼⠁⣴⠟⠁⠀⠀⠀⣿⠀⣀⣀⢀⣴⠘⣷⡀⠈⢻⣦⣀⠀⢀⣾⠟⠉⠀⠀⠉⠻⣷⣄⠀⠀⠀⠀⠀⠙⢷⡄⠀⠀⠀⠉⠀⣠⡟⠀⣼⣟⠀⠀⢸      #######  #        #  #  # ####### #
⢸⠀⠘⣧⠀⡴⠛⠳⢸⢰⠁⢰⠏⠀⠀⠀⢀⣼⡯⠟⠋⠙⠻⣷⡀⠘⠀⠀⠀⠈⠉⠻⣿⠁⠀⠀⢰⡟⠉⠀⠈⢻⣦⠀⠀⠀⣄⠀⠀⡗⠀⢸⡇⣠⣾⠟⢀⣾⠋⠹⣷⢀⡇      #     #  #        #  #  # #     # #
⠈⢆⠀⠹⢷⣤⣀⣠⠎⡇⠀⠸⠀⠀⢀⣴⠟⠉⠀⠀⠀⢄⠀⠹⣧⡀⠀⠀⣀⡀⠀⠀⣿⠀⠀⠀⠘⣿⡄⠀⠀⠀⢹⣦⡀⠀⢿⣄⠀⢀⣠⡿⠽⣯⡁⠀⠸⠃⠀⠀⡏⠉⠀      #     # ###        ## ##  #     # #
⠀⢠⢷⣄⠀⠈⣉⣉⢢⢳⡀⠀⠀⠀⣾⡏⠀⠀⠠⣀⡤⢿⠀⠀⠙⠷⠶⠛⠉⠈⠀⣰⠟⠀⠀⠀⠀⠘⣷⡀⠀⠠⠛⠉⠉⠀⢈⣯⠗⠛⠁⠀⠀⠈⠃⠀⢀⣴⠇⢠⠇⠀⠀
⠀⢸⡀⠻⣧⠈⠉⠹⣏⢀⣑⠤⣀⣀⠼⠳⣄⠀⠀⠀⠙⠺⠖⣦⣤⠤⣀⡀⠀⠀⠘⠁⠀⠀⠀⠀⠀⠀⢸⢧⡀⠀⠀⢀⣀⢴⣿⣅⡀⠠⠶⢿⢦⣀⣠⣴⠟⠃⡠⠋⠀⠀⠀        ██████╗ ██████╗  █████╗ ██╗███╗   ██╗
⠀⠀⠳⡀⠘⠃⠀⡤⠸⣼⠀⠉⠛⠋⠉⠉⠙⠻⣦⣄⠀⠀⠀⠀⠈⠉⠙⠻⣦⠀⠀⠀⠀⡀⠀⠀⠀⢀⣾⠖⠚⠛⠛⠛⠋⠁⠀⠙⣷⠀⠀⣸⡴⠛⠉⢁⡤⠊⠁⠀⠀⠀⠀        ██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║
⠀⠀⠀⠘⢦⡀⠸⣧⠀⢻⢇⠀⠳⡤⣤⠆⠀⠀⠈⢻⡇⠀⠀⠀⢰⡄⠀⠀⣿⡇⢀⡾⠛⠛⠻⡝⣲⠟⠋⠀⢀⡄⠀⠀⠀⣀⡄⠀⠋⢀⡴⣻⡄⣤⡶⡍⠀⠀⠀⠀⠀⠀⠀        ██████╔╝██████╔╝███████║██║██╔██╗ ██║
⠀⠀⠀⠀⠀⠈⠙⠁⠉⠉⠈⠣⡀⠹⣇⠀⠀⠀⠀⠘⠀⠀⠀⢀⡾⢳⡶⠾⠋⠀⠈⠃⠀⠀⣠⠟⢄⣀⣠⡴⠋⠀⠀⠀⣼⢻⣤⣴⠶⠟⠋⣡⡷⣏⢿⡧⠀⠀⠀⠀⠀⠀⠀        ██╔══██╗██╔══██╗██╔══██║██║██║╚██╗██║
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⢫⣲⣤⣀⣀⣀⣀⣤⣶⣻⠋⠛⠷⣦⣤⣤⣄⡤⢤⣺⠕⠋⠉⠉⠁⠀⠀⣀⣤⣾⠏⢩⠀⠀⢀⣤⣾⠛⣧⢻⣼⠀⠀⠀⠀⠀⠀⠀⠀        ██████╔╝██║  ██║██║  ██║██║██║ ╚████║
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠮⢭⣉⣉⡩⠥⠚⠈⢇⠀⢠⡄⠀⠉⠉⠙⣿⠀⢠⠶⠖⢫⣩⠟⠛⠛⠉⠀⣠⣿⣦⠶⠿⣭⣸⣇⡿⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣌⡿⣄⠀⠒⠚⠋⠀⠀⠀⣠⡾⠃⠀⢀⣀⠴⠚⠉⠣⢍⣛⣶⡶⠝⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠒⠂⠀⠒⠒⠉⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

"""
def get_gradient_color(start_rgb, end_rgb, fraction):
    """Linearly interpolates between two RGB colors."""
    r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * fraction)
    g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * fraction)
    b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * fraction)
    return f"rgb({r},{g},{b})"

def display_banner():
    console = Console()
    lines = BANNER.splitlines()

    # Define our colors from the image (Cyan-ish to Pink-ish)
    color_start = (36, 198, 220)  # #24c6dc
    color_end = (255, 119, 233)    # #ff77e9

    # 2. Build the gradient text line by line
    gradient_text = Text()

    for line in lines:
        if not line.strip():
            gradient_text.append("\n")
            continue

        line_length = len(line)
        for i, char in enumerate(line):
            # Calculate how far across the line we are (0.0 to 1.0)
            fraction = i / line_length if line_length > 1 else 0
            color = get_gradient_color(color_start, color_end, fraction)
            gradient_text.append(char, style=color)
        gradient_text.append("\n")

    # 3. Print the result
    console.print(gradient_text)

# --- CPU PINNING ---
try:
    # This works on Linux/WSL.
    os.sched_setaffinity(0, {6, 7, 8, 9, 10, 11})
    print("[*] CPU Affinity: Pinned to Efficiency Cores (6-11)")
except (AttributeError, OSError):
    print("[*] CPU Affinity: Platform does not support sched_setaffinity. Continuing...")

class WAFBrain:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self._init_db()
        self.success_flags = {"owasp": False, "edb": False, "nvd": False}
        self.new_hashes = set()
        self.new_signatures = []
        print("[+] AI-WAF Brain: Intelligence Database Connected.")

    def _init_db(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS intelligence (
            id TEXT PRIMARY KEY,
            source TEXT,
            payload_hash TEXT,
            description TEXT,
            last_updated DATETIME)''')
        self.conn.commit()

    def normalize(self, text):
        if not text: return ""
        text = unquote(text)
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def fetch_owasp_crs(self):
        print("[*] Mining OWASP CRS (Balanced Filter)...")
        base_url = "https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3/master/rules/"
        rule_files = [
            "REQUEST-930-APPLICATION-ATTACK-LFI.conf", "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
            "REQUEST-932-APPLICATION-ATTACK-RCE.conf", "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
            "REQUEST-941-APPLICATION-ATTACK-XSS.conf", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            "REQUEST-944-APPLICATION-ATTACK-JAVA.conf"
        ]

        try:
            for file in rule_files:
                resp = requests.get(base_url + file, timeout=10)
                if resp.status_code == 200:
                    patterns = re.findall(r'"@rx\s+(.*?)"', resp.text)
                    for p in patterns:
                        p_clean = p.rstrip('\\')
                        if p_clean in [r"^.*$", r"\s", r".*", r"^[^;\s]+"]:
                            continue
                        if len(p_clean) < 5:
                            continue
                        if p_clean.startswith('^[^'):
                            continue
                        self.new_signatures.append(p_clean)

            if len(self.new_signatures) > 0:
                self.new_signatures = list(set(self.new_signatures))
                self.success_flags["owasp"] = True
                print(f" [+] OWASP Success: {len(self.new_signatures)} high-fidelity signatures.")
        except Exception as e:
            print(f" [!] OWASP Error: {e}")

    def fetch_exploit_db(self):
        print("[*] Syncing ExploitDB...")
        try:
            r = requests.get(EDB_URL, timeout=15)
            if r.status_code == 200:
                lines = r.text.split('\n')
                for line in lines[1:]:
                    parts = line.split(',')
                    if len(parts) > 5 and "webapps" in line.lower():
                        clean_desc = self.normalize(parts[2])
                        p_hash = hashlib.md5(clean_desc.encode()).hexdigest()
                        self.new_hashes.add(p_hash)
                        self.cursor.execute("INSERT OR REPLACE INTO intelligence VALUES (?, ?, ?, ?, ?)",
                                           (f"EDB-{parts[0]}", 'ExploitDB', p_hash, parts[2], datetime.now(timezone.utc).isoformat()))
                self.conn.commit()
                self.success_flags["edb"] = True
                print(f" [+] ExploitDB Success: {len(self.new_hashes)} hashes.")
        except Exception as e:
            print(f" [!] EDB Error: {e}")

    def fetch_nvd_with_retry(self, retries=3, delay=5):
        print("[*] Fetching NVD (with Retry Logic)...")
        headers = {'apiKey': NVD_API_KEY, 'User-Agent': 'WAF-Adaptive-Bot'}
        now = datetime.now(timezone.utc).replace(microsecond=0)
        yesterday = (now - timedelta(days=1)).isoformat()
        params = {'lastModStartDate': yesterday, 'lastModEndDate': now.isoformat()}

        for i in range(retries):
            try:
                r = requests.get(NVD_API_URL, headers=headers, params=params, timeout=20)
                if r.status_code == 200:
                    data = r.json()
                    for item in data.get('vulnerabilities', []):
                        cve_id = item['cve']['id']
                        self.new_hashes.add(hashlib.md5(self.normalize(cve_id).encode()).hexdigest())
                    self.success_flags["nvd"] = True
                    print(f" [+] NVD Success on attempt {i+1}.")
                    return
                else:
                    print(f" [!] NVD Status {r.status_code}. Retrying...")
            except Exception as e:
                print(f" [!] NVD Attempt {i+1} failed: {e}")
            time.sleep(delay * (i + 1))

    def finalize_with_backup(self):
        if all(self.success_flags.values()):
            print("[*] All sources updated. Creating Production Brain and Backup...")
            with open(HASHSET_PATH, 'wb') as f:
                marshal.dump(self.new_hashes, f)
            with open(SIG_PATH, 'w') as f:
                json.dump(list(set(self.new_signatures)), f)

            ts = datetime.now().strftime("%Y%m%d_%H%M")
            shutil.copy(HASHSET_PATH, os.path.join(BACKUP_DIR, f"hashset_{ts}.bin"))
            shutil.copy(SIG_PATH, os.path.join(BACKUP_DIR, f"sigs_{ts}.json"))
            print(f"[+] Update Successful. Backup created at {ts}")
        else:
            failed = [k for k, v in self.success_flags.items() if not v]
            print(f"[!] Update Incomplete. Failed: {failed}")
            print("[!] ABORTING: Production brain was NOT overwritten.")
        self.conn.close()

if __name__ == "__main__":
    display_banner()
    print("[*] AI-WAF Brain: Starting Intelligence Sync...")
    brain = WAFBrain()
    brain.fetch_owasp_crs()
    brain.fetch_exploit_db()
    brain.fetch_nvd_with_retry()
    brain.finalize_with_backup()
