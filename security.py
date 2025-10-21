#!/usr/bin/env python3
from __future__ import annotations
import os, sys, json, time, shutil, hashlib, tempfile, platform, subprocess, threading, re, argparse, http.server, socketserver, base64
from datetime import datetime
from typing import Dict, Any, List, Tuple

# -------------------------
# Configuration defaults
# -------------------------
OUT_ROOT = os.path.join(os.getcwd(), "audit_plus_output")
CRITICAL_BINARIES = [
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\winlogon.exe",
]
EVENT_LOG_FETCH_COUNT = 200
HMAC_KEY_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "win_audit_plus", "hmac.key")
RULES_FILE = os.path.join(os.getcwd(), "rules.txt")

# -------------------------
# Utilities
# -------------------------
def check_windows():
    if sys.platform != "win32":
        print("This tool is Windows-only. Exiting.")
        sys.exit(1)

def now_iso(): return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
def mk(dir): os.makedirs(dir, exist_ok=True)

def run_cmd(cmd: str, timeout: int = 30) -> Tuple[int,str,str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=timeout, universal_newlines=True)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"

def powershell(cmd: str, timeout: int = 40) -> Tuple[int,str,str]:
    ps = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', cmd]
    try:
        proc = subprocess.run(ps, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, universal_newlines=True)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"

def write(path: str, text: str):
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
    except Exception as e:
        print(f"[!] Failed to write {path}: {e}")

def compute_sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fd:
            for chunk in iter(lambda: fd.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

# -------------------------
# HMAC signing helpers
# -------------------------
def ensure_hmac_key(path: str = HMAC_KEY_PATH) -> bytes:
    dk = os.path.dirname(path)
    if not os.path.exists(dk):
        os.makedirs(dk, exist_ok=True)
    if os.path.exists(path):
        try:
            with open(path, "rb") as f: return f.read()
        except:
            pass
    # generate 32 bytes key
    key = os.urandom(32)
    with open(path, "wb") as f: f.write(key)
    print(f"[i] HMAC key generated and stored at: {path}")
    return key

def sign_bytes(key: bytes, data: bytes) -> str:
    import hmac, hashlib
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode('ascii')

def verify_signature(key: bytes, data: bytes, sig_b64: str) -> bool:
    try:
        import hmac, hashlib
        expected = base64.b64decode(sig_b64)
        return hmac.compare_digest(hmac.new(key, data, hashlib.sha256).digest(), expected)
    except:
        return False

# -------------------------
# Rule scanner (simple regex rules)
# -------------------------
def load_rules(path: str = RULES_FILE) -> List[re.Pattern]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            try:
                out.append(re.compile(line, re.IGNORECASE))
            except Exception as e:
                print(f"[!] Invalid rule pattern '{line}': {e}")
    return out

def scan_text_with_rules(text: str, rules: List[re.Pattern]) -> List[str]:
    matches = []
    if not rules or not text: return matches
    for r in rules:
        if r.search(text):
            matches.append(r.pattern)
    return matches

# -------------------------
# Collectors (threaded-friendly)
# -------------------------
def collect_system_info(outdir: str) -> Dict[str,Any]:
    info = {"timestamp": now_iso(), "platform": platform.platform(), "hostname": platform.node(), "user": os.environ.get("USERNAME")}
    rc, sysout, syserr = run_cmd("systeminfo", timeout=30)
    info["systeminfo"] = sysout.strip()
    write(os.path.join(outdir, "systeminfo.txt"), sysout + "\n\nERR:\n" + syserr)
    return info

def collect_installed_programs(outdir: str) -> Any:
    cmd = ("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* , "
           "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* , "
           "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
           "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress")
    rc, out, err = powershell(cmd, timeout=40)
    write(os.path.join(outdir, "installed_programs.json"), out if out else ("ERR:\n"+err))
    try: return json.loads(out) if out else {}
    except: return {"raw": out, "err": err}

def collect_services(outdir: str) -> str:
    rc, out, err = run_cmd("sc query state= all", timeout=30)
    write(os.path.join(outdir, "services.txt"), out + "\n\nERR:\n" + err)
    return out

def collect_services_with_path(outdir: str) -> Any:
    cmd = r"Get-WmiObject -Class Win32_Service | Select Name,DisplayName,State,StartMode,PathName | ConvertTo-Json -Compress"
    rc, out, err = powershell(cmd, timeout=30)
    write(os.path.join(outdir, "services_with_path.json"), out if out else ("ERR:\n"+err))
    try: return json.loads(out) if out else {}
    except: return {"raw": out, "err": err}

def collect_scheduled_tasks(outdir: str) -> str:
    rc, out, err = run_cmd("schtasks /query /fo LIST /v", timeout=40)
    write(os.path.join(outdir, "scheduled_tasks.txt"), out + "\n\nERR:\n" + err)
    return out

def collect_netstat(outdir: str) -> str:
    rc, out, err = run_cmd("netstat -ano", timeout=30)
    write(os.path.join(outdir, "netstat.txt"), out + "\n\nERR:\n" + err)
    return out

def collect_tasklist(outdir: str) -> str:
    rc, out, err = run_cmd("tasklist /v /fo csv", timeout=30)
    write(os.path.join(outdir, "tasklist.csv"), out + "\n\nERR:\n" + err)
    return out

def collect_wmic_processes(outdir: str) -> str:
    rc, out, err = run_cmd('wmic process get ProcessId,ParentProcessId,CommandLine /format:csv', timeout=30)
    write(os.path.join(outdir, "wmic_processes.csv"), out + "\n\nERR:\n" + err)
    return out

def collect_event_logs(outdir: str, count: int = EVENT_LOG_FETCH_COUNT) -> Dict[str,str]:
    logs = {}
    for log in ("System","Application","Security"):
        cmd = f"wevtutil qe {log} /c:{count} /f:text /rd:true"
        rc, out, err = run_cmd(cmd, timeout=40)
        write(os.path.join(outdir, f"wevt_{log.lower()}.txt"), out + "\n\nERR:\n" + err)
        logs[log] = out
    return logs

def collect_defender(outdir: str) -> str:
    cmd = "Try { Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,FullScanAge,AMProductVersion,AMEngineVersion | ConvertTo-Json -Compress } Catch { $_ | Out-String }"
    rc, out, err = powershell(cmd, timeout=20)
    write(os.path.join(outdir, "defender_status.json"), out if out else ("ERR:\n"+err))
    return out

def collect_autoruns(outdir: str) -> str:
    ps = r"""
$keys = @(
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $keys) {
  if (Test-Path $k) {
    Get-ItemProperty $k | Select-Object PSPath, * | ConvertTo-Json -Compress
  }
}
"""
    rc, out, err = powershell(ps, timeout=20)
    write(os.path.join(outdir, "autoruns.json"), out if out else ("ERR:\n"+err))
    return out

def check_auth_signatures(outdir: str, paths: List[str]) -> Any:
    safe = [p for p in paths if os.path.exists(p)]
    if not safe:
        write(os.path.join(outdir, "auth_signatures.json"), json.dumps({}, indent=2))
        return {}
    arr = ",".join([f"'{p}'" for p in safe])
    cmd = f"@(({arr}) | ForEach-Object {{ Get-AuthenticodeSignature $_ | Select-Object Status,SignerCertificate,Path | ConvertTo-Json -Compress }})"
    rc, out, err = powershell(cmd, timeout=30)
    write(os.path.join(outdir, "auth_signatures_raw.json"), out if out else ("ERR:\n"+err))
    try: return json.loads(out)
    except: return {"raw": out, "err": err}

# -------------------------
# Heuristics & Baseline compare
# -------------------------
def compute_hashes(outdir: str, paths: List[str]) -> Dict[str,str]:
    res = {}
    for p in paths:
        if os.path.exists(p):
            res[p] = compute_sha256(p)
        else:
            res[p] = "MISSING"
    write(os.path.join(outdir, "critical_hashes.json"), json.dumps(res, indent=2))
    return res

def baseline_create(outdir: str, paths: List[str]) -> str:
    baseline = {"created": now_iso(), "paths": {}}
    for p in paths:
        baseline["paths"][p] = compute_sha256(p) if os.path.exists(p) else "MISSING"
    path = os.path.join(outdir, "baseline.json")
    write(path, json.dumps(baseline, indent=2))
    return path

def baseline_compare(baseline_path: str, current_hashes: Dict[str,str]) -> Dict[str,Any]:
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception as e:
        return {"error": f"Failed to load baseline: {e}"}
    diffs = []
    bpaths = baseline.get("paths", {})
    for p, prev in bpaths.items():
        cur = current_hashes.get(p, "MISSING")
        if cur != prev:
            diffs.append({"path": p, "baseline": prev, "current": cur})
    return {"baseline": baseline_path, "diffs": diffs}

def simple_heuristics(outdir: str, collected: Dict[str,Any], rules: List[re.Pattern]) -> List[Dict[str,Any]]:
    alerts = []
    # Missing critical binaries
    hashes = collected.get("hashes", {})
    for p,h in hashes.items():
        if h == "MISSING":
            alerts.append({"type":"missing_binary","path":p})
        elif h.startswith("ERROR:"):
            alerts.append({"type":"hash_error","path":p,"error":h})
    # suspicious strings in autoruns
    autoruns = collected.get("autoruns", "") or ""
    suspicious = ["frida","gdb","dbg","gameguardian","cheat","unusual","suspicious"]
    for s in suspicious:
        if s.lower() in autoruns.lower():
            alerts.append({"type":"suspicious_autorun","indicator":s})
    # rule matches
    if rules:
        scan_targets = "\n".join([collected.get("netstat",""), collected.get("autoruns",""), collected.get("services",""), collected.get("events","") or ""])
        matches = scan_text_with_rules(scan_targets, rules)
        for m in matches: alerts.append({"type":"rule_match","rule":m})
    # many listening ports
    port_map = collected.get("port_map", [])
    listening = [m for m in port_map if m.get("state","").upper() == "LISTENING"]
    if len(listening) > 50:
        alerts.append({"type":"many_listening_ports","count":len(listening)})
    write(os.path.join(outdir, "heuristic_alerts.json"), json.dumps(alerts, indent=2))
    return alerts

# -------------------------
# Mapping netstat -> pids
# -------------------------
def map_ports(outdir: str) -> List[Dict[str,str]]:
    rc, netstat_out, err = run_cmd("netstat -ano", timeout=30)
    mapping = []
    for line in netstat_out.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("proto") or line.startswith("Active"): continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 4:
            proto = parts[0]; local = parts[1]; foreign = parts[2]; pid = parts[-1]
            state = parts[3] if proto.upper().startswith("TCP") else ""
            mapping.append({"proto":proto,"local":local,"foreign":foreign,"state":state,"pid":pid})
    write(os.path.join(outdir, "port_pid_map.json"), json.dumps(mapping, indent=2))
    return mapping

# -------------------------
# Orchestration
# -------------------------
def run_full(outdir: str, hmac_key: bytes, rules: List[re.Pattern]) -> Dict[str,Any]:
    mk(outdir)
    meta = {"ts": now_iso(), "collected": {}}
    threads = []
    # helper to run collector in thread
    def run_collector(name, fn):
        try:
            res = fn(outdir)
            meta["collected"][name] = res
            print(f"[+] Collected {name}")
        except Exception as e:
            meta["collected"][name] = {"error": str(e)}
            print(f"[!] Collector {name} failed: {e}")
    collectors = {
        "system": collect_system_info,
        "installed_programs": collect_installed_programs,
        "services": collect_services,
        "services_with_path": collect_services_with_path,
        "scheduled_tasks": collect_scheduled_tasks,
        "autoruns": collect_autoruns,
        "netstat": collect_netstat,
        "tasklist": collect_tasklist,
        "wmic": collect_wmic_processes,
        "events": lambda d: collect_event_logs(d, EVENT_LOG_FETCH_COUNT),
        "defender": collect_defender,
    }
    for name,fn in collectors.items():
        t = threading.Thread(target=run_collector, args=(name,fn)); t.start(); threads.append(t)
    for t in threads: t.join(timeout=60)
    # maps & hashes
    meta["collected"]["port_map"] = map_ports(outdir)
    meta["collected"]["hashes"] = compute_hashes(outdir, CRITICAL_BINARIES)
    meta["collected"]["auth_signatures"] = check_auth_signatures(outdir, CRITICAL_BINARIES)
    # heuristics & rule scan
    meta["collected"]["rules_used"] = [r.pattern for r in rules]
    meta["collected"]["heuristics"] = simple_heuristics(outdir, {
        "hashes": meta["collected"]["hashes"],
        "autoruns": meta["collected"].get("autoruns",""),
        "netstat": meta["collected"].get("netstat",""),
        "services": meta["collected"].get("services",""),
        "events": "" # events large; rules scan already considered combined text
    }, rules)
    summary_path = os.path.join(outdir, "summary.json")
    write(summary_path, json.dumps(meta, indent=2))
    # sign the summary
    try:
        with open(summary_path, "rb") as f: data = f.read()
        sig = sign_bytes(hmac_key, data)
        write(os.path.join(outdir, "summary.hmac"), sig)
        print("[i] Summary HMAC written.")
    except Exception as e:
        print("[!] Failed to sign summary:", e)
    return meta

# -------------------------
# Web preview (optional)
# -------------------------
class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)
    def log_message(self, format, *args):
        pass

def serve_results(directory: str, port: int = 8000):
    handler = lambda *args, **kwargs: SimpleHandler(*args, directory=directory, **kwargs)
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"[i] Serving {directory} at http://127.0.0.1:{port} (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[i] Web server stopped.")

# -------------------------
# CLI & interactive menu
# -------------------------
def interactive(outroot: str, hmac_key: bytes):
    check_windows()
    mk(outroot)
    rules = load_rules(RULES_FILE)
    print(r"""
Windows Defensive Audit & Baseline Toolkit (single-file)
-------------------------------------------------------
Run only on systems you own or are authorized to audit.
""")
    while True:
        print("\nMenu:")
        print("  1) Run full audit and save results")
        print("  2) Create baseline of critical binaries")
        print("  3) Compare current state against baseline")
        print("  4) Scan using regex rules (rules.txt)")
        print("  5) Start local web preview of latest results")
        print("  6) Zip latest results")
        print("  q) Quit")
        ch = input("Choice: ").strip().lower()
        if ch == "1":
            outdir = os.path.join(outroot, "audit_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
            print("[*] Running full audit to", outdir)
            run_full(outdir, hmac_key, rules)
            print("[+] Done")
        elif ch == "2":
            outdir = os.path.join(outroot, "baseline_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
            mk(outdir)
            path = baseline_create(outdir, CRITICAL_BINARIES)
            print("[+] Baseline created at", path)
        elif ch == "3":
            baseline_path = input("Path to baseline JSON: ").strip()
            if not baseline_path: print("[!] No path"); continue
            current = compute_hashes(outroot, CRITICAL_BINARIES)
            diffs = baseline_compare(baseline_path, current)
            print(json.dumps(diffs, indent=2))
        elif ch == "4":
            txt = ""
            print("[i] Scanning autoruns/services/netstat/events for rule matches")
            for k in ("autoruns","services","netstat"):
                p = os.path.join(outroot, k + ".txt")
                if os.path.exists(p): txt += open(p, "r", encoding="utf-8", errors="replace").read() + "\n"
            rules = load_rules(RULES_FILE)
            matches = scan_text_with_rules(txt, rules)
            print("[+] Matches:", matches)
        elif ch == "5":
            latest = sorted([d for d in os.listdir(outroot)], reverse=True)
            if not latest: print("[!] No results yet"); continue
            d = os.path.join(outroot, latest[0])
            port = 8000
            print("[*] Launching web preview for:", d)
            serve_results(d, port)
        elif ch == "6":
            latest = sorted([d for d in os.listdir(outroot)], reverse=True)
            if not latest: print("[!] No results"); continue
            d = os.path.join(outroot, latest[0])
            zipname = d + ".zip"
            print("[*] Archiving", d, "->", zipname)
            shutil.make_archive(d, 'zip', d)
            print("[+] Archive created.")
        elif ch in ("q","quit","exit"):
            break
        else:
            print("Unknown choice.")

# -------------------------
# Main entrypoint
# -------------------------
def main():
    check_windows()
    p = argparse.ArgumentParser(description="Windows Defensive Audit & Baseline Toolkit (single-file)")
    p.add_argument("--all", action="store_true", help="Run full audit and exit")
    p.add_argument("--out", type=str, default=None, help="Output base dir")
    p.add_argument("--zip", action="store_true", help="Zip results after run (when used with --all)")
    p.add_argument("--web", action="store_true", help="Launch local web preview after run (requires --all)")
    p.add_argument("--baseline-create", action="store_true", help="Create baseline of critical binaries")
    p.add_argument("--baseline-compare", type=str, help="Compare against baseline json file")
    args = p.parse_args()

    outroot = args.out if args.out else OUT_ROOT
    mk(outroot)
    hmac_key = ensure_hmac_key(HMAC_KEY_PATH)
    rules = load_rules(RULES_FILE)

    if args.baseline_create:
        outdir = os.path.join(outroot, "baseline_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
        mk(outdir)
        path = baseline_create(outdir, CRITICAL_BINARIES)
        print("[+] Baseline created:", path)
        return

    if args.baseline_compare:
        current = compute_hashes(outroot, CRITICAL_BINARIES)
        diffs = baseline_compare(args.baseline_compare, current)
        print(json.dumps(diffs, indent=2))
        return

    if args.all:
        outdir = os.path.join(outroot, "audit_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
        mk(outdir)
        meta = run_full(outdir, hmac_key, rules)
        print("[+] Audit finished:", outdir)
        if args.zip:
            try:
                shutil.make_archive(outdir, 'zip', outdir)
                print("[+] Archive:", outdir + ".zip")
            except Exception as e:
                print("[!] Zip failed:", e)
        if args.web:
            try:
                serve_results(outdir, port=8000)
            except KeyboardInterrupt:
                pass
        return

    # interactive
    interactive(outroot, hmac_key)

if __name__ == "__main__":
    main()
