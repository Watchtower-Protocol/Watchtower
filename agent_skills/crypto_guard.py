#!/usr/bin/env python3
import os, sys, json, platform, subprocess, re, argparse

WALLET_PATHS = {
    "Windows": [
        os.path.expandvars(r"%APPDATA%\Exodus\exodus.wallet"),
        os.path.expandvars(r"%APPDATA%\Bitcoin\wallet.dat"),
        os.path.expandvars(r"%APPDATA%\Electrum\wallets")
    ],
    "Darwin": [
        os.path.expanduser("~/Library/Application Support/Exodus/exodus.wallet"),
        os.path.expanduser("~/Library/Application Support/Bitcoin/wallet.dat"),
        os.path.expanduser("~/.electrum/wallets")
    ],
    "Linux": [
        os.path.expanduser("~/.config/Exodus/exodus.wallet"),
        os.path.expanduser("~/.bitcoin/wallet.dat"),
        os.path.expanduser("~/.electrum/wallets")
    ]
}

def check_wallet_files():
    os_sys = platform.system()
    paths = WALLET_PATHS.get(os_sys, [])
    found_wallets = []
    for p in paths:
        if os.path.exists(p):
            try:
                perms = oct(os.stat(p).st_mode)[-3:]
                found_wallets.append({"path": p, "permissions": perms, "warning": "Open permissions!" if perms not in ["700", "600"] else "Secure"})
            except:
                found_wallets.append({"path": p, "status": "exists (access denied)"})
    return found_wallets

def check_clipboard_for_hijack():
    os_sys = platform.system()
    clip_data = ""
    try:
        if os_sys == "Darwin":
            clip_data = subprocess.check_output(["pbpaste"], text=True)
        elif os_sys == "Windows":
            clip_data = subprocess.check_output(["powershell", "-command", "Get-Clipboard"], text=True).strip()
        elif os_sys == "Linux":
            clip_data = subprocess.check_output(["xclip", "-o"], text=True)
            
        crypto_patterns = {
            "Bitcoin (BTC)": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
            "Ethereum/BSC/AVAX (EVM)": r"^0x[a-fA-F0-9]{40}$",
            "Solana (SOL)": r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
            "Sui (SUI)": r"^0x[a-fA-F0-9]{64}$",
            "XRP (Ripple)": r"^r[1-9a-km-zA-HJ-NP-Z]{24,34}$",
            "Cardano (ADA)": r"^addr1[a-z0-9]{58,90}$",
            "Avalanche (X/P-Chain)": r"^[XP]-avax1[a-z0-9]{38}$",
            "Dogecoin (DOGE)": r"^D[1-9A-HJ-NP-Za-km-z]{33}$",
            "Litecoin (LTC)": r"^(L|M|ltc1)[a-zA-HJ-NP-Z0-9]{26,40}$",
            "Polkadot (DOT)": r"^1[1-9A-HJ-NP-Za-km-z]{45,50}$"
        }
        
        for coin, pattern in crypto_patterns.items():
            if re.match(pattern, clip_data):
                return {"status": "warning", "detected": coin, "value": clip_data}
                
        return {"status": "clean"}
    except:
        return {"status": "error", "message": "Could not access clipboard natively."}

def scan_for_seed_phrases(directory="~/Desktop"):
    target_dir = os.path.expanduser(directory)
    found_leaks = []
    seed_regex = re.compile(r'(?:\b[a-z]{3,8}\b\s){11,23}\b[a-z]{3,8}\b')
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith((".txt", ".md", ".csv", ".rtf", ".json")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        if seed_regex.search(f.read()): found_leaks.append(filepath)
                except: pass
    return found_leaks

def run_crypto_guard(action, directory="~/Desktop"):
    report = {"status": "success", "action_taken": action}
    if action in ["scan_wallets", "all"]: report["wallet_files"] = check_wallet_files()
    if action in ["clipboard", "all"]: report["clipboard"] = check_clipboard_for_hijack()
    if action in ["scan_seeds", "all"]: report["exposed_seeds"] = scan_for_seed_phrases(directory)
    return report

def run_daemon(interval=2):
    import time
    print("[*] Starting Watchtower Crypto Guard in Standalone Monitor Mode...")
    last_clip = ""
    while True:
        try:
            current_clip = check_clipboard_for_hijack()
            if current_clip.get("status") == "warning":
                if last_clip != "" and current_clip["value"] != last_clip:
                    print(f"[!] MALWARE ALERT: Clipboard crypto address swapped from {last_clip[:10]}... to {current_clip['value'][:10]}...!")
                last_clip = current_clip["value"]
            time.sleep(interval)
        except Exception: time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["scan_wallets", "clipboard", "scan_seeds", "all"], default="all")
    parser.add_argument("--dir", default="~/Desktop")
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    
    if args.monitor: run_daemon()
    else: print(json.dumps(run_crypto_guard(args.action, args.dir), indent=2))
