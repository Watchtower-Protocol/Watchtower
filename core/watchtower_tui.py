import json
import time
import os
import sys

# Watchtower Terminal User Interface (TUI)
DB_PATH = os.path.join(os.path.dirname(__file__), "../data/watchtower_db.json")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def fetch_threats():
    if not os.path.exists(DB_PATH):
        return []
    try:
        with open(DB_PATH, 'r') as f:
            data = json.load(f)
            return data.get("threats", [])
    except Exception:
        return []

def draw_tui():
    clear_screen()
    print("="*60)
    print(" WATCHTOWER V2 // SOVEREIGN TERMINAL INTERFACE")
    print("="*60)
    print("[1] Refresh Threat Matrix")
    print("[2] Start Command Center Dashboard")
    print("[3] Exit")
    print("-" * 60)
    
    threats = fetch_threats()
    if not threats:
        print("[ SYSTEM NOMINAL // NO ACTIVE THREATS ]\n")
    else:
        print(f"!!! ACTIVE THREATS DETECTED ({len(threats)}) !!!")
        for i, t in enumerate(threats):
            print(f"\n[{i+1}] {t.get('title', 'Unknown')} | {t.get('ai_verdict', 'UNKNOWN')}")
            print(f"    Source:  {t.get('source', '')}")
            print(f"    Target:  {t.get('file_path', '')}")
            print(f"    Context: {t.get('ai_reason', '')[:100]}...")
            
    print("-" * 60)

def block_menu():
    while True:
        draw_tui()
        choice = input("\nWatchtower> ").strip()
        
        if choice == '1':
            continue
        elif choice == '2':
            print("\n[*] Initializing background orchestrator...")
            os.system("cd .. && ./start.sh")
            print("[*] Dashboard starting on http://localhost:8080")
            time.sleep(2)
        elif choice == '3':
            print("Terminating TUI...")
            sys.exit(0)
        else:
            print("Invalid command.")
            time.sleep(1)

if __name__ == "__main__":
    block_menu()
