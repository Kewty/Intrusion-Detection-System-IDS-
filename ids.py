#!/usr/bin/env python3
# ids_pro.py

from __future__ import annotations
import os
import sys
import time
import json
import shutil
import signal
import logging
import threading
import subprocess
from typing import Dict, Any, Optional, List, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter

try:
    import scapy.all as scapy
except Exception as e:
    print("Scapy import edilemedi. Virtualenv aktif mi? scapy kurulu mu kontrol et.")
    print("Hata:", e)
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
except Exception:
    print("colorama kurulu değil. 'pip install colorama' ile kur.")
    sys.exit(1)

colorama_init(autoreset=True)

# -------------------- KONFIGÜRASYON --------------------
CONFIG = {
    # sliding window seconds
    "window_seconds": 10,

    # thresholds
    "dos_threshold": 120,
    "icmp_threshold": 80,
    "syn_portscan_threshold": 40,
    "syn_flood_threshold": 120,

    # autoban
    "enable_autoban": False,
    "ban_duration_seconds": 300,
    "ban_manager_interval": 5,

    # logging
    "log_dir": "logs",
    "json_log": True,
    "verbose_packet_summary": False,

    # whitelist networks - otomatik ban'a karşı (RFC1918 + loopback)
    "whitelist_networks": [
        "127.0.0.1/32",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ],

    # operation
    "use_ufw_if_present": True,
    "print_periodic_stats": True,
    "stats_period_seconds": 5,
}

# -------------------- GLOBALS --------------------
stop_event = threading.Event()
LOCK = threading.Lock()
start_time = time.time()

# High-throughput structures
packet_times: Dict[str, deque] = defaultdict(deque)     # ip -> deque[timestamps]
tcp_syn_events: Dict[str, deque] = defaultdict(deque)   # ip -> deque[(ts, port)]
icmp_times: Dict[str, deque] = defaultdict(deque)       # ip -> deque[timestamps]
arp_table: Dict[str, Set[str]] = defaultdict(set)       # ip -> set(mac)

# ban map
blocked_ips: Dict[str, float] = {}  # ip -> unblock_ts

# statistics
stat_counter = Counter()

# firewall availability
USE_UFW = shutil.which("ufw") is not None and CONFIG["use_ufw_if_present"]
USE_IPTABLES = shutil.which("iptables") is not None

# whitelist networks
try:
    import ipaddress
    WHITELIST_NETWORKS = [ipaddress.ip_network(n) for n in CONFIG["whitelist_networks"]]
except Exception:
    WHITELIST_NETWORKS = []

# -------------------- LOGGING SETUP --------------------
os.makedirs(CONFIG["log_dir"], exist_ok=True)
TEXT_LOG_PATH = os.path.join(CONFIG["log_dir"], f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
JSON_LOG_PATH = os.path.join(CONFIG["log_dir"], f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json") if CONFIG["json_log"] else None

logger = logging.getLogger("ids_logger")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(TEXT_LOG_PATH, encoding="utf-8")
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(fmt)
logger.addHandler(file_handler)

def json_log(entry: Dict[str, Any]):
    if not JSON_LOG_PATH:
        return
    try:
        with open(JSON_LOG_PATH, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass

def log_event(level: str, message: str, extra: Optional[Dict[str, Any]]=None):
    ts = datetime.now().isoformat()
    text_line = f"{ts} | {level} | {message}"
    if level == "ERROR":
        logger.error(message)
    elif level == "WARN":
        logger.warning(message)
    else:
        logger.info(message)
    entry = {"timestamp": ts, "level": level, "message": message}
    if extra:
        entry["extra"] = extra
    json_log(entry)

# -------------------- UTILITIES --------------------
def is_whitelisted(ip_str: str) -> bool:
    if not WHITELIST_NETWORKS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in WHITELIST_NETWORKS:
            if ip in net:
                return True
    except Exception:
        return False
    return False

def run_cmd(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

# -------------------- FIREWALL (autoban) --------------------
def block_ip(ip: str) -> bool:
    """Apply temporary block on IP using ufw or iptables."""
    if is_whitelisted(ip):
        log_event("WARN", f"Ban skipped for whitelisted IP {ip}")
        return False
    with LOCK:
        if ip in blocked_ips:
            return False
        blocked_ips[ip] = time.time() + CONFIG["ban_duration_seconds"]
    ok = False
    if USE_UFW:
        ok = run_cmd(["ufw", "deny", "from", ip])
    elif USE_IPTABLES:
        ok = run_cmd(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        msg = f"Auto-ban applied: {ip} for {CONFIG['ban_duration_seconds']}s"
        print(Fore.RED + msg)
        log_event("WARN", msg)
    else:
        with LOCK:
            blocked_ips.pop(ip, None)
        msg = f"Auto-ban failed for {ip} (firewall not available)"
        print(Fore.YELLOW + msg)
        log_event("ERROR", msg)
    return ok

def unblock_ip(ip: str) -> bool:
    ok = False
    if USE_UFW:
        ok = run_cmd(["ufw", "delete", "deny", "from", ip])
    elif USE_IPTABLES:
        ok = run_cmd(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    with LOCK:
        blocked_ips.pop(ip, None)
    if ok:
        msg = f"Auto-unban executed: {ip}"
        print(Fore.GREEN + msg)
        log_event("INFO", msg)
    else:
        msg = f"Auto-unban attempted (rule not found maybe): {ip}"
        log_event("WARN", msg)
    return ok

def ban_manager_loop():
    while not stop_event.is_set():
        now = time.time()
        to_unban = []
        with LOCK:
            for ip, ts in list(blocked_ips.items()):
                if ts <= now:
                    to_unban.append(ip)
        for ip in to_unban:
            try:
                unblock_ip(ip)
            except Exception as e:
                log_event("ERROR", f"Error while unblocking {ip}: {e}")
        time.sleep(CONFIG["ban_manager_interval"])

# -------------------- HELPERS FOR DEQUE CLEANUP --------------------
def cleanup_old_deque(dq: deque, window: float):
    cutoff = time.time() - window
    while dq and dq[0] < cutoff:
        dq.popleft()

def cleanup_old_deque_with_ports(dq: deque, window: float):
    cutoff = time.time() - window
    while dq and dq[0][0] < cutoff:
        dq.popleft()

# -------------------- PACKET HANDLER (CORE IDS) --------------------
def packet_handler(pkt):
    try:
        stat_counter["total_packets"] += 1

        # optional verbose packet summary
        if CONFIG["verbose_packet_summary"]:
            try:
                print(Style.DIM + pkt.summary())
            except Exception:
                pass

        # ARP first (spoof detection)
        if pkt.haslayer(scapy.ARP):
            arp = pkt[scapy.ARP]
            ip = getattr(arp, "psrc", None)
            mac = getattr(arp, "hwsrc", None)
            if ip and mac:
                with LOCK:
                    arp_table[ip].add(mac)
                    if len(arp_table[ip]) > 1:
                        msg = f"ARP_SPOOF_SUSPECT ip={ip} macs={list(arp_table[ip])}"
                        print(Fore.RED + "[ARP-SPOOF] " + msg)
                        log_event("WARN", msg)

        # only IP packets for DOS/SYN/ICMP
        if not pkt.haslayer(scapy.IP):
            return

        now = time.time()
        ip_layer = pkt[scapy.IP]
        src = ip_layer.src

        # GENERAL PACKET COUNT (DoS)
        dq = packet_times[src]
        dq.append(now)
        cleanup_old_deque(dq, CONFIG["window_seconds"])
        window_count = len(dq)
        if window_count >= CONFIG["dos_threshold"]:
            msg = f"ALERT_DOS src={src} count={window_count}"
            print(Fore.RED + msg)
            log_event("WARN", msg, {"src": src, "count": window_count})
            stat_counter["dos_alerts"] += 1
            if CONFIG["enable_autoban"]:
                block_ip(src)
            dq.clear()

        # TCP / SYN handling
        if pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            flags = tcp.flags
            is_syn = False
            try:
                if int(flags) & 0x02:
                    is_syn = True
            except Exception:
                try:
                    if str(flags) == "S":
                        is_syn = True
                except Exception:
                    pass
            if is_syn:
                dport = tcp.dport
                syn_dq = tcp_syn_events[src]
                syn_dq.append((now, dport))
                cleanup_old_deque_with_ports(syn_dq, CONFIG["window_seconds"])
                syn_count = len(syn_dq)
                unique_ports = {p for (_, p) in syn_dq}
                if syn_count >= CONFIG["syn_flood_threshold"]:
                    msg = f"SYN_FLOOD src={src} syn_count={syn_count}"
                    print(Fore.RED + msg)
                    log_event("WARN", msg, {"src": src, "syn_count": syn_count})
                    stat_counter["syn_floods"] += 1
                    if CONFIG["enable_autoban"]:
                        block_ip(src)
                    syn_dq.clear()
                elif len(unique_ports) >= CONFIG["syn_portscan_threshold"]:
                    msg = f"PORT_SCAN src={src} unique_ports={len(unique_ports)}"
                    print(Fore.YELLOW + msg)
                    log_event("WARN", msg, {"src": src, "unique_ports": len(unique_ports)})
                    stat_counter["port_scans"] += 1
                    if CONFIG["enable_autoban"]:
                        block_ip(src)
                    syn_dq.clear()

        # ICMP handling
        if pkt.haslayer(scapy.ICMP):
            icmp_dq = icmp_times[src]
            icmp_dq.append(now)
            cleanup_old_deque(icmp_dq, CONFIG["window_seconds"])
            icmp_count = len(icmp_dq)
            if icmp_count >= CONFIG["icmp_threshold"]:
                msg = f"ICMP_FLOOD src={src} count={icmp_count}"
                print(Fore.RED + msg)
                log_event("WARN", msg, {"src": src, "icmps": icmp_count})
                stat_counter["icmp_floods"] += 1
                if CONFIG["enable_autoban"]:
                    block_ip(src)
                icmp_dq.clear()

    except Exception as e:
        stat_counter["handler_errors"] += 1
        log_event("ERROR", f"packet_handler_exception: {e}")

# -------------------- SNIFF WORKER --------------------
def sniff_worker(iface: Optional[str] = None):
    try:
        scapy.sniff(iface=iface, prn=packet_handler, store=False, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        log_event("ERROR", f"sniff_worker_exception: {e}")
        print(Fore.RED + f"[SNIFF ERROR] {e}")

# -------------------- STATS PRINTER --------------------
def stats_printer_loop():
    last_total = 0
    while not stop_event.is_set():
        time.sleep(CONFIG["stats_period_seconds"])
        with LOCK:
            elapsed = time.time() - start_time
            total = stat_counter.get("total_packets", 0)
            delta = total - last_total
            last_total = total
            print("\n" + Fore.CYAN + "===== IDS STATS =====")
            print(Fore.CYAN + f"Uptime: {timedelta(seconds=int(elapsed))}")
            print(Fore.CYAN + f"Total packets processed: {total} (Δ {delta} last {CONFIG['stats_period_seconds']}s)")
            print(Fore.CYAN + f"Active watched IPs: {len(packet_times)}")
            print(Fore.CYAN + f"Blocked IPs: {len(blocked_ips)}")
            print(Fore.CYAN + f"Alerts: dos={stat_counter.get('dos_alerts',0)}, syn={stat_counter.get('syn_floods',0)}, icmp={stat_counter.get('icmp_floods',0)}, scans={stat_counter.get('port_scans',0)}")
            top = sorted(packet_times.items(), key=lambda kv: len(kv[1]), reverse=True)[:5]
            if top:
                print(Fore.YELLOW + "Top talkers (ip:count):")
                for ip, dq in top:
                    print(Fore.YELLOW + f" - {ip}: {len(dq)}")
            print(Fore.CYAN + "=====================\n")

# -------------------- NETWORK INTERFACE MENU --------------------
def get_interfaces() -> List[str]:
    try:
        ifaces = scapy.get_if_list()
        return ifaces
    except Exception:
        # fallback to psutil if scapy fails to fetch (psutil optional)
        try:
            import psutil
            return list(psutil.net_if_addrs().keys())
        except Exception:
            return ["lo"]

def print_interface_menu(interfaces: List[str]):
    os.system("clear")
    print("\n" + Fore.MAGENTA + "===============================================")
    print(Fore.MAGENTA + "        IDS - Network Interface Seçim Menüsü     ")
    print(Fore.MAGENTA + "===============================================\n")
    for idx, iface in enumerate(interfaces, start=1):
        print(Fore.CYAN + f" {idx}) {iface}")
    print(Fore.YELLOW + "\n 0) Otomatik Seç (Önerilir)")
    print(Fore.RED + " q) Çıkış\n")
    print(Fore.MAGENTA + "Seçiminizi yapın (0 - {}):".format(len(interfaces)))

def select_interface_menu() -> Optional[str]:
    interfaces = get_interfaces()
    while True:
        print_interface_menu(interfaces)
        choice = input(Fore.GREEN + "\nSeçiminiz: ").strip().lower()
        if choice == "q":
            print(Fore.YELLOW + "Çıkış yapılıyor.")
            return None
        if choice == "0":
            for iface in interfaces:
                if iface != "lo":
                    print(Fore.GREEN + f"[+] Otomatik seçilen arayüz: {iface}")
                    time.sleep(0.8)
                    return iface
            print(Fore.GREEN + f"[+] Otomatik moda düştü: {interfaces[0]}")
            return interfaces[0]
        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(interfaces):
                selected = interfaces[num - 1]
                print(Fore.GREEN + f"[+] Seçilen arayüz: {selected}")
                time.sleep(0.6)
                return selected
        print(Fore.RED + "[!] Geçersiz seçim, tekrar deneyin.")
        time.sleep(0.6)

# -------------------- SIGNAL HANDLING --------------------
def signal_handler(sig, frame):
    print(Fore.YELLOW + "\nSignal received, shutting down...")
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# -------------------- MAIN --------------------
def print_banner():
    os.system("clear")
    print(Fore.MAGENTA + "========================================")
    print(Fore.MAGENTA + "     MINI IDS - Profesyonel Eğitim Sürümü")
    print(Fore.MAGENTA + "========================================")
    print(Fore.CYAN + f"Started: {datetime.now().isoformat()}")
    print(Fore.YELLOW + "Not: Otomatik ban default kapalı. Açmak için menu içinden ayarla.")
    print()

def main():
    if os.geteuid() != 0:
        print(Fore.YELLOW + "Uyarı: Paket sniffing ve iptables root yetkisi gerektirir. 'sudo' ile çalıştırın.")
        # Continue anyway; user may still run but sniff may be limited.

    print_banner()

    iface = select_interface_menu()
    if iface is None:
        print(Fore.YELLOW + "Kullanıcı çıkışı. Program sonlanıyor.")
        sys.exit(0)

    # show config summary and ask to toggle autoban
    print(Fore.CYAN + "\n===== Konfigürasyon Özeti =====")
    print(Fore.CYAN + f"Ara yüz: {iface}")
    print(Fore.CYAN + f"Otomatik ban (autoban): {CONFIG['enable_autoban']}")
    print(Fore.CYAN + f"Ban süresi (s): {CONFIG['ban_duration_seconds']}")
    print(Fore.CYAN + f"Dos threshold (pkt/{CONFIG['window_seconds']}s): {CONFIG['dos_threshold']}")
    print(Fore.CYAN + "===============================\n")
    choice = input(Fore.YELLOW + "Autoban açmak istiyor musunuz? (y/N): ").strip().lower()
    if choice == "y":
        CONFIG["enable_autoban"] = True
        print(Fore.GREEN + "Autoban etkinleştirildi.")
    else:
        print(Fore.YELLOW + "Autoban kapalı şekilde devam edilecek.")

    # Start ban manager thread (always start to manage dict cleanup even if autoban disabled)
    ban_thread = threading.Thread(target=ban_manager_loop, daemon=True)
    ban_thread.start()

    # Start sniff thread
    sniff_thread = threading.Thread(target=sniff_worker, args=(iface,), daemon=True)
    sniff_thread.start()

    # Stats printer thread
    stats_thread = None
    if CONFIG["print_periodic_stats"]:
        stats_thread = threading.Thread(target=stats_printer_loop, daemon=True)
        stats_thread.start()

    log_event("INFO", f"IDS started on iface={iface}", {"iface": iface, "autoban": CONFIG["enable_autoban"]})
    print(Fore.GREEN + "[+] IDS dinlemede. Çıkmak için CTRL+C veya menüden çıkış yapın.")

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()

    # graceful shutdown
    print(Fore.CYAN + "Kapanış: Threadler bekleniyor...")
    log_event("INFO", "Shutdown requested")
    sniff_thread.join(timeout=2)
    ban_thread.join(timeout=2)
    if stats_thread:
        stats_thread.join(timeout=1)

    # summary
    elapsed = time.time() - start_time
    print(Fore.CYAN + "\n===== Final Summary =====")
    print(Fore.CYAN + f"Uptime: {timedelta(seconds=int(elapsed))}")
    print(Fore.CYAN + f"Total packets processed: {stat_counter.get('total_packets',0)}")
    print(Fore.CYAN + f"Alerts: dos={stat_counter.get('dos_alerts',0)}, syn={stat_counter.get('syn_floods',0)}, icmp={stat_counter.get('icmp_floods',0)}, scans={stat_counter.get('port_scans',0)}")
    print(Fore.CYAN + f"Logs: {TEXT_LOG_PATH} {JSON_LOG_PATH or ''}")
    log_event("INFO", "IDS stopped")
    time.sleep(0.2)

if __name__ == "__main__":
    main()