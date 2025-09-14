#!/usr/bin/env python3
import asyncio
import socket
import ssl
import json
import os
import time
import requests
import threading
import ipaddress
from collections import defaultdict, Counter
from tqdm import tqdm

# Scapy imports
from scapy.all import (
    sniff,
    IP,
    ARP,
    Ether,
    srp,
    traceroute,
    get_if_list,
    get_if_addr,
    TCP,
    UDP,
    DNS,
    DNSRR,
    Raw,
    send,
)

# -----------------------------
# Global State
# -----------------------------
captured_ips = set()
results = {}
ttl_data = {}
mac_data = {}
semaphore = asyncio.Semaphore(2)
port_usage = defaultdict(int)
start_time = None

# -----------------------------
# Detection state & tuning
# -----------------------------
arp_baseline = {}              # ip -> mac
portscan_tracker = {}          # src -> set of (port, timestamp)
syn_counter = Counter()        # src -> count (reset periodically)
dns_records = {}               # qname -> rdata (last seen)
alert_log_path = "alerts.log"

# tuning (conservative defaults for phone-hotspot lab)
PORTSCAN_PORT_THRESHOLD = 20    # unique ports in WINDOW seconds to flag scan
PORTSCAN_WINDOW = 30           # seconds window
SYN_FLOOD_THRESHOLD = 80       # SYN packets per WINDOW to flag DoS
SYN_WINDOW = 5                 # seconds

# -----------------------------
# Utility Functions
# -----------------------------
def guess_os(ttl):
    """Rough OS guess based on TTL value."""
    if ttl >= 255:
        return "Router/IoT"
    elif ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    return "Unknown"


def reverse_dns(ip):
    """Try reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def geoip_lookup(ip):
    """Return 'Local' for private IPs; otherwise query ipapi."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return "Local"
    except Exception:
        pass

    try:
        res = requests.get(f"https://ipapi.co/{ip}/json", timeout=5)
        data = res.json()
        return f"{data.get('city')}, {data.get('country_name')}"
    except Exception:
        return "Unknown"


def get_ssl_info(ip):
    """Fetch SSL certificate details from port 443."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return {
                    "CN": cert.get("subject", [[("", "")]])[0][0][1],
                    "Issuer": cert.get("issuer", [[("", "")]])[0][0][1],
                    "Expiry": cert.get("notAfter"),
                }
    except Exception:
        return {}


async def grab_banner(ip, port):
    """Try grabbing service banner from open ports."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
        await asyncio.sleep(1)
        banner = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return "Unknown"


async def scan_port(ip, port, timeout=1):
    """Check if a port is open by attempting connection."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def scan_host_ports(ip, ports):
    """Scan all given ports on a host and return open ones with banners."""
    open_ports = {}
    tasks = [scan_port(ip, port) for port in ports]

    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Scanning {ip}", leave=False):
        port = await f
        if port:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "unknown"
            banner = await grab_banner(ip, port)
            open_ports[port] = {"service": service, "banner": banner}
            port_usage[port] += 1
    return open_ports


def run_traceroute(ip):
    """Perform traceroute to a given IP."""
    try:
        res, _ = traceroute(ip, maxttl=10, verbose=False)
        return [r[1].src for r in res]
    except Exception:
        return []


def infer_cidr_from_iface(iface):
    """Try to infer /24 CIDR from interface IP. Fallback to common hotspot CIDR."""
    try:
        ip = get_if_addr(iface)
        if ip and ip.count('.') == 3 and not ip.startswith("127."):
            network = ipaddress.ip_network(ip + '/24', strict=False)
            return str(network)
    except Exception:
        pass
    # common Android hotspot fallback
    return "192.168.43.0/24"


# -----------------------------
# Logging / Alerts
# -----------------------------
def log_alert(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(alert_log_path, "a") as af:
            af.write(line + "\n")
    except Exception:
        pass


# -----------------------------
# Detection helpers & cleanup thread
# -----------------------------
def _cleanup_worker():
    while True:
        now = time.time()
        # prune portscan entries older than window
        for src in list(portscan_tracker.keys()):
            entries = portscan_tracker.get(src, set())
            portscan_tracker[src] = { (p,t) for (p,t) in entries if now - t <= PORTSCAN_WINDOW }
            if not portscan_tracker[src]:
                del portscan_tracker[src]
        # reset SYN counters periodically
        syn_counter.clear()
        time.sleep(SYN_WINDOW)

cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True)
cleanup_thread.start()


def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        old = arp_baseline.get(ip)
        if old and old != mac:
            log_alert(f"ARP spoof suspected: {ip} previously {old}, now {mac}")
        arp_baseline[ip] = mac


def detect_portscan(pkt):
    if IP in pkt and pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        dport = pkt[TCP].dport
        now = time.time()
        entries = portscan_tracker.setdefault(src, set())
        entries.add((dport, now))
        unique_ports = {p for (p, _) in entries}
        if len(unique_ports) >= PORTSCAN_PORT_THRESHOLD:
            log_alert(f"Port scan suspected from {src} ({len(unique_ports)} unique ports in last {PORTSCAN_WINDOW}s)")


def detect_syn_flood(pkt):
    if IP in pkt and pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        syn_counter[src] += 1
        if syn_counter[src] >= SYN_FLOOD_THRESHOLD:
            log_alert(f"SYN flood suspected from {src} ({syn_counter[src]} SYNs in last {SYN_WINDOW}s)")


def detect_dns_tamper(pkt):
    # lightweight check for DNS responses
    if pkt.haslayer(UDP) and pkt[UDP].sport == 53 and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
        try:
            qname = pkt[DNS].qd.qname.decode()
            # take first answer rdata for comparison
            an = pkt[DNSRR]
            rdata = None
            try:
                rdata = an.rdata
            except Exception:
                # older scapy versions store differently
                rdata = bytes(an.rdata) if hasattr(an, "rdata") else None
            prev = dns_records.get(qname)
            if prev and prev != rdata:
                log_alert(f"DNS tamper suspected for {qname}: {prev} -> {rdata}")
            dns_records[qname] = rdata
        except Exception:
            pass


# -----------------------------
# Scanning Handler
# -----------------------------
async def handle_ip(ip, ports):
    async with semaphore:
        print(f"\n[SCAN STARTED] {ip}")
        hostname = reverse_dns(ip)
        guessed_os = guess_os(ttl_data.get(ip, 0))
        mac = mac_data.get(ip, "Unknown")
        geo = geoip_lookup(ip) if not ip.startswith("192.168.") else "Local"
        ssl_info = get_ssl_info(ip) if 443 in ports else {}
        traceroute_path = run_traceroute(ip)
        open_ports = await scan_host_ports(ip, ports)

        results[ip] = {
            "hostname": hostname,
            "guessed_os": guessed_os,
            "mac": mac,
            "geoip": geo,
            "ssl": ssl_info,
            "traceroute": traceroute_path,
            "open_ports": open_ports,
        }

        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)

        print(f"[SCAN COMPLETE] {ip}")


# -----------------------------
# Passive Sniffing Mode
# -----------------------------
def passive_sniff(interface, count, ports):
    """Sniff packets and scan discovered IPs."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = set()

    def process_packet(pkt):
        # run detection on every packet (non-blocking quick checks)
        try:
            detect_arp_spoof(pkt)
            detect_portscan(pkt)
            detect_syn_flood(pkt)
            detect_dns_tamper(pkt)
        except Exception:
            pass

        # existing discovery logic
        if IP in pkt:
            for ip in [pkt[IP].src, pkt[IP].dst]:
                if ip not in captured_ips:
                    print(f"[NEW IP FOUND] {ip}")
                    captured_ips.add(ip)
                    try:
                        ttl_data[ip] = pkt[IP].ttl
                    except Exception:
                        ttl_data[ip] = 0
                    task = asyncio.ensure_future(handle_ip(ip, ports))
                    tasks.add(task)

    try:
        sniff(prn=process_packet, iface=interface, filter="ip", store=False, count=count)
    except Exception as e:
        print(f"[!] Sniff failed on interface {interface}: {e}")
        return

    if tasks:
        loop.run_until_complete(asyncio.wait(tasks))


# -----------------------------
# Active ARP Discovery Mode
# -----------------------------
def arp_discovery(interface):
    """Send ARP requests and discover devices on LAN."""
    print(f"[*] Sending ARP requests on {interface}...")
    ip_range = infer_cidr_from_iface(interface)
    print(f"[*] ARP discovery using IP range {ip_range}")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    packet = ether / arp
    try:
        ans, _ = srp(packet, timeout=2, iface=interface, verbose=False)
    except Exception as e:
        print(f"[!] ARP discovery failed on {interface}: {e}")
        return

    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        captured_ips.add(ip)
        mac_data[ip] = mac
        ttl_data[ip] = 64  # assume typical LAN default


# -----------------------------
# Reporting
# -----------------------------
def show_port_trends():
    print("\n[*] Port Activity Trend (most common open ports):")
    for port, count in sorted(port_usage.items(), key=lambda x: x[1], reverse=True):
        print(f"Port {port}: Open on {count} device(s)")


def show_network_map():
    print("\n[*] Network Map (Simplified):")
    for ip, data in results.items():
        print(f"└── {ip} ({data['hostname']}) [{data['mac']}] → {data['guessed_os']}")


# -----------------------------
# Detection-only mode (runs sniff with detectors)
# -----------------------------
def detection_only(interface):
    print("[*] Running detection-only (IDS) on interface:", interface)
    try:
        sniff(prn=lambda p: (detect_arp_spoof(p), detect_portscan(p), detect_syn_flood(p), detect_dns_tamper(p)),
              iface=interface, filter="ip", store=False)
    except Exception as e:
        print(f"[!] Detection sniff failed on {interface}: {e}")


# -----------------------------
# Main Entry
# -----------------------------
def main():
    global start_time

    # show interfaces and pick sensible default
    try:
        ifaces = get_if_list()
    except Exception:
        ifaces = []
    print("Available interfaces:", ifaces)
    default_iface = None
    for i in ifaces:
        if "Loopback" not in i and "Loopback" not in i.lower():
            default_iface = i
            break
    default_iface = default_iface or (ifaces[0] if ifaces else "wlan0")

    mode = input("Choose mode:\n1. Passive Sniffing\n2. Active ARP Discovery\n3. Detection-only (IDS)\n> ").strip()
    interface = input(f"Enter network interface (default={default_iface}): ").strip() or default_iface
    port_range = input("Enter port range to scan (default=20-1024): ").strip()

    if port_range:
        try:
            start_port, end_port = map(int, port_range.split("-"))
            ports = list(range(start_port, end_port + 1))
        except Exception:
            print("[!] Invalid range. Using default 20–1024.")
            ports = list(range(20, 1025))
    else:
        ports = list(range(20, 1025))

    if os.path.exists("scan_results.json"):
        os.remove("scan_results.json")

    start_time = time.time()

    if mode == "1":
        try:
            pkt_count = int(input("Packets to sniff (default=100): ").strip() or "100")
        except Exception:
            pkt_count = 100
        passive_sniff(interface, pkt_count, ports)

    elif mode == "2":
        arp_discovery(interface)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = [handle_ip(ip, ports) for ip in captured_ips]
        if tasks:
            loop.run_until_complete(asyncio.gather(*tasks))
        show_port_trends()
        show_network_map()

    elif mode == "3":
        detection_only(interface)

    else:
        print("[!] Invalid mode selected.")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n[*] SCAN COMPLETE: {len(results)} IPs scanned")
    print(f"[*] Total open ports found: {sum(len(r['open_ports']) for r in results.values())}")
    print(f"[*] Duration: {elapsed} seconds")
    print("[*] Results saved to scan_results.json")


if __name__ == "__main__":
    main()
