##############################################
##  File scanner.py                         ##
##  sviluppato da: Matteo, Eleonardo,       ##
##               Anthony, Manuel, Alberto   ##
##                                          ##
##  Funzioni implementate                   ##
##                                          ##
##  | Nome func         | Descrizione    |  ##
##  -------------------------------------   ##
##  | get_default_gw    | trova gateway  |  ##
##  | dns_query_to_srv  | DNS a server   |  ##
##  | get_hostname_...  | risolve host   |  ##
##  | get_ttl_by_ping   | TTL via ping   |  ##
##  | analyze_os_by_ttl | stima OS da TTL|  ##
##  | scan_tcp_connect  | scan TCP       |  ##
##  | scan_udp_scapy    | scan UDP       |  ##
##  | scanner_target    | core scanner   |  ##
##                                          ##
##############################################


#Librerie Python
import logging
import socket
import concurrent.futures
import threading
import subprocess
import re
import sys
import os
import ipaddress
from collections import defaultdict
from scapy.all import UDP, ICMP, IP, sr1, RandShort, Conf
from tqdm import tqdm

# Import moduli locali
from .report import init_report, write_result_row, write_footer

# Error Handling
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

stop_event = threading.Event()  
scapy_lock = threading.Lock()   



def get_default_gateway():
    """
    Trova il gateway di default.
    Funziona su Windows e Linux.
    """
    try:
        if os.name == 'nt':  
            
            result = subprocess.run(
                ['route', 'print', '0.0.0.0'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line:
                    parts = line.split()
                    for part in parts:
                        
                        if re.match(r'^(192\.168\.|10\.|172\.)', part):
                            return part
        else:  
            
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except:
        pass
    
    
    return None




def dns_query_to_server(ip, dns_server):
    """
    Esegue una reverse DNS query direttamente a un server DNS specifico.
    Usa il comando nslookup che è disponibile su Windows e Linux.
    """
    try:
        if os.name == 'nt':  
            result = subprocess.run(
                ['nslookup', ip, dns_server],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        else:  # Linux
            result = subprocess.run(
                ['nslookup', ip, dns_server],
                capture_output=True,
                text=True,
                timeout=3
            )
        
        output = result.stdout + result.stderr
        
        
        patterns = [
            r'[Nn]ome[:\s]+(\S+)',      
            r'[Nn]ame[:\s]+(\S+)',       
            r'name\s*=\s*(\S+)',         
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                hostname = match.group(1).strip('.')
                
                if hostname and hostname != ip and not hostname.startswith(dns_server):
                    return hostname
    except:
        pass
    
    return None


def get_hostname_advanced(ip):
    """
    Risolve hostname con fallback:
    1. DNS standard (socket.gethostbyaddr)
    2. NetBIOS query (porta 137)
    3. DNS query diretta al gateway locale
    """
    
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except:
        pass
    
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        
        
        query = (
            b'\x82\x28'  # Transaction ID
            b'\x00\x00'  # Flags: Query
            b'\x00\x01'  # Questions: 1
            b'\x00\x00'  # Answer RRs: 0
            b'\x00\x00'  # Authority RRs: 0
            b'\x00\x00'  # Additional RRs: 0
            b'\x20'      # Nome encoded length (32)
            b'\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
            b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
            b'\x00'      # Nome terminator
            b'\x00\x21'  # Type: NBSTAT
            b'\x00\x01'  # Class: IN
        )
        
        sock.sendto(query, (ip, 137))
        response, _ = sock.recvfrom(1024)
        sock.close()
        
        if len(response) > 57:
            num_names = response[56]
            if num_names > 0:
                name_bytes = response[57:57+15]
                netbios_name = name_bytes.decode('ascii', errors='ignore').strip()
                if netbios_name and len(netbios_name) > 0:
                    return netbios_name
    except:
        pass
    
    
    
    try:
        gateway = get_default_gateway()
        if gateway and gateway != ip:  
            hostname = dns_query_to_server(ip, gateway)
            if hostname:
                return hostname
    except:
        pass
    
    return "?"


def get_ttl_by_ping(ip):
    """
    Esegue ping e estrae il TTL dalla risposta.
    Funziona su Windows e Linux senza privilegi speciali.
    """
    if stop_event.is_set():
        return None
    
    try:
        
        if os.name == 'nt':  
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
             
            ttl_pattern = r'TTL[=:](\d+)'
        else:  # Linux/Mac
            # -c 1 = un solo ping, -W 1 = timeout 1 secondo
            cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            ttl_pattern = r'ttl[=:](\d+)'
        
        
        if os.name == 'nt':
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3
            )
        
        
        output = result.stdout + result.stderr
        match = re.search(ttl_pattern, output, re.IGNORECASE)
        
        if match:
            return int(match.group(1))
            
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    return None


def analyze_os_by_ttl(ttl):
    """
    Stima il sistema operativo basandosi solo sul TTL.
    
    Valori TTL di default:
    - Linux/Unix: 64
    - Windows: 128
    - Cisco/Network devices: 255
    
    I valori ricevuti sono decrementati dai router attraversati,
    quindi usiamo range invece di valori esatti.
    """
    if ttl is None:
        return "Unknown"
    
    try:
        ttl = int(ttl)
    except:
        return "Unknown"
    
    
    if 1 <= ttl <= 64:
        return "Linux/Unix"
    
    
    elif 65 <= ttl <= 128:
        return "Winzoz"
    
    
    elif 129 <= ttl <= 255:
        return "Cisco Router"
    
    return "Unknown"


def scan_tcp_connect(ip, port):
    """
    Connessione TCP standard.
    Non fa più il probe OS (viene fatto una volta per host).
    """
    if stop_event.is_set():
        return None
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                
                return (ip, port, "TCP", "Open", "-", "")
    except:
        pass
    
    return None


def scan_udp_scapy(ip, port):
    """Scansione UDP con Scapy"""
    if stop_event.is_set():
        return None

    try:
        pkt = IP(dst=ip)/UDP(sport=RandShort(), dport=port)
        with scapy_lock:
            resp = sr1(pkt, timeout=2, verbose=0)
        
        if resp is None:
            
            return (ip, port, "UDP", "Open|Filtered", "-", "")
        elif resp.haslayer(UDP):
            
            return (ip, port, "UDP", "Open", "-", "")
        elif resp.haslayer(ICMP):
            
            if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                return None  
            else:
                
                return None  
    except:
        pass
        
    return None


def scanner_target(targets, tcp_ports, udp_ports, target_input, ports_description):
    """
    Funzione principale di scansione.
    Accetta liste separate per porte TCP e UDP.
    """
    stop_event.clear()
    
    has_tcp = len(tcp_ports) > 0
    has_udp = len(udp_ports) > 0
    is_all_ports = len(tcp_ports) > 1000 or len(udp_ports) > 1000
    
    
    if has_tcp and has_udp:
        protocols = ["TCP", "UDP"]
    elif has_tcp:
        protocols = ["TCP"]
    else:
        protocols = ["UDP"]

    print(f"\n[*] Starting scan on {len(targets)} host(s)...")
    print("-" * 80)

    print(f"[*] OS Fingerprinting ({len(targets)} hosts)...")
    
    host_os_map = {}      
    host_ttl_map = {}     
    
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(get_ttl_by_ping, ip): ip for ip in targets}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ttl = future.result(timeout=5)
                host_ttl_map[ip] = ttl
                host_os_map[ip] = analyze_os_by_ttl(ttl)
            except:
                host_os_map[ip] = "Unknown"
    
    print(f"[*] OS Fingerprinting completed.")
    print("-" * 80)

    results_buffer = []

    def format_time(seconds):
        if seconds is None or seconds < 0:
            return "??"
        m, s = divmod(int(seconds), 60)
        return f"{m:02d}:{s:02d}"

    
    if has_tcp:
        tcp_threads = 50 if is_all_ports else 100
        
        print(f"[*] TCP Scan...")
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=tcp_threads)
        futures = []
        
        try:
            for ip in targets:
                for port in tcp_ports:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(scan_tcp_connect, ip, port))
            
            pbar = tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures),
                unit="port",
                ncols=120,
                bar_format="{desc}: {percentage:3.0f}%|{bar:35}| {n_fmt}/{total_fmt} {postfix}"
            )
            pbar.set_description("TCP Scan")
            pbar.set_postfix_str("[Time: 00:00/--:--, ?ports/s | Open: 0]")
            
            for future in pbar:
                if stop_event.is_set():
                    break
                try:
                    res = future.result(timeout=0.1)
                    if res:
                        results_buffer.append(res)
                    
                    elapsed = pbar.format_dict['elapsed']
                    rate = pbar.format_dict['rate']
                    n = pbar.format_dict['n']
                    total = pbar.format_dict['total']
                    
                    if rate and rate > 0:
                        remaining = (total - n) / rate
                        rate_str = f"{rate:.2f}ports/s"
                    else:
                        remaining = None
                        rate_str = "?ports/s"
                    
                    time_str = f"Time: {format_time(elapsed)}/{format_time(remaining)}"
                    pbar.set_postfix_str(f"[{time_str}, {rate_str} | Open: {len(results_buffer)}]")
                    
                except:
                    pass
            pbar.close()
            executor.shutdown(wait=True)
                    
        except KeyboardInterrupt:
            stop_event.set()
            pbar.close()
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit()

    
    if has_udp:
        udp_threads = 20
        
        tcp_open_count = len(results_buffer)
        
        print(f"[*] UDP Scan...")
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=udp_threads)
        futures = []
        
        try:
            for ip in targets:
                for port in udp_ports:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(scan_udp_scapy, ip, port))
            
            pbar = tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures),
                unit="port",
                ncols=120,
                bar_format="{desc}: {percentage:3.0f}%|{bar:35}| {n_fmt}/{total_fmt} {postfix}"
            )
            pbar.set_description("UDP Scan")
            pbar.set_postfix_str("[Time: 00:00/--:--, ?ports/s | Open: 0]")
            
            for future in pbar:
                if stop_event.is_set():
                    break
                try:
                    res = future.result(timeout=0.1)
                    if res:
                        results_buffer.append(res)
                    
                    elapsed = pbar.format_dict['elapsed']
                    rate = pbar.format_dict['rate']
                    n = pbar.format_dict['n']
                    total = pbar.format_dict['total']
                    
                    if rate and rate > 0:
                        remaining = (total - n) / rate
                        rate_str = f"{rate:.2f}ports/s"
                    else:
                        remaining = None
                        rate_str = "?ports/s"
                    
                    udp_open = len(results_buffer) - tcp_open_count
                    time_str = f"Time: {format_time(elapsed)}/{format_time(remaining)}"
                    pbar.set_postfix_str(f"[{time_str}, {rate_str} | Open: {udp_open}]")
                    
                except:
                    pass
            pbar.close()
            executor.shutdown(wait=True)
                    
        except KeyboardInterrupt:
            stop_event.set()
            pbar.close()
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit()

    print("\n[!] Scan completed. Generating report...")

    
    
    
    try:
        if results_buffer:
            init_report(target_input, protocols, ports_description)
            
            grouped = defaultdict(list)
            for row in results_buffer:
                grouped[row[0]].append(row)
            
            
            sorted_ips = sorted(grouped.keys(), key=lambda ip: ipaddress.ip_address(ip))

            print(f"\n{'='*100}")
            print(f"  {'IP':<20} {'HOSTNAME':<30} {'PORT':<20} {'STATE':<15} {'OS':<15}")
            print(f"{'='*100}")

            for ip in sorted_ips:
                rows = grouped[ip]
                hostname = get_hostname_advanced(ip)
                
                
                final_os = host_os_map.get(ip, "Unknown")

                rows.sort(key=lambda x: (x[1], x[2]))  
                first_row = True

                for row in rows:
                    _, port, proto, state, _, _ = row
                    port_str = f"{port}/{proto}"
                    
                    if first_row:
                        prefix = "#"
                        first_row = False
                    else:
                        prefix = " "
                    
                    print(f"{prefix} {ip:<20} {hostname:<30} {port_str:<20} {state:<15} {final_os:<15}")
                    write_result_row(prefix, ip, hostname, port_str, state, final_os)

            write_footer()
            print(f"{'='*100}")
            print(f"[*] Results saved to 'analysis.txt'")

        else:
            print(" [!] No open ports found.")
    except KeyboardInterrupt:
        stop_event.set()
        sys.exit()