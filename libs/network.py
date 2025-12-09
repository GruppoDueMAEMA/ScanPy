##############################################
##  File network.py                         ##
##  sviluppato da: Matteo, Eleonardo,       ##
##                Anthony, Manuel, Alberto  ##
##                                          ##
##  Funzioni implementate                   ##
##                                          ##
##  | Nome func       | Descrizione      |  ##
##  -------------------------------------   ##
##  | check_host_alive| verifica host up |  ##
##  | discover_hosts  | discovery rete   |  ##
##  | validate        | valida target    |  ##
##                                          ##
##############################################


# Librerie Python
import socket
import ipaddress
import logging
import threading
import sys
import os
import concurrent.futures
from scapy.all import Ether, ARP, srp, Conf
from tqdm import tqdm


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


stop_event = threading.Event()



def check_host_alive(ip_str):
    if stop_event.is_set():
        return None
    
    
    check_ports = [445, 80, 22, 135, 3389, 443, 8080, 53, 139, 21]
    
    for port in check_ports:
        if stop_event.is_set():
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((ip_str, port))
            s.close()
            
            
            if result == 0 or result == 111:
                return ip_str
        except Exception:
            pass
         
    return None




def discover_hosts(network_obj):
    stop_event.clear()
    target_ip = str(network_obj)
    hosts_up = []

    hostname = socket.gethostname()
    my_ip = socket.gethostbyname(hostname)

    
    try:
        is_network = isinstance(network_obj, ipaddress.IPv4Network) and network_obj.num_addresses > 1
    except:
        is_network = False

    print(f"[*] Discovery Phase on {target_ip}...")

    
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0, retry=2)[0]
        
        for sent, received in result:
            hosts_up.append(received.psrc)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        pass

    
    hosts_up = list(set(hosts_up))
    print(f"[*] ARP found {len(hosts_up)} hosts. Deep scanning remaining range...")

    
    if is_network:
        all_ips = [str(ip) for ip in network_obj.hosts()]
        if my_ip in all_ips:
            all_ips.remove(my_ip)
        
        ips_to_scan = [ip for ip in all_ips if ip not in hosts_up]
        
        if ips_to_scan:
            max_workers = 100
            
            def format_time(seconds):
                if seconds is None or seconds == float('inf') or seconds < 0:
                    return "??:??"
                m, s = divmod(int(seconds), 60)
                return f"{m:02d}:{s:02d}"
            
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(check_host_alive, ip): ip for ip in ips_to_scan}
                    
                    pbar = tqdm(
                        total=len(ips_to_scan), 
                        desc="Deep Discovery", 
                        unit="host", 
                        ncols=110,
                        bar_format="{desc}: {percentage:3.0f}%|{bar:40}| {n_fmt}/{total_fmt} {postfix}"
                    )
                    pbar.set_postfix_str("[Time: 00:00/--:--, ?host/s]")
                    
                    for future in concurrent.futures.as_completed(futures):
                        if stop_event.is_set():
                            pbar.close()
                            executor.shutdown(wait=False, cancel_futures=True)
                            os._exit(0)
                        try:
                            res = future.result(timeout=0.5)
                            if res:
                                hosts_up.append(res)
                        except:
                            pass
                        pbar.update(1)
                        
                        
                        elapsed = pbar.format_dict['elapsed']
                        rate = pbar.format_dict['rate']
                        n = pbar.format_dict['n']
                        total = pbar.format_dict['total']
                        
                        if rate and rate > 0:
                            remaining = (total - n) / rate
                            rate_str = f"{rate:.2f}host/s"
                        else:
                            remaining = None
                            rate_str = "?host/s"
                        
                        time_str = f"Time: {format_time(elapsed)}/{format_time(remaining)}"
                        pbar.set_postfix_str(f"[{time_str}, {rate_str}]")
                    
                    pbar.close()
                    
            except KeyboardInterrupt:
                stop_event.set()
                os._exit(0)
    
    elif not hosts_up and not is_network:
        try:
            if check_host_alive(target_ip):
                hosts_up.append(target_ip)
        except KeyboardInterrupt:
            sys.exit(0)

    return sorted(list(set(hosts_up)))


def validate(target_input):
    try:
        if "/" in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            return discover_hosts(network)
        else:
            ipaddress.ip_address(target_input)
            if check_host_alive(target_input):
                return [target_input]
            return discover_hosts(target_input)
    except KeyboardInterrupt:
        sys.exit(0)
    except ValueError:
        print("[!] Invalid Target.")
        return []
