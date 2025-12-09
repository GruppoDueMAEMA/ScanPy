#!/usr/bin/env python3

##############################################
##  File main.py                            ##
##  sviluppato da: Matteo, Eleonardo,       ##
##                Anthony, Manuel, Alberto  ##
##                                          ##
##  Funzioni implementate                   ##
##                                          ##
##  | Nome func      | Descrizione       |  ##
##  -------------------------------------   ##
##  | signal_handler | gestisce CTRL+C   |  ##
##  | show_help      | mostra help CLI   |  ##
##  | main           | flusso principale |  ##
##                                          ##
##############################################


import sys
import os
import signal

if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')

# Librerie da libs
from libs.scanner import scanner_target
from libs.network import validate

def signal_handler(sig, frame):
    print("\n\n[!] CTRL+C detected. Exiting...")
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def show_help():
    print(r"""
   NETWORK SCANNER v8.1
   ================================================================================

    USAGE:
    Windows:   python main.py
    Linux:     sudo python3 main.py

    --help     Show this help message

    TARGET FORMATS:
    Single host:  192.168.1.1
    Subnet:       192.168.1.0/24

    PORT FORMATS:
    Single:    80
    Multiple:  22,80,443
    Range:     1-1000

    OUTPUT:
    Results saved to 'analysis.txt'

    Press CTRL+C to stop scan

================================================================================
   
    """)
    sys.exit()



def main():
    
    if len(sys.argv) > 1:
        if sys.argv[1] in ["-h", "--help", "-help"]:
            show_help()

    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(r"""
   _____                 ____             
  / ____|               |  _ \            
 | (___   ___ __ _ _ __ | |_) |_   _      
  \___ \ / __/ _` | '_ \|  __/| | | |     
  ____) | (_| (_| | | | | |   | |_| |     
 |_____/ \___\__,_|_| |_|_|    \__, |     
                                __/ |     
   M.A.E.M.A.       v8.1       |___/      
    """)
    
    
    print("Supported formats: 192.168.1.1, 192.168.1.0/24") 
    target_input = input("Target IP/Subnet > ").strip()
    
    print("\n[*] Validating and discovering hosts...")
    
    hosts = validate(target_input)
    
    if not hosts:
        print("\n[!] No live hosts found. Try running as ROOT or check connection.")
        sys.exit()
        
    print(f"[*] Found {len(hosts)} active host(s).")

    
    print("\nScan Mode:")
    print("1) TCP Scan")
    print("2) UDP Scan")
    print("3) Full Scan (TCP + UDP)")

    while True:
        p_choice = input("Choice [1-3] > ").strip()
        if p_choice in ["1", "2", "3"]:
            break
        print("[!] Invalid choice! Enter a number between 1 and 3.\n")

    
    TOP_TCP = [21, 22, 23, 25, 53, 80, 110, 135, 139, 389, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 27017] 
    TOP_UDP = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353, 11211, 1701, 4789, 33434]

    
    print("\nPort Selection:")
    if p_choice == "1":
        print("1) Top common ports (TCP)")
    elif p_choice == "2":
        print("1) Top common ports (UDP)")
    else:
        print("1) Top common ports (TCP + UDP)")

    print("2) All ports (1-65535)")
    print("3) Custom range")

    while True:
        port_choice = input("Choice [1-3] > ").strip()
        if port_choice in ["1", "2", "3"]:
            break
        print("[!] Invalid choice! Enter a number between 1 and 3.\n")

    
    tcp_ports = []
    udp_ports = []
    ports_description = ""
    
    try:
        
        if port_choice == "1":
            if p_choice == "1":
                tcp_ports = TOP_TCP
                ports_description = "Top common ports (TCP)"
            elif p_choice == "2":
                udp_ports = TOP_UDP
                ports_description = "Top common ports (UDP)"
            else:
                tcp_ports = TOP_TCP
                udp_ports = TOP_UDP
                ports_description = "Top common ports (TCP + UDP)"

        
        elif port_choice == "2":
            all_ports = list(range(1, 65536))
            if p_choice == "1":
                tcp_ports = all_ports
            elif p_choice == "2":
                udp_ports = all_ports
            else:
                tcp_ports = all_ports
                udp_ports = all_ports
            ports_description = "All (1-65535)"

        
        elif port_choice == "3":
            while True:
                ports_input = input("Enter ports (e.g. 22,80,443 or 20-100) > ").strip()
                
                try:
                    custom_ports = []
                    
                    
                    if "," in ports_input:
                        custom_ports = [int(x.strip()) for x in ports_input.split(",")]
                    
                    
                    elif "-" in ports_input:
                        parts = ports_input.split("-")
                        if len(parts) != 2:
                            raise ValueError("Invalid range format")
                        
                        s, e = int(parts[0].strip()), int(parts[1].strip())
                        
                        if s < 0 or e > 65535:
                            raise ValueError("Ports must be between 0-65535")
                        if s >= e:
                            raise ValueError("Start port must be less than end port")
                        
                        custom_ports = list(range(s, e+1))
                    
                    
                    else:
                        custom_ports = [int(ports_input)]
                    
                    
                    for port in custom_ports:
                        if port < 0 or port > 65535:
                            raise ValueError(f"Port {port} is out of range (0-65535)")

                    ports_description = f"Custom ({ports_input})"

                    if p_choice == "1":
                        tcp_ports = custom_ports
                    elif p_choice == "2":
                        udp_ports = custom_ports
                    else:
                        tcp_ports = custom_ports
                        udp_ports = custom_ports
                    
                    break

                except ValueError:
                    print("[!] Try again (valid formats: 80 or 22,80,443 or 20-100)\n")

    except ValueError:
        print("[!] Port format error.")
        sys.exit()

    
    if tcp_ports and udp_ports:
        protocols_display = "['TCP', 'UDP']"
    elif tcp_ports:
        protocols_display = "['TCP']"
    else:
        protocols_display = "['UDP']"
    
    print(f"""
    
    Scan Options:
        Target - {target_input}
        Ports - {ports_description}
        Protocols - {protocols_display} 
        
    
    """)
    
    right = input("Right? (y/n): ").lower().strip()
    if right == "y":
        scanner_target(hosts, tcp_ports, udp_ports, target_input, ports_description)
    elif right == "n":
        main()


if __name__ == "__main__":
    main()