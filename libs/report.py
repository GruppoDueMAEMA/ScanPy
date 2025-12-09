##############################################
##  File report.py                          ##
##  sviluppato da: Matteo, Eleonardo,       ##
##                 Anthony, Manuel, Alberto ##
##                                          ##
##  Funzioni implementate                   ##
##                                          ##
##  | Nome func       | Descrizione      |  ##
##  -------------------------------------   ##
##  | init_report     | crea header file |  ##
##  | write_result_row| scrive riga porta|  ##
##  | write_footer    | aggiunge timestamp| ##
##                                          ##
##############################################



import datetime


FILE_NAME = "analysis.txt"


def init_report(target, protocols, ports_description):
    try:
        
        if "TCP" in protocols and "UDP" in protocols:
            scan_type = "TCP + UDP"
        elif "UDP" in protocols:
            scan_type = "UDP"
        else:
            scan_type = "TCP"
        
        with open(FILE_NAME, "w") as f:
            f.write(f"[SCAN REPORT - v8.1]\n")
            f.write("=" * 100 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Type: {scan_type}\n")
            f.write(f"Ports: {ports_description}\n")
            f.write("=" * 100 + "\n")
            f.write(f"  {'IP':<20} {'HOSTNAME':<30} {'PORT':<20} {'STATE':<15} {'OS':<15}\n")
            f.write("=" * 100 + "\n")
    except:
        pass



def write_result_row(prefix, ip, hostname, port_str, state, os_sys):
    try:
        with open(FILE_NAME, "a") as f:
            row = f"{prefix} {ip:<20} {hostname:<30} {port_str:<20} {state:<15} {os_sys:<15}\n"
            f.write(row)
    except:
        pass


def write_footer():
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(FILE_NAME, "a") as f:
            f.write("=" * 100 + "\n")
            f.write(f"Timestamp: {ts}\n")
    except:
        pass
