#by @curtthecoder
import nmap
import os

def network_scan(ip):
    """
        Performs a network scan using nmap.
        This scan checks if hosts are up or down.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sP')
        if len(nm.all_hosts()) == 0:
            print(f"No hosts found in network {ip}. This could be due to:")
            print("1. The network is down or unreachable.")
            print("2. The network is not responding to ping requests.")
            print("3. The IP address is incorrect.")
        else:
            for host in nm.all_hosts():
                print(f"Host: {host} is up")
    except nmap.PortScannerError as e:
        print(f"Error: {e}")

def port_scan(ip):
    """
        Performs a port scan using nmap.
        This scan checks if ports are open on the specified host.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sT -Pn')
        if len(nm.all_hosts()) == 0:
            print(f"No open ports found on host {ip}. This could be due to:")
            print("1. The host is down or unreachable.")
            print("2. The host is not responding to TCP requests.")
            print("3. The IP address is incorrect.")
        else:
            for host in nm.all_hosts():
                print(f"Host: {host} has the following open ports:")
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    sorted(lport)
                    for port in lport:
                        print(f"Port: {port} is open")
    except nmap.PortScannerError as e:
        print(f"Error: {e}")

def udp_scan(ip):
    """
        Performs a UDP scan using nmap.
        This scan checks if UDP ports are open on the specified host.
        Note: This scan requires root privileges.
    """
    if os.geteuid() != 0:
        print("This scan requires root privileges")
        return
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='-sU -Pn')
        if len(nm.all_hosts()) == 0:
            print(f"No open UDP ports found on host {ip}. This could be due to:")
            print("1. The host is down or unreachable.")
            print("2. The host is not responding to UDP requests.")
            print("3. The IP address is incorrect.")
        else:
            for host in nm.all_hosts():
                print(f"Host: {host} has the following open UDP ports:")
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    sorted(lport)
                    for port in lport:
                        print(f"Port: {port} is open")
    except nmap.PortScannerError as e:
        print(f"Error: {e}")

def vulns_scan(ip):
    """
        Performs a vulnerability scan using nmap.
        This scan checks for known vulnerabilities on the specified host.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='--script=vuln -Pn')
        if len(nm.all_hosts()) == 0:
            print(f"No vulnerabilities found on host {ip}. This could be due to:")
            print("1. The host is down or unreachable.")
            print("2. The host is not responding to TCP requests.")
            print("3. The IP address is incorrect.")
            return False
        else:
            vulnerabilities_found = False
            for host in nm.all_hosts():
                print(f"Host: {host} has the following vulnerabilities:")
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    sorted(lport)
                    for port in lport:
                        if 'script' in nm[host][proto][port]:
                            if nm[host][proto][port]['script']:
                                vulnerabilities_found = True
                                print(f"Port: {port} has vulnerability: {nm[host][proto][port]['script']}")
                                print(f"Vulnerability output: {nm[host][proto][port]['script']}\n")
            return vulnerabilities_found
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        return False
def ssl_tls_scan(ip):
    """
        Performs an SSL/TLS scan using nmap.
        This scan checks for SSL/TLS encryption on open ports.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments='--script=ssl-enum-ciphers -Pn')
        if len(nm.all_hosts()) == 0:
            print(f"No SSL/TLS encryption found on host {ip}. This could be due to:")
            print("1. The host is down or unreachable.")
            print("2. The host is not responding to SSL/TLS requests.")
            print("3. The IP address is incorrect.")
        else:
            for host in nm.all_hosts():
                print(f"Host: {host} has the following SSL/TLS encryption:")
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    sorted(lport)
                    for port in lport:
                        if 'script' in nm[host][proto][port]:
                            if nm[host][proto][port]['script']:
                                print(f"Port: {port} has SSL/TLS encryption: {nm[host][proto][port]['script']}")
                                print(f"SSL/TLS output: {nm[host][proto][port]['script']}\n")
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
def recon_scan(ip):
    """
        Performs a reconnaissance scan using nmap.
        This scan runs common reconnaissance commands.
    """
    print("Here are some recon commands you can use:")
    print("1. nmap -sP <ip> (Ping scan)")
    print("2. nmap -sT <ip> (TCP scan)")
    print("3. nmap -sU <ip> (UDP scan)")
    choice = input("Do you want to run them automatically? (y/n): ")
    if choice.lower() == 'y':
        network_scan(ip)
        port_scan(ip)
        udp_scan(ip)

def all_scan(ip):
    """
        Performs all scans using nmap.
        This scan runs all scans in one go.
    """
    network_scan(ip)
    port_scan(ip)
    full_scan(ip)
    udp_scan(ip)
    vulns_scan(ip)
    recon_scan(ip)

def scan_list(file_path):
    """
        Performs scans on a list of IP addresses from a file.
    """
    with open(file_path, 'r') as file:
        ip_list = [line.strip() for line in file]

    for ip in ip_list:
        print(f"Scanning {ip}...")
        network_scan(ip)
        port_scan(ip)
        full_scan(ip)
        udp_scan(ip)
        vulns_scan(ip)
        recon_scan(ip)

def main():
    print("Multi-Use Nmap Scanner")
    print("Scans 2-7 will take some time, so just have a cup of coffee and kick your feet up. If you see no error then it's still running")
    print("1. Network Scan - This scan checks if hosts are up or down.")
    print("2. Port Scan - This scan checks if ports are open on the specified host.")
    print("3. UDP Scan - This scan checks if UDP ports are open on the specified host.")
    print("4. Vulns Scan - This scan checks for known vulnerabilities on the specified host.")
    print("5. Recon Scan - This scan runs common reconnaissance commands.")
    print("6. SSL/TLS Scan - This scan identifies the SSL/TLS ciphers supported by the target.")
    print("7. All Scan - This one will take some time, Everything everywhere all at once")
    print("8. Scan List - This will scan an IP from a list - text file")
    print("9. Exit")

    choice = input("Choose a scan type: ")

    if choice == '1':
        ip = input("Enter the IP address: ")
        network_scan(ip)
    elif choice == '2':
        ip = input("Enter the IP address: ")
        port_scan(ip)
    elif choice == '3':
        ip = input("Enter the IP address: ")
        udp_scan(ip)
    elif choice == '4':
        ip = input("Enter the IP address: ")
        vulnerabilities_found = vulns_scan(ip)
        if vulnerabilities_found:
            print(f"Vulnerabilities found on host {ip}")
        else:
            print(f"No vulnerabilities found on host {ip}")
    elif choice == '5':
        ip = input("Enter the IP address: ")
        recon_scan(ip)
    elif choice == '6':
        ip = input("Enter the IP address: ")
        ssl_tls_scan(ip)
    elif choice == '7':
        ip = input("Enter the IP address: ")
        all_scan(ip)
    elif choice == '8':
        file_path = input("Enter the path to the IP list file: ")
        scan_list(file_path)
    elif choice == '9':
        print("Exiting script...")
        exit()
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
