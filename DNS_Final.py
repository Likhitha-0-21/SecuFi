import os
import socket
import psutil

def get_router_ip():
    gateways = psutil.net_if_addrs()
    for interface, addrs in gateways.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address.startswith("192.168"):
                return addr.address
    return None

def get_dns_servers():
    dns_servers = []
    if os.name == 'nt':
        result = os.popen("ipconfig /all").read()
        found_dns = False
        for line in result.split("\n"):
            if "DNS Servers" in line:
                found_dns = True
            elif found_dns and line.strip() and not line.startswith(" "):
                break
            elif found_dns:
                dns_servers.append(line.strip())
    else:
        result = os.popen("cat /etc/resolv.conf").read()
        for line in result.split("\n"):
            if line.startswith("nameserver"):
                dns_servers.append(line.split()[1])
    return dns_servers

def get_hostname_from_ip(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unknown"
    except Exception as e:
        return f"Error: {e}"

def check_dns_spoofing():
    test_domain = "google.com"
    
    try:
        resolved_ip = socket.gethostbyname(test_domain)
        print(f"Resolved IP for {test_domain}: {resolved_ip}")
        
        hostname = get_hostname_from_ip(resolved_ip)
        print(f"Resolved Hostname: {hostname}")

        if "1e100.net" in hostname:
            print("DNS resolution is safe.")
        else:
            print("Potential DNS spoofing detected! The resolved hostname does not belong to Google.")
    except Exception as e:
        print(f"Error resolving domain: {e}")

def check_router_vulnerability():
    router_ip = get_router_ip()
    
    if not router_ip:
        print("Unable to find the router IP. Are you connected to WiFi?")
        return
    
    print(f"Router IP: {router_ip}")
    
    dns_servers = get_dns_servers()
    print(f"DNS Servers: {dns_servers}")
    
    print("\nChecking for DNS spoofing...")
    check_dns_spoofing()

if __name__ == "__main__":
    check_router_vulnerability()