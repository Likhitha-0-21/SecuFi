import psutil
import socket
import scapy.all as sc

def get_default_interface():
    """Gets the default network interface and local IP address."""
    try:
        # Get all network interfaces and their addresses
        interfaces = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        for interface, addrs in interfaces.items():
            if interface in net_if_stats and net_if_stats[interface].isup:
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4 address
                        return interface, addr.address
        raise RuntimeError("No active network interface found.")
    except Exception as e:
        print(f"Error getting default interface: {e}")
        return None, None

def get_router_ip():
    """Finds the router's IP from the system routing table."""
    try:
        # Get all network gateway information
        gateways = psutil.net_if_addrs()
        route_info = psutil.net_if_stats()

        for interface, addrs in gateways.items():
            if interface in route_info and route_info[interface].isup:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        # Extracts first three octets and assumes .1 as the gateway
                        return addr.address.rsplit(".", 1)[0] + ".1"
        raise RuntimeError("Router IP not found.")
    except Exception as e:
        print(f"Error getting router IP: {e}")
        return None

def get_mac(ip):
    """Gets the MAC address of a given IP using ARP request."""
    try:
        arp_request = sc.ARP(pdst=ip)
        ether = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        ans, _ = sc.srp(packet, timeout=2, verbose=False)

        for _, received in ans:
            return received.hwsrc  # Return the MAC address
    except Exception as e:
        print(f"Error getting MAC address for {ip}: {e}")
    return None

def detect_arp_spoofing(router_ip):
    """Detects ARP spoofing by checking for duplicate MACs in the network."""
    try:
        print("\nScanning for ARP Spoofing...")

        mac_addresses = {}
        subnet = router_ip.rsplit('.', 1)[0] + ".0/24"

        # Send ARP request to entire subnet
        arp_request = sc.ARP(pdst=subnet)
        ether = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        ans, _ = sc.srp(packet, timeout=2, verbose=False)

        for _, received in ans:
            ip, mac = received.psrc, received.hwsrc

            if ip in mac_addresses and mac_addresses[ip] != mac:
                print(f"[ALERT] ARP Spoofing detected! IP {ip} has multiple MACs: {mac_addresses[ip]}, {mac}")
                return True
            mac_addresses[ip] = mac

        print("No ARP spoofing detected.")
        return False
    except Exception as e:
        print(f"Error detecting ARP spoofing: {e}")
        return False

def check_arp_spoofing():
    """Main function to check for ARP spoofing."""
    print("==========================")
    print("    ARP Spoofing Detector ")
    print("==========================")

    interface, local_ip = get_default_interface()
    if not interface or not local_ip:
        print("Failed to determine network interface. Exiting...")
        return

    print(f"[E] Selected Interface: {interface}")
    print(f"Local IP: {local_ip}")

    router_ip = get_router_ip()
    if not router_ip:
        print("Could not determine router IP. Exiting...")
        return

    print(f"Router IP: {router_ip}")

    # Start ARP Spoofing Detection
    if detect_arp_spoofing(router_ip):
         print("ARP Spoofing detected!.")
    else:
         print("Network is safe.")

if __name__ == "__main__":
    check_arp_spoofing()