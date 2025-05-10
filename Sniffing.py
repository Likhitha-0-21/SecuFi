from scapy.all import sniff, ARP
import socket
import subprocess

# Define constants
GOOGLE_DNS = "8.8.8.8"
SNIFF_TIMEOUT = 30  # Reduce sniffing time

# Store detected MAC and IP addresses (use sets to avoid duplicates)
mac_ip_table = {}
sniffing_detected = False

def get_ip_address():
    """Get the device's IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((GOOGLE_DNS, 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return f"Unable to get IP Address: {e}"

def get_mac_address(interface):
    """Get the device's MAC address."""
    try:
        output = subprocess.run(["getmac", "/V", "/FO", "TABLE"], capture_output=True, text=True, shell=True)
        lines = output.stdout.split("\n")
        for line in lines:
            if interface in line:
                parts = line.split()
                return parts[-2]  # Extract MAC address
        return "MAC Address not found"
    except Exception as e:
        return f"Unable to get MAC Address: {e}"

def detect_sniffing(packet):
    """Detect sniffing using ARP packets (Prevent Duplicate Entries)."""
    global sniffing_detected
    if packet.haslayer(ARP):
        mac = packet.hwsrc  # MAC Address of sender
        ip = packet.psrc  # IP Address of sender

        # Avoid duplicates by using a set
        if ip not in mac_ip_table:
            mac_ip_table[ip] = set()
        
        # Only print if a new MAC is detected for an existing IP
        if mac not in mac_ip_table[ip]:
            mac_ip_table[ip].add(mac)
            print(f" Detected: IP {ip} is using MAC {mac}")

        # Detect MAC Address Change (Possible Sniffing)
        if len(mac_ip_table[ip]) > 1 and not sniffing_detected:
            print(f" Possible Sniffing Detected! IP {ip} has multiple MACs: {', '.join(mac_ip_table[ip])}")
            sniffing_detected = True

def start_sniffing(interface):
    """Start packet sniffing for a limited time."""
    print(f" Sniffing started on {interface}...")
    try:
        sniff(iface=interface, filter="arp", prn=detect_sniffing, store=0, timeout=SNIFF_TIMEOUT)
    except Exception as e:
        print(f" Sniffing error: {e}")

def get_interface():
    """Detect the active network interface on Windows."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True
        )
        interface = output.stdout.strip()
        if interface:
            print(f" Detected Interface: {interface}")
            return interface
        else:
            print(" No suitable network interface detected")
            return None
    except Exception as e:
        print(f" Error detecting interface: {e}")
        return None

if __name__ == "__main__":
    interface = get_interface()
    if interface:
        ip = get_ip_address()
        mac = get_mac_address(interface)
        print(f" Device IP Address: {ip}")
        print(f" Device MAC Address: {mac}")
        print("-----------------------------------")
        start_sniffing(interface)

        print("\nSniffing Completed.")
        print("MAC and IP Table (Final Report):")
        if mac_ip_table:
            for ip, macs in mac_ip_table.items():
                print(f"{ip} => {', '.join(macs)}")
        else:
            print("No ARP packets captured!")

        if sniffing_detected:
            print("Sniffing Attack Detected at the end of the scan")
        else:
            print("No Sniffing Attack Detected")