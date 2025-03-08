from scapy.all import ARP, Ether, srp
import sys
import psutil
import argparse
import MACVendors  # Import your MACVendors.py file

# Function to fetch the vendor from the MAC address using the mac_vendors dictionary
def get_vendor(mac_address):
    # Extract the first 6 characters (24-bit prefix) from the MAC address
    prefix = mac_address.replace(":", "")[:6].upper()
    
    # Return the vendor name if found, otherwise "Unknown"
    return MACVendors.mac_vendors.get(prefix, "Unknown")

# ASCII Art for the script introduction
def print_ascii_art():
    ascii_art = """
                          .         .o8   o8o                                                              
                        .o8        "888   `"'                                                              
ooo. .oo.    .ooooo.  .o888oo  .oooo888  oooo   .oooo.o  .ooooo.   .ooooo.  oooo    ooo  .ooooo.  oooo d8b 
`888P"Y88b  d88' `88b   888   d88' `888  `888  d88(  "8 d88' `"Y8 d88' `88b  `88.  .8'  d88' `88b `888""8P 
 888   888  888ooo888   888   888   888   888  `"Y88b.  888       888   888   `88..8'   888ooo888  888     
 888   888  888    .o   888 . 888   888   888  o.  )88b 888   .o8 888   888    `888'    888    .o  888     
o888o o888o `Y8bod8P'   "888" `Y8bod88P" o888o 8""888P' `Y8bod8P' `Y8bod8P'     `8'     `Y8bod8P' d888b    
                                                                                       by Lalit (@M3CA)  
    """
    print(ascii_art)

# Validate the network interface
def is_valid_interface(interface):
    # Get a list of available interfaces
    interfaces = list_friendly_interfaces()
    return interface in interfaces

# Function to get human-readable network interfaces using psutil
def list_friendly_interfaces():
    # List all interfaces and return them in a user-friendly format
    interfaces = psutil.net_if_addrs()
    friendly_interfaces = []
    
    for iface in interfaces:
        # Display only the name of the interface, not the detailed address info
        friendly_interfaces.append(iface)
    
    return friendly_interfaces

def network_discovery(target_ip, iface):
    print(f"Starting Network Discovery on interface {iface}...")

    # Craft the ARP request packet
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the packet and capture the response with a timeout of 5 seconds
    print("Scanning network for devices...")
    ans, _ = srp(arp_request_broadcast, timeout=5, verbose=True, iface=iface)  # Use the user-provided interface

    # Print headers for the table with the 3rd column: Vendor
    print("\nIP Address\tMAC Address\t\tVendor")
    print("-----------------------------------------------")

    # Iterate through the responses and display IP, MAC, and Vendor
    for sent, received in ans:
        mac_address = received.hwsrc
        vendor = get_vendor(mac_address)  # Get vendor from MAC address using the MACVendors.py
        print(f"{received.psrc}\t{mac_address}\t{vendor}")

def main():
    print_ascii_art()  # Print ASCII Art at the start of the execution
    
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Network Discovery Tool")
    
    # Add the target subnet and interface arguments
    parser.add_argument("target_subnet", help="Target subnet to scan (e.g., 192.168.0.0/24)")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0, Wi-Fi)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if the interface was provided
    if not args.interface:
        print("Error: The interface (-i) is required. Please specify the network interface to use.")
        parser.print_help()
        sys.exit(1)
    
    target_subnet = args.target_subnet
    iface = args.interface  # Get the network interface from the command-line arguments
    
    # Validate the interface
    if not is_valid_interface(iface):
        print(f"Error: The interface '{iface}' is not valid. Please provide a valid interface name.")
        print("\nAvailable interfaces:")
        friendly_interfaces = list_friendly_interfaces()  # Get user-friendly interface names
        print(", ".join(friendly_interfaces))  # Print available interfaces in user-friendly format
        input("\nPress Enter to exit...")  # Wait for user input before closing
        sys.exit(1)
    
    network_discovery(target_subnet, iface)

    # Add a pause here so that the terminal window stays open after the script finishes
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
