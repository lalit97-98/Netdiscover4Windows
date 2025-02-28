from scapy.all import ARP, Ether, srp
import sys
import requests

# Function to fetch the vendor from the MAC address using the macvendors.co API
def get_vendor(mac_address):
    try:
        # Call macvendors API with the MAC address
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text.strip()  # Return the vendor name
        else:
            return "Unknown"  # If no vendor found, return "Unknown"
    except requests.RequestException:
        return "Unknown"  # Return "Unknown" if the API request fails

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

def network_discovery(target_ip):
    print("Starting Network Discovery...")

    # Craft the ARP request packet
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the packet and capture the response
    print("Scanning network for devices...")
    ans, _ = srp(arp_request_broadcast, timeout=2, verbose=True)

    # Print headers for the table with the 3rd column: Vendor
    print("\nIP Address\tMAC Address\t\tVendor")
    print("-----------------------------------------------")

    # Iterate through the responses and display IP, MAC, and Vendor
    for sent, received in ans:
        mac_address = received.hwsrc
        vendor = get_vendor(mac_address)  # Get vendor from MAC address
        print(f"{received.psrc}\t{mac_address}\t{vendor}")

def main():
    print_ascii_art()  # Print ASCII Art at the start of the execution
    
    if len(sys.argv) != 2:
        print("\nUsage  : python3 netdiscover.py <target_subnet>" "\n\n\t\t===OR===\n" "\nExample: netdiscover.py 192.168.0.0/24")
        input("\nPress Enter to exit...")  # Wait for user input before closing
        sys.exit(1)
    
    target_subnet = sys.argv[1]
    network_discovery(target_subnet)

    # Add a pause here so that the terminal window stays open after the script finishes
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
