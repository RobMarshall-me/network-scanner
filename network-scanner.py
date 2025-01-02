from scapy.all import ARP, Ether, srp, IP, TCP, ICMP, sr1
import time
import threading
import sys
import openpyxl
import itertools


def scan(ip_range):
    """
    Scans the network for devices and attempts to determine their OS.

    Args:
        ip_range: The IP range to scan in CIDR notation (e.g., 192.168.1.0/24).
    """

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        os = get_os(ip)  # This is where the "thinking" happens
        client_dict = {"ip": ip, "mac": mac, "os": os}
        clients_list.append(client_dict)

    return clients_list


def animate(stop_event):
    """Animates a "thinking" wheel in the terminal.

    Args:
        stop_event: A threading.Event object to signal the animation to stop.
    """
    for c in itertools.cycle(["|", "/", "-", "\\"]):
        if stop_event.is_set():
            break  # Exit the loop if the stop event is set
        sys.stdout.write("\rScanning " + c)
        sys.stdout.flush()
        time.sleep(0.1)


def get_os(ip):
    """
    Attempts to determine the OS of a device based on its TCP/IP stack responses.

    Args:
        ip: The IP address of the device.
    """

    try:
        # TCP SYN Scan with MSS option
        pkt = IP(dst=ip) / TCP(dport=80, flags="S", options=[("MSS", 1460)])
        response = sr1(pkt, timeout=1, verbose=False)

        if response is None:
            return "Unknown (No response)"

        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN+ACK
                if response.getlayer(IP).ttl <= 64:
                    return "Linux/Unix (TTL)"
                else:
                    return "Windows (TTL)"
            elif response.getlayer(TCP).flags == 0x14:  # RST
                return "Unknown (RST)"

        # ICMP Echo Request (Ping)
        ping = IP(dst=ip) / ICMP()
        reply = sr1(ping, timeout=1, verbose=False)

        if reply is None:
            return "Unknown (No ping reply)"

        if reply.haslayer(ICMP):
            if reply.getlayer(ICMP).type == 0 and reply.getlayer(ICMP).code == 0:
                # Check for specific ICMP response patterns for different OS
                if reply.getlayer(IP).ttl == 64:
                    return "Linux/Unix (Ping TTL)"
                elif reply.getlayer(IP).ttl == 128:
                    return "Windows (Ping TTL)"
                else:
                    return "Unknown (ICMP Echo Reply)"

    except Exception:
        return "Unknown (Error)"

    return "Unknown"


def save_to_excel(results_list, filename="scan_results.xlsx"):
    """Saves the scan results to an Excel file.

    Args:
        results_list: A list of dictionaries containing device IP, MAC, and OS.
        filename: The name of the Excel file to save the results to.
    """

    try:
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "Network Scan Results"

        # Add headers
        sheet.append(["IP Address", "MAC Address", "Operating System"])

        # Add data rows
        for result in results_list:
            sheet.append([result["ip"], result["mac"], result["os"]])

        workbook.save(filename)
        print(f"Scan results saved to {filename}")

    except Exception as e:
        print(f"Error saving to Excel: {e}")


def print_results(results_list):
    """Prints the scan results in a formatted table.

    Args:
        results_list: A list of dictionaries containing device IP, MAC, and OS.
    """

    print(
        "IP\t\t\tMAC Address\t\tOS\n-----------------------------------------------------"
    )
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t" + client["os"])


if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ").strip()
    if not ip_range:
        ip_range = "192.168.1.0/24"

    # Create a threading.Event object to signal the animation to stop
    stop_event = threading.Event()

    # Start the animation in a separate thread
    animation_thread = threading.Thread(target=animate, args=(stop_event,))
    animation_thread.start()

    scan_results = scan(ip_range)  # Perform the scan

    # Signal the animation thread to stop
    stop_event.set()

    # Wait for the animation thread to finish (optional)
    animation_thread.join()

    # Clear the animation and print "Done!"
    sys.stdout.write("\rDone!     \n")

    print_results(scan_results)
    save_to_excel(scan_results)
