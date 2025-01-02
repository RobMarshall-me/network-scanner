# Network Scanner
This Python script scans a given IP range for active devices, attempts to determine their operating systems, and displays the results in a formatted table.

## Features
* **Network Scanning:** Discovers active devices on the network using ARP requests.
* **OS Fingerprinting:** Attempts to identify the operating system of each device by analyzing TCP/IP stack responses.
* **Visual Feedback:** Displays a "thinking" animation while the scan is in progress.
* **Formatted Output:** Presents the scan results in a clear and organized table.

## Requirements
* Python 3.10 or higher
* Poetry

## Usage

This project uses Poetry for dependency management. If you don't have Poetry installed, follow the instructions on their website: [https://python-poetry.org/docs/](https://python-poetry.org/docs/)

1. **Clone the repository:** `git clone <repository_url>`
2. **Install dependencies:** `poetry install`
3. **Run the script:** `poetry run python network_scanner.py`
4. **Enter IP range:** When prompted, enter the IP range you want to scan in CIDR notation (e.g., `192.168.1.0/24`). If you press Enter without providing an IP range, the script will scan the default range `192.168.1.0/24`.

The script will then scan the network and display a "thinking" animation while it's working. Once the scan is complete, the results will be printed in a table format, showing the IP address, MAC address, and guessed OS of each discovered device.

## Example Output

```
IP              MAC Address        OS
-----------------------------------------------------
192.168.1.1     aa:bb:cc:dd:ee:ff  Windows (TTL)
192.168.1.10    11:22:33:44:55:66  Linux/Unix (Ping TTL)
192.168.1.100   77:88:99:aa:bb:cc  Unknown (No response)
```

## Notes

* **OS fingerprinting** is not always accurate and can be evaded. This script provides a basic implementation for educational purposes.
* **Running this script may require root privileges or administrator rights**, depending on your network configuration and operating system.
* **Use this script responsibly and ethically**, respecting privacy and security regulations.

## Disclaimer

This script is provided for educational and informational purposes only. The author is not responsible for any misuse or damage caused by this script.

