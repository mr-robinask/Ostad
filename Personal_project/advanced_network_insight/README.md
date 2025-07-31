# Advanced Network Insight (ANI) - Ethical Hacking Education Edition

ANI is a Python-based graphical tool designed for educational purposes to explore various network functionalities, with a focus on passive reconnaissance and network analysis techniques used in ethical hacking.

**Disclaimer:** This tool is for educational use only. Always ensure you have explicit permission before scanning, probing, or sniffing networks you do not own or administer. Unauthorized network activity is illegal and unethical. Using this tool for any illicit activity is strictly prohibited. You are solely responsible for your actions.

## Features

* **Modular Architecture:** Organized project structure for better maintainability and extensibility.
* **Persistent Settings:** Saves and loads user preferences for input fields, window size, and position across sessions.
* **Theming Support:** Switch between 'Light' and 'Dark' themes (extendable with custom JSON files).
* **Enhanced IP Sniffer:**
    * Capture and display **detailed network packets**, including parsed HTTP and DNS information.
    * **Live packet count and statistics** (Total, TCP, UDP, ICMP, ARP, Other).
    * Supports **Berkeley Packet Filter (BPF)** syntax for advanced filtering.
    * Option to display **raw hexadecimal packet dumps** for in-depth protocol analysis.
    * **Live refreshing** of available network interfaces with **user-friendly names**.
    * **Search functionality** within the sniffer output for specific text.
* **Advanced IP Geolocation:**
    * Look up approximate geographical information for public IP addresses, including ASN (Autonomous System Number).
    * **In-memory caching** to reduce API calls and prevent rate limiting.
    * Support for **ipinfo.io API keys** for higher rate limits.
    * Robust error handling for API and network issues.
* **Robust Ping Utility:**
    * Test network connectivity and measure latency to a host using Scapy's ICMP implementation.
    * Provides **min, max, average, and standard deviation** of Round-Trip Times (RTTs).
* **Port Scanner:**
    * Identify open TCP ports on a target IP address.
    * Attempts to perform **basic banner grabbing** for common services (e.g., HTTP, SSH, FTP).
    * Displays **real-time scan progress** with a progress bar.
* **Comprehensive DNS Lookup:**
    * Resolve domain names to IP addresses (A, AAAA, MX, CNAME, NS, TXT, SOA, SRV, NSEC records) and perform reverse DNS lookups (IP to hostname).
* **WHOIS Lookup:**
    * Retrieve detailed registration and administrative information for domains and IP addresses. (Requires `python-whois` library).
* **Traceroute Utility:**
    * Visualize the network path (hops) packets take to a destination, showing intermediate routers and their latency.
    * **Generates an HTML map file** using Folium in your current directory, which can be opened in a web browser to visualize hop locations (requires `folium` library and API key for best results).
    * Displays **real-time progress**.
* **Network Discovery (ARP Scan):**
    * Discover active hosts (IP and MAC addresses) on your local network segment using ARP requests.
* **IP Range Scanner (Ping Sweep):**
    * Scan a CIDR IP range (e.g., `192.168.1.0/24`) to find live hosts using ICMP pings.
* **Packet Crafting & Sending:**
    * Educationally **craft and send custom TCP, UDP, or ICMP packets** to a target IP. This demonstrates how packets are built and can be injected. **(Use with extreme caution and only on your own controlled lab network! Misuse is illegal.)**
* **Subnet Calculator:**
    * Calculate network address, broadcast address, usable host range, and other subnet details from an IP and CIDR.
* **Subdomain Enumeration (Passive):**
    * Find subdomains for a given domain using passive techniques (e.g., public DNS queries, Certificate Transparency logs via `crt.sh`).
* **Email Harvester (Basic, Public Sources):**
    * Attempt to find publicly available email addresses associated with a domain by simulating simple Google dorking.
* **Web Server Fingerprinting (Passive):**
    * Attempt to identify web server technologies (e.g., Apache, Nginx, IIS, PHP, ASP.NET) from HTTP headers and basic HTML content analysis.
* **SSL/TLS Certificate Analyzer:**
    * Connect to a host and extract/display detailed information from its SSL/TLS certificate (e.g., Common Name, Issuer, Validity Period, SANs, Public Key details).
* **Detailed "My IP Info":**
    * Display your local network interface IPs (IPv4/IPv6), MAC addresses, default gateway, and your public IP address with associated geographical and ISP details.
* **Improved User Experience (UX):**
    * **Tabbed Interface** for organized functionalities.
    * **Global Application Log:** A dedicated area for status messages, warnings, and errors. Can be cleared or saved to a file.
    * **Tooltips:** Provide helpful hints when hovering over input fields and buttons.
    * **Clear Output Buttons:** Easily clear results in each section.
    * **Enhanced Context Menus:** Right-click to copy selected text or select all text in output areas.
    * **Visual Progress Bars** for Port Scan, Traceroute, and IP Range Scan.
    * **About Dialog:** Basic application information.
    * **Configurable Settings Tab:** Centralized location for application-wide settings like API keys and themes.

## Requirements

* Python 3.x
* The libraries listed in `requirements.txt`:
    * `scapy`
    * `requests`
    * `dnspython`
    * `python-whois` (Optional, but recommended for WHOIS functionality)
    * `folium` (Optional, but recommended for Traceroute map visualization)
    * `netifaces` (Recommended for user-friendly interface names and detailed info)
    * `shodan` (Optional, but recommended for advanced passive reconnaissance)
    * `requests_html` (Optional, but recommended for Subdomain Enum, Email Harvester, Web Fingerprint)

## Installation

1.  **Clone or download this repository:**
    ```bash
    git clone [https://github.com/your-repo/advanced_network_insight.git](https://github.com/your-repo/advanced_network_insight.git) # Replace with your repo URL
    cd advanced_network_insight
    ```
2.  **Install the required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Install Npcap (Windows only):**
    On Windows, `scapy` relies on `Npcap` for packet capturing. Download and install it from the official Npcap website ([https://nmap.org/npcap/](https://nmap.org/npcap/)). It's also typically included when you install Wireshark.

## How to Run

**Important: This application requires Administrator/Root privileges to function correctly, especially for the IP Sniffer, Ping, Traceroute, ARP Scan, and Packet Crafting utilities (which use Scapy's raw sockets).**

* **On Linux/macOS:**
    Open your terminal and run:
    ```bash
    sudo python3 main.py
    ```
    (You will be prompted for your password.)

* **On Windows:**
    1.  Right-click on your Command Prompt or PowerShell icon.
    2.  Select "Run as administrator."
    3.  Navigate to the `advanced_network_insight` directory where `main.py` is located.
    4.  Run:
        ```bash
        python main.py
        ```

## Usage

1.  **Launch the application** as described above.
2.  **Explore the many tabs** for different network utilities. They are categorized for easier navigation.
3.  **Input fields will pre-fill** with values from your last session or sensible defaults.
4.  **Hover over input fields or buttons** for helpful **tooltips**.
5.  **Click action buttons** (e.g., "Start Sniffer", "Lookup IP Location").
6.  **Observe outputs** in the dedicated text areas.
7.  **Monitor the "Application Log"** at the bottom for status updates, warnings, and errors.
8.  **To clear an output area**, click the "Clear Output" button for that section.
9.  **To copy output**, right-click on any text area and select "Copy" or "Select All" then "Copy".
10. **Adjust settings** in the dedicated "Settings" tab. Here you can change themes and **enter API keys** for `ipinfo.io` (for better geolocation limits) and `Shodan.io` (for future passive recon features). Click "Save All Settings" to persist changes.

## Ethical Hacking Context & Disclaimers (Crucial for Education)

This tool provides capabilities common in the "Reconnaissance" and "Scanning" phases of ethical hacking.

* **Passive Reconnaissance:** Features like **DNS Lookup, WHOIS, Subdomain Enumeration, Email Harvester, Web Server Fingerprinting, and SSL/TLS Analyzer** are primarily passive. They gather information from publicly available sources without directly interacting with the target's systems in an intrusive way. This is an essential first step for ethical hackers to understand their target's online footprint.
* **Active Reconnaissance/Scanning:** Features like **Ping, Port Scanner, Traceroute, ARP Scan, and IP Range Scan** involve active network interaction. While this is fundamental for understanding network topology and open services, **it MUST be done only on systems you own or have explicit written permission to test.**
* **Packet Crafting:** This is a powerful educational feature to understand how network packets are formed and transmitted. **Using this to create malicious packets, launch denial-of-service attacks, or exploit vulnerabilities on networks you don't own is illegal and unethical.** Use it strictly for testing on isolated lab environments.

## Troubleshooting

* **"Permission denied" / "Scapy_Exception: Can't open interface":**
    * **Solution:** Ensure you are running the script with **Administrator (Windows) or Root (Linux/macOS) privileges.** This is absolutely essential for network capture and raw socket operations.
    * **Solution:** Verify that `Npcap` is correctly installed on Windows.
* **"No interfaces found" in Sniffer/ARP Scan tabs:**
    * **Solution:** This usually indicates a permissions issue or `scapy`/`netifaces` not being able to detect interfaces. Run as administrator/root.
    * **Action:** Try clicking "Refresh Interfaces" after gaining privileges.
* **"HTTP Error 429: Too Many Requests" for Geolocation/Traceroute:**
    * **Reason:** You've hit the rate limit of the free `ipinfo.io` API.
    * **Solution:** Wait for a while (usually 24 hours).
    * **Long-term Solution:** Go to `ipinfo.io/signup`, get a free API key, and enter it in the "Settings" tab. This significantly increases your rate limit.
* **"[Feature] functionality disabled: [library name] not installed.":**
    * **Solution:** This means a required optional library is not installed. Install it using `pip install [library-name]` (e.g., `pip install python-whois` or `pip install folium`). Check your `requirements.txt` and install all its contents.
* **"Traceroute functionality disabled":**
    * **Solution:** This usually indicates a problem with Scapy's ability to create raw ICMP packets, often due to insufficient permissions. Ensure you are running as administrator/root.
* **Application crashes or freezes:**
    * **Solution:** Ensure all required libraries are installed correctly as per `requirements.txt`.
    * **Solution:** Ensure you have the latest version of Python 3.
    * **Action:** If it persists, report the error with the full traceback from the console.

---

This version of ANI is now a powerful educational tool for aspiring ethical hackers, providing a much richer set of features and data for network reconnaissance and analysis. Remember to always use it wisely and within ethical boundaries. What specific area would you like to dive into next for even more advanced features or deeper explanations?