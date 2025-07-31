# core/ani_network.py
import threading
import queue
import requests
import socket
import platform
import subprocess
import time
import ipaddress
import binascii
import os
import re
import ssl
import certifi
import random # For random source port in packet crafting

# Scapy specific imports
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, sr1, conf, get_if_list, get_if_addr, Packet, traceroute, srp, send
from scapy.error import Scapy_Exception
from scapy.utils import hexdump
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP # Basic HTTP dissection (requires scapy[http] or scapy-http)

# DNS specific imports
import dns.resolver
import dns.reversename

# WHOIS specific import
_whois_module_available = False
try:
    import whois
    _whois_module_available = True
except ImportError:
    whois = None
    print("Warning: 'python-whois' library not found. WHOIS functionality will be disabled.")

# Folium for map visualization
_folium_available = False
try:
    import folium
    _folium_available = True
except ImportError:
    folium = None
    print("Warning: 'folium' library not found. Map visualization will be disabled.")

# Netifaces for more detailed interface info
_netifaces_available = False
try:
    import netifaces
    _netifaces_available = True
except ImportError:
    netifaces = None
    print("Warning: 'netifaces' library not found. Detailed interface info may be limited.")

# Shodan for passive reconnaissance
_shodan_available = False
try:
    import shodan
    _shodan_available = True
except ImportError:
    shodan = None
    print("Warning: 'shodan' library not found. Shodan search functionality will be disabled.")

# requests_html for web scraping/parsing
_requests_html_available = False
try:
    from requests_html import HTMLSession
    _requests_html_available = True
except ImportError:
    HTMLSession = None
    print("Warning: 'requests_html' library not found. Web fingerprinting/Email harvesting may be limited.")


class ANINetwork:
    def __init__(self, output_queue):
        self.output_queue = output_queue
        self.sniff_thread = None
        self.stop_sniffing_event = threading.Event()
        self.ping_stop_event = threading.Event()
        self.scan_stop_event = threading.Event()
        self.traceroute_stop_event = threading.Event()
        self.arp_scan_stop_event = threading.Event()
        self.packet_craft_event = threading.Event()
        self.ip_range_scan_event = threading.Event()
        self.subdomain_enum_event = threading.Event()
        self.email_harvester_event = threading.Event()
        self.web_fingerprint_event = threading.Event()
        self.ssl_analyzer_event = threading.Event()


        self.whois = whois if _whois_module_available else None
        self.folium = folium if _folium_available else None
        self.netifaces = netifaces if _netifaces_available else None
        self.shodan = shodan if _shodan_available else None
        self.html_session = HTMLSession() if _requests_html_available else None

        self._geolocation_cache = {}
        self.ipinfo_api_key = ""
        self.shodan_api_key = ""

        self._sniffer_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'other_packets': 0
        }

        conf.verb = 0
        conf.srtimeout = 2

    # --- API Key Setters ---
    def set_ipinfo_api_key(self, key):
        self.ipinfo_api_key = key.strip()

    def set_shodan_api_key(self, key):
        self.shodan_api_key = key.strip()
        if self.shodan and key:
            try:
                self.shodan_api = shodan.Shodan(key)
                self._put_output("Shodan API key set and initialized.", tag="log")
            except Exception as e:
                self._put_output(f"Failed to initialize Shodan API with provided key: {e}", tag="error")
        elif self.shodan and not key:
            self._put_output("Shodan API key cleared.", tag="log")
        elif not self.shodan:
            self._put_output("Shodan library not available. Shodan features disabled.", tag="log")

    # --- Utility Functions for Inter-thread Communication ---
    def _put_output(self, message, tag=None):
        timestamp = time.strftime("[%H:%M:%S]")
        self.output_queue.put({"message": f"{timestamp} {message}", "tag": tag})

    def _update_progress(self, current, total, tag_prefix):
        if total == 0:
            percent = 0.0
            progress_str = "N/A"
        else:
            percent = (current / total) * 100
            progress_str = f"{current}/{total}"
        self.output_queue.put({"message": f"PROGRESS:{progress_str}:{percent:.1f}", "tag": tag_prefix + "_progress"})

    # --- Interface Management ---
    def get_interface_list(self):
        interfaces = []
        if self.netifaces:
            try:
                for iface_guid in self.netifaces.interfaces():
                    display_name = iface_guid
                    if platform.system() == "Windows":
                        try:
                            ps_cmd = f"(Get-NetAdapter -InterfaceDescription '{iface_guid}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)"
                            result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True, check=False)
                            if result.returncode == 0 and result.stdout.strip():
                                display_name = result.stdout.strip()
                            else:
                                ps_cmd_guid = f"(Get-NetAdapter | Where-Object {{ $_.ifGuid -eq '{iface_guid}' }} | Select-Object -ExpandProperty Name)"
                                result_guid = subprocess.run(['powershell', '-Command', ps_cmd_guid], capture_output=True, text=True, check=False)
                                if result_guid.returncode == 0 and result_guid.stdout.strip():
                                    display_name = result_guid.stdout.strip()

                        except Exception:
                            pass
                    
                    addrs = self.netifaces.ifaddresses(iface_guid)
                    if self.netifaces.AF_INET in addrs:
                        ip_info = addrs[self.netifaces.AF_INET][0]
                        ip_addr = ip_info.get('addr')
                        if ip_addr and ip_addr != '127.0.0.1':
                            display_name += f" ({ip_addr})"
                            
                    interfaces.append(display_name)
                return sorted(list(set(interfaces)))
            except Exception as e:
                self._put_output(f"Error using netifaces to list interfaces: {e}", tag="error")
                return get_if_list()
        else:
            self._put_output("Warning: 'netifaces' not available for friendly interface names. Falling back to basic names.", tag="log")
            return get_if_list()

    def get_interface_details(self, interface_name):
        details = {}
        if self.netifaces:
            try:
                if "(" in interface_name and ")" in interface_name:
                    original_name = interface_name.split('(')[0].strip()
                else:
                    original_name = interface_name

                actual_iface_name = original_name
                if platform.system() == "Windows":
                     try:
                        ps_cmd = f"(Get-NetAdapter -Name '{original_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifGuid)"
                        result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True, check=False)
                        if result.returncode == 0 and result.stdout.strip():
                            actual_iface_name = result.stdout.strip()
                     except Exception:
                         pass

                addrs = self.netifaces.ifaddresses(actual_iface_name)
                
                if self.netifaces.AF_INET in addrs:
                    ip_info = addrs[self.netifaces.AF_INET][0]
                    details['IPv4 Address'] = ip_info.get('addr')
                    details['Netmask'] = ip_info.get('netmask')
                    details['Broadcast'] = ip_info.get('broadcast')
                
                if self.netifaces.AF_INET6 in addrs:
                    ipv6_info = addrs[self.netifaces.AF_INET6][0]
                    details['IPv6 Address'] = ipv6_info.get('addr')
                
                if self.netifaces.AF_LINK in addrs:
                    mac_info = addrs[self.netifaces.AF_LINK][0]
                    details['MAC Address'] = mac_info.get('addr')
                
                gws = self.netifaces.gateways()
                if 'default' in gws and self.netifaces.AF_INET in gws['default']:
                    details['Default Gateway'] = gws['default'][self.netifaces.AF_INET][0]
                
                details['Status'] = "Up" if details.get('IPv4 Address') or details.get('IPv6 Address') else "Down/No IP"

            except Exception as e:
                details['Error'] = f"Could not get details: {e}. Ensure interface is active or you have permissions."
        else:
            details['Error'] = "'netifaces' not available. Cannot fetch detailed info."
        return details


    # --- IP Sniffer ---
    def _packet_callback(self, packet, include_hex_dump=False):
        if self.stop_sniffing_event.is_set():
            return

        self._sniffer_stats['total_packets'] += 1
        info_lines = []
        try:
            info_lines.append(f"Packet #{self._sniffer_stats['total_packets']} - Received at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

            if packet.haslayer(Ether):
                ether_layer = packet[Ether]
                info_lines.append(f"  MAC: {ether_layer.src} -> {ether_layer.dst} (Type: {hex(ether_layer.type)})")

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info_lines.append(f"  IP: {ip_layer.src} -> {ip_layer.dst} (TTL: {ip_layer.ttl}, ID: {ip_layer.id})")
                
                proto_name = {
                    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
                    51: "AH", 132: "SCTP", 58: "ICMPv6"
                }.get(ip_layer.proto, f"Proto:{ip_layer.proto}")
                info_lines.append(f"  Protocol: {proto_name}, Total Length: {len(packet)} bytes")

                if packet.haslayer(TCP):
                    self._sniffer_stats['tcp_packets'] += 1
                    tcp_layer = packet[TCP]
                    info_lines.append(f"  TCP Ports: {tcp_layer.sport} -> {tcp_layer.dport} (Flags: {tcp_layer.flags})")
                    info_lines.append(f"  Seq: {tcp_layer.seq}, Ack: {tcp_layer.ack}, Win: {tcp_layer.window}")
                    if packet.haslayer(HTTP.HTTPRequest):
                        http_req = packet[HTTP.HTTPRequest]
                        info_lines.append(f"  HTTP Request: {http_req.Method.decode()} {http_req.Path.decode()} Host: {http_req.Host.decode()}")
                        if http_req.Headers:
                            for h_field in http_req.Headers:
                                info_lines.append(f"    Header: {h_field.decode()}")
                    elif packet.haslayer(HTTP.HTTPResponse):
                        http_res = packet[HTTP.HTTPResponse]
                        info_lines.append(f"  HTTP Response: {http_res.Status_Code.decode()} {http_res.Reason_Phrase.decode()}")
                    elif hasattr(packet[TCP], 'payload') and bytes(packet[TCP].payload):
                        info_lines.append(f"  TCP Payload (hex): {bytes(packet[TCP].payload)[:50].hex()}...")
                elif packet.haslayer(UDP):
                    self._sniffer_stats['udp_packets'] += 1
                    udp_layer = packet[UDP]
                    info_lines.append(f"  UDP Ports: {udp_layer.sport} -> {udp_layer.dport}")
                    if packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        info_lines.append(f"  DNS ID: {dns_layer.id}, QR: {dns_layer.qr}, Rcode: {dns_layer.rcode}")
                        if dns_layer.qd:
                            info_lines.append("    Questions:")
                            for q in dns_layer.qd:
                                info_lines.append(f"      - {q.qname.decode()} (Type: {q.qtype}, Class: {q.qclass})")
                        if dns_layer.an:
                            info_lines.append("    Answers:")
                            for ans_rec in dns_layer.an:
                                if ans_rec.type == 1:
                                    info_lines.append(f"      - {ans_rec.rrname.decode()} -> {ans_rec.rdata} (A)")
                                elif ans_rec.type == 28:
                                    info_lines.append(f"      - {ans_rec.rrname.decode()} -> {ans_rec.rdata} (AAAA)")
                                elif ans_rec.type == 5:
                                    info_lines.append(f"      - {ans_rec.rrname.decode()} -> {ans_rec.rdata.decode()} (CNAME)")
                                elif ans_rec.type == 15:
                                    info_lines.append(f"      - {ans_rec.rrname.decode()} -> {ans_rec.exchange.decode()} (MX Pref: {ans_rec.preference})")
                                else:
                                     info_lines.append(f"      - {ans_rec.rrname.decode()} (Type: {ans_rec.type})")
                elif packet.haslayer(ICMP):
                    self._sniffer_stats['icmp_packets'] += 1
                    icmp_layer = packet[ICMP]
                    info_lines.append(f"  ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")
            elif packet.haslayer(ARP):
                self._sniffer_stats['arp_packets'] += 1
                arp_layer = packet[ARP]
                info_lines.append(f"  ARP Operation: {arp_layer.op} ({arp_layer.op})")
                info_lines.append(f"  Sender: {arp_layer.psrc} ({arp_layer.hwsrc})")
                info_lines.append(f"  Target: {arp_layer.pdst} ({arp_layer.hwdst})")
            else:
                self._sniffer_stats['other_packets'] += 1
                info_lines.append(f"  Non-IP/ARP Packet (Summary: {packet.summary()})")

            if include_hex_dump:
                try:
                    raw_bytes = bytes(packet)
                    hex_dump_lines = []
                    for i in range(0, len(raw_bytes), 16):
                        chunk = raw_bytes[i:i+16]
                        hex_str = ' '.join(f'{b:02x}' for b in chunk).ljust(48)
                        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        hex_dump_lines.append(f"  {i:04x}  {hex_str}  {ascii_str}")
                    info_lines.append("\n--- Raw Hex Dump ---")
                    info_lines.extend(hex_dump_lines)
                except Exception as e:
                    info_lines.append(f"  Error generating hex dump: {e}")

            self._put_output("\n".join(info_lines) + "\n" + "="*80, tag="sniffer_packet")
            self.output_queue.put({"message": self._sniffer_stats, "tag": "sniffer_stats_update"})
        except Exception as e:
            self._put_output(f"Error processing packet: {e}", tag="error")

    def start_sniffer(self, interface=None, bpf_filter="", include_hex_dump=False):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self._put_output("Sniffer already running.", tag="sniffer_status")
            return

        self.stop_sniffing_event.clear()
        self._sniffer_stats = {
            'total_packets': 0, 'tcp_packets': 0, 'udp_packets': 0,
            'icmp_packets': 0, 'arp_packets': 0, 'other_packets': 0
        }
        self.output_queue.put({"message": self._sniffer_stats, "tag": "sniffer_stats_update"})
        self._put_output("Starting Sniffer...", tag="sniffer_status")
        self.sniff_thread = threading.Thread(target=self._sniff_loop, args=(interface, bpf_filter, include_hex_dump))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff_loop(self, interface, bpf_filter, include_hex_dump):
        try:
            filter_msg = f" with filter '{bpf_filter}'" if bpf_filter else ""
            self._put_output(f"Sniffing on interface: {interface if interface else 'all available'}{filter_msg}", tag="sniffer_status")
            sniff(prn=lambda pkt: self._packet_callback(pkt, include_hex_dump),
                  iface=interface,
                  filter=bpf_filter,
                  stop_filter=lambda x: self.stop_sniffing_event.is_set(),
                  store=0)
        except Scapy_Exception as e:
            self._put_output(f"Sniffing error (Scapy): {e}. (Ensure correct interface and BPF filter. Run with sudo/admin privileges)", tag="error")
        except Exception as e:
            self._put_output(f"Sniffing error: {e}", tag="error")
        finally:
            self._put_output("Sniffer stopped.", tag="sniffer_status")

    def stop_sniffer(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.stop_sniffing_event.set()
        else:
            self._put_output("Sniffer is not running.", tag="sniffer_status")

    # --- IP Geolocation ---
    def _fetch_geolocation_from_api(self, ip_address):
        api_url = f"https://ipinfo.io/{ip_address}/json"
        if self.ipinfo_api_key:
            api_url += f"?token={self.ipinfo_api_key}"
        
        response = requests.get(api_url, timeout=10, verify=certifi.where())
        response.raise_for_status()
        return response.json()

    def get_geolocation(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self._put_output("Invalid IP Address format.", tag="error")
            return

        if ip_address in self._geolocation_cache:
            self._put_output(f"Geolocation for {ip_address} from cache.", tag="geo_status")
            result = self._geolocation_cache[ip_address]
            self._put_output(result, tag="geo_result")
            self._put_output("Geolocation lookup finished (from cache).", tag="geo_status")
            return

        self._put_output(f"Looking up geolocation for {ip_address}...", tag="geo_status")
        threading.Thread(target=self._get_geolocation_thread, args=(ip_address,), daemon=True).start()

    def _get_geolocation_thread(self, ip_address):
        try:
            data = self._fetch_geolocation_from_api(ip_address)

            if 'bogon' in data and data['bogon']:
                result_text = f"IP: {ip_address}\nType: Bogon/Private IP (not publicly routable)"
            else:
                location_info = {
                    "IP": data.get("ip", "N/A"),
                    "Hostname": data.get("hostname", "N/A"),
                    "City": data.get("city", "N/A"),
                    "Region": data.get("region", "N/A"),
                    "Country": f"{data.get('country_name', 'N/A')} ({data.get('country', 'N/A')})",
                    "Location (Lat/Lon)": data.get("loc", "N/A"),
                    "Organization (ISP)": data.get("org", "N/A"),
                    "Postal": data.get("postal", "N/A"),
                    "Timezone": data.get("timezone", "N/A"),
                    "ASN": data.get("asn", "N/A")
                }
                result_text = "\n".join([f"{k}: {v}" for k, v in location_info.items()])
            
            self._geolocation_cache[ip_address] = result_text
            self._put_output(result_text, tag="geo_result")
        except requests.exceptions.Timeout:
            self._put_output("Geolocation request timed out. Check internet connection.", tag="error")
        except requests.exceptions.ConnectionError:
            self._put_output("Geolocation connection error. Check internet connection.", tag="error")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                self._put_output(f"HTTP Error 429: Too Many Requests. You've hit the API rate limit for ipinfo.io. Try again later or consider adding an API key in settings.", tag="error")
            else:
                self._put_output(f"HTTP Error during geolocation: {e.response.status_code} - {e.response.reason}", tag="error")
        except requests.exceptions.RequestException as e:
            self._put_output(f"Error fetching geolocation: {e}", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error occurred during geolocation: {e}", tag="error")
        finally:
            self._put_output("Geolocation lookup finished.", tag="geo_status")

    # --- Ping Utility ---
    def ping_host(self, host, count=4, timeout=1):
        self._put_output(f"Pinging {host} (count={count}, timeout={timeout}s)...", tag="ping_status")
        threading.Thread(target=self._ping_thread, args=(host, count, timeout), daemon=True).start()

    def _ping_thread(self, host, count, timeout):
        try:
            target_ip = socket.gethostbyname(host)
            self._put_output(f"Resolved {host} to {target_ip}", tag="ping_result")
        except socket.gaierror:
            self._put_output(f"Could not resolve host: {host}. Check hostname or internet connection.", tag="error")
            self._put_output("Ping finished.", tag="ping_status")
            return
        except Exception as e:
            self._put_output(f"Error resolving host: {e}", tag="error")
            self._put_output("Ping finished.", tag="ping_status")
            return

        sent_packets = 0
        received_packets = 0
        rtts = []

        self.ping_stop_event.clear()
        
        ping_id = os.getpid() & 0xFFFF

        for i in range(count):
            if self.ping_stop_event.is_set():
                break
            try:
                packet = IP(dst=target_ip)/ICMP(id=ping_id, seq=i+1)
                sent_packets += 1
                start_time = time.time()
                ans, unans = sr1(packet, timeout=timeout, verbose=0, retry=0)
                end_time = time.time()

                if ans and ans.haslayer(ICMP) and ans[ICMP].type == 0 and ans[ICMP].id == ping_id:
                    rtt = (end_time - start_time) * 1000
                    received_packets += 1
                    rtts.append(rtt)
                    self._put_output(f"Reply from {ans[IP].src}: bytes={len(ans)} time={rtt:.2f}ms TTL={ans[IP].ttl}", tag="ping_result")
                else:
                    self._put_output(f"Request timed out for {target_ip} (seq={i+1})", tag="ping_result")
            except Scapy_Exception as e:
                self._put_output(f"Scapy Ping Error: {e}. (Run with sudo/admin privileges)", tag="error")
                break
            except Exception as e:
                self._put_output(f"An unexpected error during ping: {e}", tag="error")
                break
            time.sleep(max(0, 1 - (time.time() - start_time)))

        if not self.ping_stop_event.is_set():
            loss_percent = ((sent_packets - received_packets) / sent_packets) * 100 if sent_packets > 0 else 0
            
            summary = [
                f"\n--- Ping Statistics for {host} ({target_ip}) ---",
                f"Packets: Sent = {sent_packets}, Received = {received_packets}, Lost = {sent_packets - received_packets} ({loss_percent:.1f}% loss)",
            ]
            if received_packets > 0:
                min_rtt = min(rtts)
                max_rtt = max(rtts)
                avg_rtt = sum(rtts) / len(rtts)
                std_dev_rtt = (sum((x - avg_rtt) ** 2 for x in rtts) / len(rtts)) ** 0.5 if len(rtts) > 1 else 0

                summary.append(f"Approximate round trip times in milli-seconds:")
                summary.append(f"    Minimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {avg_rtt:.2f}ms")
                if std_dev_rtt > 0:
                    summary.append(f"    Std Dev = {std_dev_rtt:.2f}ms")
            self._put_output("\n".join(summary), tag="ping_result")
        else:
            self._put_output("Ping stopped by user.", tag="ping_status")
        self._put_output("Ping finished.", tag="ping_status")

    def stop_ping(self):
        self.ping_stop_event.set()

    # --- Port Scanner ---
    def get_service_name(self, port, protocol="tcp"):
        try:
            return socket.getservbyport(port, protocol)
        except OSError:
            return "Unknown"

    def scan_ports(self, target_ip, start_port, end_port, timeout=0.5):
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            self._put_output("Invalid Target IP Address format.", tag="error")
            return

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            self._put_output("Invalid port range. Ports must be between 1 and 65535, and start <= end.", tag="error")
            return
        if not timeout > 0:
            self._put_output("Timeout must be a positive number.", tag="error")
            return

        self._put_output(f"Scanning ports {start_port}-{end_port} on {target_ip} (timeout={timeout}s/port)...", tag="scan_status")
        threading.Thread(target=self._scan_ports_thread, args=(target_ip, start_port, end_port, timeout), daemon=True).start()

    def _scan_ports_thread(self, target_ip, start_port, end_port, timeout):
        open_ports = []
        self.scan_stop_event.clear()
        total_ports = end_port - start_port + 1
        scanned_count = 0

        try:
            for port in range(start_port, end_port + 1):
                if self.scan_stop_event.is_set():
                    break

                service_info = "Unknown"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        service_name = self.get_service_name(port)
                        try:
                            if port in [21, 22, 23, 25, 80, 110, 143, 443]:
                                # Attempt banner grabbing (be careful not to hang)
                                sock.send(b"HEAD / HTTP/1.0\r\n\r\n" if port == 80 else b"\n")
                                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip().split('\n')[0]
                                if banner:
                                    service_info = f"{service_name} ({banner})"
                                else:
                                    service_info = service_name
                            else:
                                service_info = service_name
                        except socket.timeout:
                            service_info = f"{service_name} (Timed out during banner grab)"
                        except Exception:
                            service_info = service_name
                        open_ports.append(f"Port {port}: Open ({service_info})")
                    sock.close()
                except socket.error as e:
                    self._put_output(f"Socket error scanning port {port}: {e}", tag="error")
                except Exception as e:
                    self._put_output(f"Error checking port {port}: {e}", tag="error")
                
                scanned_count += 1
                self._update_progress(scanned_count, total_ports, "scan")

            if not self.scan_stop_event.is_set():
                if open_ports:
                    self._put_output("\n--- Open Ports Found ---", tag="scan_result")
                    for p in open_ports:
                        self._put_output(p, tag="scan_result")
                else:
                    self._put_output("No open ports found in the specified range.", tag="scan_result")
        except Exception as e:
            self._put_output(f"Error during port scan: {e}", tag="error")
        finally:
            if self.scan_stop_event.is_set():
                self.output_queue.put({"message": "PROGRESS:0/0:0", "tag": "scan_progress"})
                self._put_output("Port scan stopped by user.", tag="scan_status")
            else:
                self.output_queue.put({"message": "PROGRESS:0/0:0", "tag": "scan_progress"})
                self._put_output("Port scan finished.", tag="scan_status")

    def stop_scan(self):
        self.scan_stop_event.set()

    # --- DNS Lookup ---
    def dns_lookup(self, hostname_or_ip):
        if not hostname_or_ip.strip():
            self._put_output("Input for DNS lookup cannot be empty.", tag="error")
            return

        self._put_output(f"Performing DNS lookup for '{hostname_or_ip}'...", tag="dns_status")
        threading.Thread(target=self._dns_lookup_thread, args=(hostname_or_ip,), daemon=True).start()

    def _dns_lookup_thread(self, hostname_or_ip):
        result = []
        try:
            is_ip = False
            try:
                ipaddress.ip_address(hostname_or_ip)
                is_ip = True
            except ValueError:
                pass

            if is_ip:
                result.append(f"--- Reverse DNS Lookup for {hostname_or_ip} ---")
                try:
                    addr = dns.reversename.from_address(hostname_or_ip)
                    names = dns.resolver.resolve(addr, "PTR")
                    for rdata in names:
                        result.append(f"PTR Record: {rdata.to_text().rstrip('.')}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    result.append(f"No PTR record found.")
                except Exception as e:
                    result.append(f"Reverse DNS Error: {e}")
            else:
                result.append(f"--- Forward DNS Lookup for {hostname_or_ip} ---")
                record_types = ["A", "AAAA", "MX", "CNAME", "NSEC", "NS", "SOA", "TXT", "SRV"]

                for rtype in record_types:
                    try:
                        answers = dns.resolver.resolve(hostname_or_ip, rtype)
                        for rdata in answers:
                            if rtype == "MX":
                                result.append(f"MX Record: {rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                            elif rtype == "TXT":
                                txt_data = ' '.join(s.decode() for s in rdata.strings)
                                result.append(f"TXT Record: {txt_data}")
                            elif rtype == "CNAME":
                                result.append(f"CNAME Record: {rdata.target.to_text().rstrip('.')}")
                            elif rtype == "SOA":
                                result.append(f"SOA Record: {rdata.mname.to_text().rstrip('.')} {rdata.rname.to_text().rstrip('.')}")
                            elif rtype == "SRV":
                                result.append(f"SRV Record: Prio={rdata.priority}, Weight={rdata.weight}, Port={rdata.port}, Target={rdata.target.to_text().rstrip('.')}")
                            else:
                                result.append(f"{rtype} Record: {rdata.to_text()}")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    except Exception as e:
                        result.append(f"Error fetching {rtype} record: {e}")

            if not result:
                result.append("No DNS records found or invalid input.")

            self._put_output("\n".join(result), tag="dns_result")

        except dns.resolver.Timeout:
            self._put_output("DNS lookup timed out. Check DNS server settings or internet connection.", tag="error")
        except Exception as e:
            self._put_output(f"DNS lookup error: {e}", tag="error")
        finally:
            self._put_output("DNS lookup finished.", tag="dns_status")

    # --- WHOIS Lookup ---
    def whois_lookup(self, query):
        if not self.whois:
            self._put_output("WHOIS functionality is disabled. Install 'python-whois' library.", tag="error")
            return
        if not query.strip():
            self._put_output("Input for WHOIS lookup cannot be empty.", tag="error")
            return
        
        # Use a unified tag for Reconnaissance tab output
        self._put_output(f"\n===== WHOIS Lookup for '{query}' =====", tag="recon_output")
        self._put_output(f"Performing WHOIS lookup for '{query}'...", tag="recon_output")
        threading.Thread(target=self._whois_lookup_thread, args=(query,), daemon=True).start()

    def _whois_lookup_thread(self, query):
        try:
            w = self.whois.whois(query)
            
            if w and w.status:
                result_lines = [f"--- WHOIS Information for {query} ---"]
                
                key_order = ['domain_name', 'registrar', 'whois_server', 'updated_date',
                             'creation_date', 'expiration_date', 'name_servers', 'status',
                             'emails', 'org', 'address', 'city', 'state', 'zipcode', 'country']
                
                displayed_keys = set()

                for key in key_order:
                    value = getattr(w, key, None)
                    if value:
                        if isinstance(value, list):
                            value_str = ", ".join(map(str, value))
                        else:
                            value_str = str(value)
                        result_lines.append(f"{key.replace('_', ' ').title()}: {value_str}")
                        displayed_keys.add(key)
                
                if w.text:
                    for line in w.text.splitlines():
                        if ':' in line:
                            key_part, value_part = line.split(':', 1)
                            original_key = key_part.strip().replace(' ', '_').lower()
                            if original_key not in displayed_keys and key_part.strip() not in ['Domain Name', 'Registrar', 'Name Server'] :
                                result_lines.append(f"{key_part.strip()}: {value_part.strip()}")

                self._put_output("\n".join(result_lines), tag="recon_output")
            elif w.text and "no match for" in w.text.lower():
                self._put_output(f"No WHOIS record found for '{query}'.", tag="recon_output")
            else:
                self._put_output(f"WHOIS lookup returned unexpected data for '{query}'. Raw output:\n{w.text}", tag="recon_output")
        except self.whois.parser.WhoisCommandFailed as e:
            self._put_output(f"WHOIS command failed: {e}. Might be an invalid domain/IP or server issue.", tag="error")
        except Exception as e:
            self._put_output(f"Error during WHOIS lookup: {e}", tag="error")
        finally:
            self._put_output("WHOIS lookup finished.", tag="recon_status")

    # --- Traceroute ---
    def traceroute_target(self, target_host, max_hops=30):
        self._put_output(f"Tracerouting to {target_host} (max hops={max_hops})...", tag="traceroute_status")
        threading.Thread(target=self._traceroute_thread, args=(target_host, max_hops), daemon=True).start()

    def _traceroute_thread(self, target_host, max_hops):
        self.traceroute_stop_event.clear()
        try:
            try:
                target_ip = socket.gethostbyname(target_host)
                self._put_output(f"Resolved {target_host} to {target_ip}", tag="traceroute_result")
            except socket.gaierror:
                self._put_output(f"Could not resolve host: {target_host}. Check hostname or internet connection.", tag="error")
                self._put_output("Traceroute finished.", tag="traceroute_status")
                return

            ans, unans = traceroute(target_host, maxttl=max_hops, timeout=1, verbose=0)
            
            hop_coords = []
            
            self._put_output("\n--- Traceroute Results ---", tag="traceroute_result")
            for i, (send_packet, recv_packet) in enumerate(ans):
                if self.traceroute_stop_event.is_set():
                    break
                
                hop_ip = recv_packet.src if recv_packet else "Request timed out."
                rtt = f"{(recv_packet.time - send_packet.time)*1000:.2f}ms" if recv_packet else ""
                
                hop_hostname = hop_ip
                if hop_ip != "Request timed out.":
                    try:
                        hop_hostname = socket.gethostbyaddr(hop_ip)[0]
                    except (socket.herror, socket.gaierror):
                        pass

                self._put_output(f"Hop {i+1:2d}: {hop_ip} ({hop_hostname}) {rtt}", tag="traceroute_result")
                self._update_progress(i + 1, max_hops, "traceroute")

                if hop_ip != "Request timed out." and not ipaddress.ip_address(hop_ip).is_private:
                    try:
                        geo_response = self._fetch_geolocation_from_api(hop_ip)
                        if 'loc' in geo_response and geo_response['loc'] != "N/A":
                            lat, lon = map(float, geo_response['loc'].split(','))
                            hop_coords.append((lat, lon, f"Hop {i+1}: {hop_ip} ({geo_response.get('city', '')}, {geo_response.get('country', '')})"))
                    except Exception as e:
                        pass

            if self.traceroute_stop_event.is_set():
                self._put_output("Traceroute stopped by user.", tag="traceroute_status")
            elif not ans:
                self._put_output("Traceroute failed to reach destination or find any hops.", tag="traceroute_result")
            
            if self.folium and hop_coords:
                map_center = hop_coords[0][0:2]
                m = self.folium.Map(location=map_center, zoom_start=2)

                for lat, lon, popup_text in hop_coords:
                    self.folium.Marker([lat, lon], popup=popup_text).add_to(m)
                
                if len(hop_coords) > 1:
                    line_points = [coord[0:2] for coord in hop_coords]
                    self.folium.PolyLine(line_points, color="blue", weight=2.5, opacity=1).add_to(m)

                map_filename = "traceroute_map.html"
                map_filepath = os.path.join(os.getcwd(), map_filename)
                m.save(map_filepath)
                self._put_output(f"\nMap generated: {map_filepath}", tag="traceroute_result")
                self.output_queue.put({"message": map_filepath, "tag": "open_browser"})


            elif not self.folium:
                self._put_output("\nMap visualization skipped: 'folium' library not found.", tag="traceroute_result")
            elif not hop_coords:
                self._put_output("\nMap visualization skipped: No geographical coordinates found for hops.", tag="traceroute_result")

        except Scapy_Exception as e:
            self._put_output(f"Traceroute error (Scapy): {e}. (Run with sudo/admin privileges)", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during traceroute: {e}", tag="error")
        finally:
            self.output_queue.put({"message": "PROGRESS:0/0:0", "tag": "traceroute_progress"})
            self._put_output("Traceroute finished.", tag="traceroute_status")

    def stop_traceroute(self):
        self.traceroute_stop_event.set()

    # --- Network Discovery (ARP Scan) ---
    def arp_scan_network(self, interface=None, timeout=2):
        self._put_output(f"Starting ARP scan on interface: {interface if interface else 'all'}...", tag="arp_scan_status")
        threading.Thread(target=self._arp_scan_thread, args=(interface, timeout), daemon=True).start()

    def _arp_scan_thread(self, interface, timeout):
        self.arp_scan_stop_event.clear()
        discovered_hosts = []
        try:
            if not interface:
                self._put_output("ARP scan requires a selected interface.", tag="error")
                self._put_output("ARP scan finished.", tag="arp_scan_status")
                return

            if "(" in interface:
                scapy_iface_name = interface.split('(')[0].strip()
            else:
                scapy_iface_name = interface

            iface_ip = get_if_addr(scapy_iface_name)
            if not iface_ip or iface_ip == '0.0.0.0':
                self._put_output(f"Interface '{scapy_iface_name}' has no valid IPv4 address for ARP scan.", tag="error")
                self._put_output("ARP scan finished.", tag="arp_scan_status")
                return
            
            network_prefix = ".".join(iface_ip.split('.')[:3]) + ".0/24"
            self._put_output(f"Scanning local network: {network_prefix} via {scapy_iface_name}", tag="arp_scan_status")

            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_prefix),
                             timeout=timeout, iface=scapy_iface_name, verbose=0, retry=0)
            
            for sent, received in ans:
                if self.arp_scan_stop_event.is_set():
                    break
                discovered_hosts.append({"ip": received.psrc, "mac": received.hwsrc})
                self._put_output(f"Found Host: IP={received.psrc}, MAC={received.hwsrc}", tag="arp_scan_result")
            
            if not self.arp_scan_stop_event.is_set():
                if discovered_hosts:
                    self._put_output("\n--- Discovered Hosts (ARP Scan) ---", tag="arp_scan_result")
                    for host in discovered_hosts:
                        self._put_output(f"IP: {host['ip']}, MAC: {host['mac']}", tag="arp_scan_result")
                else:
                    self._put_output("No active hosts found on the local network via ARP scan.", tag="arp_scan_result")

        except Scapy_Exception as e:
            self._put_output(f"ARP Scan Error (Scapy): {e}. (Run with sudo/admin privileges and ensure valid interface)", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during ARP scan: {e}", tag="error")
        finally:
            if self.arp_scan_stop_event.is_set():
                self._put_output("ARP scan stopped by user.", tag="arp_scan_status")
            else:
                self._put_output("ARP scan finished.", tag="arp_scan_status")

    def stop_arp_scan(self):
        self.arp_scan_stop_event.set()

    # --- IP Range Scanner (Ping Sweep) ---
    def ip_range_scan(self, cidr_range, timeout=0.1, retries=1):
        self._put_output(f"Starting IP Range Scan on {cidr_range}...", tag="ip_range_scan_status")
        threading.Thread(target=self._ip_range_scan_thread, args=(cidr_range, timeout, retries), daemon=True).start()

    def _ip_range_scan_thread(self, cidr_range, timeout, retries):
        self.ip_range_scan_event.clear()
        live_hosts = []
        try:
            network = ipaddress.ip_network(cidr_range, strict=False)
            total_ips = network.num_addresses - 2 # Exclude network and broadcast for usable hosts
            if total_ips < 0: total_ips = network.num_addresses # For /31, /32 ranges

            scanned_count = 0

            self._put_output(f"Pinging {total_ips} IPs in {cidr_range}...", tag="ip_range_scan_result")

            # Iterate over hosts, skipping network and broadcast if they exist
            if total_ips > 0:
                for ip_addr in network.hosts():
                    if self.ip_range_scan_event.is_set():
                        break
                    
                    scanned_count += 1
                    self._update_progress(scanned_count, total_ips, "ip_range_scan")

                    packet = IP(dst=str(ip_addr))/ICMP()
                    try:
                        ans, unans = sr1(packet, timeout=timeout, verbose=0, retry=retries)
                        if ans and ans.haslayer(ICMP) and ans[ICMP].type == 0:
                            live_hosts.append(str(ip_addr))
                            self._put_output(f"Host is UP: {ip_addr}", tag="ip_range_scan_result")
                    except Scapy_Exception:
                        pass
                    except Exception:
                        pass
            else:
                self._put_output("No usable hosts in the specified range (e.g., /31, /32).", tag="ip_range_scan_result")

            if not self.ip_range_scan_event.is_set():
                if live_hosts:
                    self._put_output("\n--- Live Hosts Found (Ping Sweep) ---", tag="ip_range_scan_result")
                    for host in live_hosts:
                        self._put_output(f"Live Host: {host}", tag="ip_range_scan_result")
                else:
                    self._put_output("No live hosts found in the specified range.", tag="ip_range_scan_result")
            
        except ValueError as e:
            self._put_output(f"Invalid CIDR range: {e}. Example: 192.168.1.0/24", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during IP range scan: {e}", tag="error")
        finally:
            if self.ip_range_scan_event.is_set():
                self.output_queue.put({"message": "PROGRESS:0/0:0", "tag": "ip_range_scan_progress"})
                self._put_output("IP Range Scan stopped by user.", tag="ip_range_scan_status")
            else:
                self.output_queue.put({"message": "PROGRESS:0/0:0", "tag": "ip_range_scan_progress"})
                self._put_output("IP Range Scan finished.", tag="ip_range_scan_status")

    def stop_ip_range_scan(self):
        self.ip_range_scan_event.set()

    # --- Packet Crafting and Sending ---
    def send_crafted_packet(self, target_ip, protocol, port, payload):
        self._put_output(f"Crafting and sending {protocol} packet to {target_ip}:{port}...", tag="packet_craft_status")
        threading.Thread(target=self._send_crafted_packet_thread, args=(target_ip, protocol, port, payload), daemon=True).start()

    def _send_crafted_packet_thread(self, target_ip, protocol, port, payload):
        self.packet_craft_event.clear()
        try:
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                self._put_output("Invalid Target IP Address format.", tag="error")
                return

            packet = IP(dst=target_ip)
            if protocol.lower() == "tcp":
                packet /= TCP(dport=int(port), sport=random.randint(1024,65535))/payload.encode('utf-8')
            elif protocol.lower() == "udp":
                packet /= UDP(dport=int(port), sport=random.randint(1024,65535))/payload.encode('utf-8')
            elif protocol.lower() == "icmp":
                packet /= ICMP()/payload.encode('utf-8')
            else:
                self._put_output("Unsupported protocol for crafting. Choose TCP, UDP, or ICMP.", tag="error")
                return
            
            self._put_output(f"Sending packet: {packet.summary()}", tag="packet_craft_result")
            
            send(packet, verbose=0)
            self._put_output("Packet sent successfully. Note: No reply is displayed unless sniffed.", tag="packet_craft_result")

        except Scapy_Exception as e:
            self._put_output(f"Packet crafting/sending error (Scapy): {e}. (Run with sudo/admin privileges)", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during packet crafting: {e}", tag="error")
        finally:
            self._put_output("Packet crafting finished.", tag="packet_craft_status")

    # --- Subnet Calculator ---
    def calculate_subnet(self, ip_cidr):
        self._put_output(f"Calculating subnet for {ip_cidr}...", tag="subnet_status")
        threading.Thread(target=self._calculate_subnet_thread, args=(ip_cidr,), daemon=True).start()

    def _calculate_subnet_thread(self, ip_cidr):
        try:
            net = ipaddress.ip_network(ip_cidr, strict=False)
            
            result_lines = [f"--- Subnet Calculation for {ip_cidr} ---",
                            f"Address Family: IPv{net.version}",
                            f"Network Address: {net.network_address}",
                            f"Netmask: {net.netmask}",
                            f"Wildcard Mask: {net.hostmask}",
                            f"Broadcast Address: {net.broadcast_address}",
                            f"Prefix Length (CIDR): /{net.prefixlen}",
                            f"Total Addresses: {net.num_addresses}",
                            f"Usable Hosts: {net.num_addresses - 2 if net.num_addresses > 1 else 0}",
                            f"Usable Host Range: {net.network_address + 1} - {net.broadcast_address - 1}" if net.num_addresses > 2 else "N/A",
                            f"Is Private: {net.is_private}",
                            f"Is Multicast: {net.is_multicast}",
                            f"Is Global: {net.is_global}",
                            f"Is Loopback: {net.is_loopback}",
                           ]
            self._put_output("\n".join(result_lines), tag="subnet_result")
        except ValueError as e:
            self._put_output(f"Invalid IP/CIDR format: {e}. Example: 192.168.1.0/24 or 10.0.0.1/8", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during subnet calculation: {e}", tag="error")
        finally:
            self._put_output("Subnet calculation finished.", tag="subnet_status")

    # --- Subdomain Enumeration (Passive) ---
    def enumerate_subdomains(self, domain):
        self._put_output(f"\n===== Subdomain Enumeration for '{domain}' =====", tag="recon_output")
        self._put_output(f"Enumerating subdomains for '{domain}'...", tag="recon_output")
        threading.Thread(target=self._enumerate_subdomains_thread, args=(domain,), daemon=True).start()

    def _enumerate_subdomains_thread(self, domain):
        self.subdomain_enum_event.clear()
        found_subdomains = set()
        try:
            self._put_output("  Searching via DNS (common subdomains)...", tag="recon_output")
            try:
                common_subdomains = ["www", "mail", "ftp", "blog", "dev", "test", "admin", "api", "vpn", "webmail", "ns1", "ns2", "autodiscover", "cpanel", "direct", "jira", "docs", "portal", "status", "support"]
                for sub in common_subdomains:
                    if self.subdomain_enum_event.is_set(): break
                    try:
                        res = dns.resolver.resolve(f"{sub}.{domain}", "A")
                        for rdata in res:
                            found_subdomains.add(f"{sub}.{domain} -> {rdata.address}")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    except Exception as e:
                        self._put_output(f"    DNS lookup error for {sub}.{domain}: {e}", tag="error")
            except Exception as e:
                self._put_output(f"  Initial DNS check failed for {domain}: {e}", tag="error")


            self._put_output("  Searching via Certsh.com (Certificate Transparency logs)...", tag="recon_output")
            if self.html_session:
                try:
                    r = self.html_session.get(f"https://crt.sh/?q=%25.{domain}", timeout=15)
                    r.raise_for_status()
                    for link in r.html.find('td', containing=domain):
                        sub_entry = link.text.strip()
                        if sub_entry.endswith(domain) and '*' not in sub_entry:
                            found_subdomains.add(sub_entry)
                    resolved_subdomains = []
                    for sub in found_subdomains:
                        if '->' in sub:
                            resolved_subdomains.append(sub)
                        else:
                            try:
                                ip = socket.gethostbyname(sub)
                                resolved_subdomains.append(f"{sub} -> {ip}")
                            except socket.gaierror:
                                resolved_subdomains.append(f"{sub} -> (No IP found)")
                    found_subdomains = set(resolved_subdomains)

                except requests.exceptions.RequestException as e:
                    self._put_output(f"  Error fetching from Certsh.com: {e}", tag="error")
                except Exception as e:
                    self._put_output(f"  Parsing Certsh.com data failed: {e}", tag="error")
            else:
                self._put_output("  Skipping Certsh.com: 'requests_html' not available.", tag="log")

            if not self.subdomain_enum_event.is_set():
                if found_subdomains:
                    self._put_output("\n--- Found Subdomains ---", tag="recon_output")
                    for sub in sorted(list(found_subdomains)):
                        self._put_output(sub, tag="recon_output")
                else:
                    self._put_output(f"No subdomains found for '{domain}'.", tag="recon_output")
        except Exception as e:
            self._put_output(f"An unexpected error during subdomain enumeration: {e}", tag="error")
        finally:
            if self.subdomain_enum_event.is_set():
                self._put_output("Subdomain enumeration stopped by user.", tag="recon_status")
            else:
                self._put_output("Subdomain enumeration finished.", tag="recon_status")

    def stop_subdomain_enum(self):
        self.subdomain_enum_event.set()

    # --- Email Harvester (Basic, Public Sources) ---
    def harvest_emails(self, domain):
        self._put_output(f"\n===== Email Harvesting for '{domain}' =====", tag="recon_output")
        self._put_output(f"Harvesting emails for '{domain}'...", tag="recon_output")
        threading.Thread(target=self._harvest_emails_thread, args=(domain,), daemon=True).start()

    def _harvest_emails_thread(self, domain):
        self.email_harvester_event.clear()
        found_emails = set()
        try:
            if self.html_session:
                dorks = [
                    f'site:{domain} "email"',
                    f'site:{domain} "contact"',
                    f'site:{domain} intitle:"contact us"',
                    f'site:{domain} inurl:"contact"',
                    f'"{domain}" email'
                ]
                
                email_regex = r"[a-zA-Z0-9._%+-]+@" + re.escape(domain)

                for dork in dorks:
                    if self.email_harvester_event.is_set(): break
                    self._put_output(f"  Searching with dork: '{dork}'...", tag="recon_output")
                    try:
                        r = self.html_session.get(f"https://www.google.com/search?q={dork}", timeout=10)
                        r.raise_for_status()
                        
                        matches = re.findall(email_regex, r.html.html)
                        for match in matches:
                            found_emails.add(match)
                        time.sleep(1)
                    except requests.exceptions.RequestException as e:
                        self._put_output(f"    Error fetching from Google: {e}", tag="error")
                    except Exception as e:
                        self._put_output(f"    Parsing Google results failed: {e}", tag="error")
                
            else:
                self._put_output("  Skipping web search: 'requests_html' not available.", tag="log")

            if not self.email_harvester_event.is_set():
                if found_emails:
                    self._put_output("\n--- Found Email Addresses ---", tag="recon_output")
                    for email in sorted(list(found_emails)):
                        self._put_output(email, tag="recon_output")
                else:
                    self._put_output(f"No email addresses found for '{domain}'.", tag="recon_output")
        except Exception as e:
            self._put_output(f"An unexpected error during email harvesting: {e}", tag="error")
        finally:
            if self.email_harvester_event.is_set():
                self._put_output("Email harvesting stopped by user.", tag="recon_status")
            else:
                self._put_output("Email harvesting finished.", tag="recon_status")

    def stop_email_harvester(self):
        self.email_harvester_event.set()

    # --- Web Server Fingerprinting (Passive) ---
    def web_fingerprint(self, url):
        self._put_output(f"\n===== Web Server Fingerprinting for '{url}' =====", tag="recon_output")
        self._put_output(f"Fingerprinting web server for '{url}'...", tag="recon_output")
        threading.Thread(target=self._web_fingerprint_thread, args=(url,), daemon=True).start()

    def _web_fingerprint_thread(self, url):
        self.web_fingerprint_event.clear()
        try:
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'http://' + url
            
            self._put_output(f"Requesting headers from {url}...", tag="recon_output")
            response = requests.head(url, allow_redirects=True, timeout=10, verify=certifi.where())
            response.raise_for_status()

            headers = response.headers
            fingerprint_info = [f"--- HTTP Headers for {url} ---"]
            for header, value in headers.items():
                fingerprint_info.append(f"{header}: {value}")
            
            fingerprint_info.append("\n--- Inferred Technologies ---")
            
            server_header = headers.get('Server', 'N/A')
            x_powered_by = headers.get('X-Powered-By', 'N/A')
            x_aspnet_version = headers.get('X-AspNet-Version', 'N/A')
            cookie_names = ", ".join([c.name for c in response.cookies]) if response.cookies else "N/A"
            
            fingerprint_info.append(f"Server: {server_header}")
            fingerprint_info.append(f"X-Powered-By: {x_powered_by}")
            fingerprint_info.append(f"X-AspNet-Version: {x_aspnet_version}")
            fingerprint_info.append(f"Set-Cookie Names: {cookie_names}")

            if "Apache" in server_header: fingerprint_info.append("  -> Apache Web Server detected.")
            if "Nginx" in server_header: fingerprint_info.append("  -> Nginx Web Server detected.")
            if "IIS" in server_header: fingerprint_info.append("  -> Microsoft IIS Web Server detected.")
            if "Express" in server_header or "Express" in x_powered_by: fingerprint_info.append("  -> Node.js Express framework detected.")
            if "PHP" in x_powered_by or "PHP" in server_header: fingerprint_info.append("  -> PHP detected.")
            if "ASP.NET" in x_powered_by or x_aspnet_version != 'N/A': fingerprint_info.append("  -> ASP.NET detected.")
            
            if self.html_session: # Attempt to fetch body for more clues if requests_html is available
                try:
                    full_response = self.html_session.get(url, timeout=10, verify=certifi.where())
                    if "wordpress" in full_response.text.lower() or "wp-includes" in full_response.text.lower():
                        fingerprint_info.append("  -> Possible WordPress site (found keywords in page content).")
                except requests.exceptions.RequestException:
                    pass # Ignore if full fetch fails
            
            self._put_output("\n".join(fingerprint_info), tag="recon_output")

        except requests.exceptions.RequestException as e:
            self._put_output(f"Error fetching web server headers: {e}. Check URL or network.", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during web fingerprinting: {e}", tag="error")
        finally:
            self._put_output("Web server fingerprinting finished.", tag="recon_status")

    def stop_web_fingerprint(self):
        self.web_fingerprint_event.set()

    # --- SSL/TLS Certificate Analyzer ---
    def analyze_ssl_cert(self, host, port=443):
        self._put_output(f"\n===== SSL/TLS Certificate Analysis for {host}:{port} =====", tag="recon_output")
        self._put_output(f"Analyzing SSL/TLS certificate for {host}:{port}...", tag="recon_output")
        threading.Thread(target=self._analyze_ssl_cert_thread, args=(host, port,), daemon=True).start()

    def _analyze_ssl_cert_thread(self, host, port):
        self.ssl_analyzer_event.clear()
        try:
            ctx = ssl.create_default_context(cafile=certifi.where())
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            
            with ctx.wrap_socket(s, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    self._put_output("Failed to retrieve SSL/TLS certificate.", tag="error")
                    return
                
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.x509.oid import NameOID

                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                result_lines = [f"--- SSL/TLS Certificate Details for {host}:{port} ---"]
                
                subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                result_lines.append(f"Common Name (Subject): {subject_attrs[0].value if subject_attrs else 'N/A'}")
                
                issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                result_lines.append(f"Issuer Common Name: {issuer_attrs[0].value if issuer_attrs else 'N/A'}")
                
                result_lines.append(f"Not Before: {cert.not_valid_before}")
                result_lines.append(f"Not After: {cert.not_valid_after}")
                
                result_lines.append(f"Serial Number: {cert.serial_number:x}")
                result_lines.append(f"Version: {cert.version.name}")

                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    dns_names = san.value.get_values_for_type(x509.DNSName)
                    result_lines.append(f"Subject Alternative Names (SANs): {', '.join(dns_names) if dns_names else 'N/A'}")
                except x509.ExtensionNotFound:
                    result_lines.append("Subject Alternative Names (SANs): N/A (Extension not found)")

                public_key = cert.public_key()
                key_size = public_key.key_size
                key_type = public_key.__class__.__name__.replace('PublicKey', '')
                result_lines.append(f"Public Key Type: {key_type}, Size: {key_size} bits")

                result_lines.append(f"Signature Algorithm: {cert.signature_hash_algorithm.name}")

                try:
                    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                    result_lines.append(f"Is CA Certificate: {basic_constraints.ca}")
                    if basic_constraints.path_length is not None:
                        result_lines.append(f"Path Length Constraint: {basic_constraints.path_length}")
                except x509.ExtensionNotFound:
                    result_lines.append("Basic Constraints: N/A")

                self._put_output("\n".join(result_lines), tag="recon_output") # Use recon_output tag

        except socket.timeout:
            self._put_output(f"Connection to {host}:{port} timed out.", tag="error")
        except ConnectionRefusedError:
            self._put_output(f"Connection to {host}:{port} refused. Port might not be open or SSL/TLS is not active.", tag="error")
        except ssl.SSLError as e:
            self._put_output(f"SSL/TLS Handshake Error: {e}. Check if host supports SSL/TLS or port is correct.", tag="error")
        except Exception as e:
            self._put_output(f"An unexpected error during SSL/TLS analysis: {e}", tag="error")
        finally:
            self._put_output("SSL/TLS Certificate analysis finished.", tag="recon_status")

    def stop_ssl_analyzer(self):
        self.ssl_analyzer_event.set()

    # --- My IP Info ---
    def get_my_ip_info(self):
        self._put_output("Getting my IP information...", tag="myip_status")
        threading.Thread(target=self._get_my_ip_info_thread, daemon=True).start()

    def _get_my_ip_info_thread(self):
        info = []
        try:
            info.append(f"System Hostname: {socket.gethostname()}")

            info.append("\n--- Local Network Interfaces ---")
            if self.netifaces:
                try:
                    for iface_guid in self.netifaces.interfaces():
                        details = self.get_interface_details(iface_guid)
                        if details:
                            info.append(f"  Interface: {iface_guid}")
                            display_name = iface_guid
                            if platform.system() == "Windows":
                                try:
                                    ps_cmd = f"(Get-NetAdapter | Where-Object {{ $_.ifGuid -eq '{iface_guid}' }} | Select-Object -ExpandProperty Name)"
                                    result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True, check=False)
                                    if result.returncode == 0 and result.stdout.strip():
                                        display_name = result.stdout.strip()
                                except Exception:
                                    pass
                            
                            info.append(f"    Friendly Name: {display_name}")

                            for key, value in details.items():
                                info.append(f"    {key}: {value}")
                        else:
                            info.append(f"  Interface: {iface_guid} (No detailed info available)")
                except Exception as e:
                    info.append(f"  Error enumerating local interfaces: {e}")
            else:
                info.append("  'netifaces' not available for detailed local interface info.")
                try:
                    found_basic_ip = False
                    for iface in get_if_list():
                        try:
                            ip_v4 = get_if_addr(iface)
                            if ip_v4 and ip_v4 != '0.0.0.0':
                                info.append(f"  {iface} (IPv4): {ip_v4}")
                                found_basic_ip = True
                        except Scapy_Exception:
                            pass
                    if not found_basic_ip:
                        hostname = socket.gethostname()
                        local_ips = socket.gethostbyname_ex(hostname)[-1]
                        for ip in local_ips:
                            if ipaddress.ip_address(ip).is_private:
                                info.append(f"  Local IP (General): {ip}")
                except Exception as e:
                    info.append(f"  Could not retrieve basic local IPs: {e}")


            info.append("\n--- Public IP Information ---")
            try:
                data = self._fetch_geolocation_from_api("self")
                public_ip = data.get("ip", "N/A")
                city = data.get("city", "N/A")
                region = data.get("region", "N/A")
                country = data.get("country_name", "N/A")
                org = data.get("org", "N/A")
                asn = data.get("asn", "N/A")
                timezone = data.get("timezone", "N/A")
                loc = data.get("loc", "N/A")

                info.append(f"Public IP: {public_ip}")
                info.append(f"Location: {city}, {region}, {country} (Lat/Lon: {loc})")
                info.append(f"Organization: {org} (ASN: {asn})")
                info.append(f"Timezone: {timezone}")
            except requests.exceptions.Timeout:
                info.append("Could not get public IP: Request timed out.")
            except requests.exceptions.ConnectionError:
                info.append("Could not get public IP: Connection error (No internet?).")
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    info.append(f"HTTP Error 429: Too Many Requests for public IP. Consider adding an API key.")
                else:
                    info.append(f"HTTP Error getting public IP: {e.response.status_code} - {e.response.reason}")
            except requests.exceptions.RequestException as e:
                info.append(f"Could not get public IP: {e}")

            self._put_output("\n".join(info), tag="myip_result")

        except Exception as e:
            self._put_output(f"An error occurred getting IP info: {e}", tag="error")
        finally:
            self._put_output("My IP info fetched.", tag="myip_status")