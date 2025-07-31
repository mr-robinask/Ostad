# gui/ani_main_window.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, Menu, filedialog
import queue
import time
import os
import webbrowser

from core.ani_network import ANINetwork
from core.ani_config import load_settings, save_settings, DEFAULT_SETTINGS, load_theme, get_available_themes
from gui.ani_widgets import ToolTip, CustomScrolledText

class ANIMainWindow:
    def __init__(self, master):
        self.master = master
        self.settings = load_settings()

        self.output_queue = queue.Queue()
        self.ani_network = ANINetwork(self.output_queue)
        self.ani_network.set_ipinfo_api_key(self.settings.get('ipinfo_api_key', ''))
        self.ani_network.set_shodan_api_key(self.settings.get('shodan_api_key', ''))

        self._apply_theme(self.settings.get('current_theme', 'Light'))

        master.title("Advanced Network Insight (ANI) - Ethical Hacking Education Edition")
        master.geometry(f"{self.settings['window_width']}x{self.settings['window_height']}+"
                        f"{self.settings['window_pos_x']}+{self.settings['window_pos_y']}")
        master.minsize(900, 700)

        # Initialize StringVars here so they exist when setup methods are called
        self.interface_var = tk.StringVar(master)
        self.arp_interface_var = tk.StringVar(master)
        self.craft_protocol_var = tk.StringVar(master)
        self.include_hex_dump_var = tk.BooleanVar(master)
        self.sniffer_packet_count_var = tk.StringVar(value="Total: 0")
        self.sniffer_tcp_count_var = tk.StringVar(value="TCP: 0")
        self.sniffer_udp_count_var = tk.StringVar(value="UDP: 0")
        self.sniffer_icmp_count_var = tk.StringVar(value="ICMP: 0")
        self.sniffer_arp_count_var = tk.StringVar(value="ARP: 0")
        self.sniffer_other_count_var = tk.StringVar(value="Other: 0")

        self.scan_progress_var = tk.DoubleVar()
        self.traceroute_progress_var = tk.DoubleVar()
        self.ip_range_scan_progress_var = tk.DoubleVar()

        self._create_widgets()
        self._check_queue()
        self._populate_interfaces()

        self._load_settings_into_gui()

    # --- Theme Management ---
    def _apply_theme(self, theme_name):
        self.current_theme_name = theme_name
        self.style = ttk.Style()
        self.style.theme_use('clam')

        theme_settings = load_theme(theme_name)

        # Configure general styles
        self.style.configure('.', font=('TkDefaultFont', 10), background=theme_settings.get('bg_primary', '#f0f0f0'))
        self.style.configure('TNotebook', background=theme_settings.get('bg_secondary', '#e0e0e0'), borderwidth=0)
        self.style.map('TNotebook.Tab',
            background=[('selected', theme_settings.get('tab_active_bg', '#cccccc')),
                        ('!selected', theme_settings.get('tab_inactive_bg', '#eeeeee'))],
            foreground=[('selected', theme_settings.get('tab_active_fg', '#000000')),
                        ('!selected', theme_settings.get('tab_inactive_fg', '#555555'))],
            font=[('selected', theme_settings.get('tab_font_active', ['TkDefaultFont', 10, 'bold'])),
                  ('!selected', theme_settings.get('tab_font_inactive', ['TkDefaultFont', 10]))]
        )
        self.style.configure('TLabel', background=theme_settings.get('bg_primary', '#f0f0f0'), foreground=theme_settings.get('fg_primary', '#000000'))
        self.style.configure('TButton', background=theme_settings.get('button_bg', '#007bff'), foreground=theme_settings.get('button_fg', '#ffffff'), borderwidth=0, relief="flat")
        self.style.map('TButton', background=[('active', theme_settings.get('button_hover_bg', '#0056b3'))])
        self.style.configure('TEntry', fieldbackground=theme_settings.get('entry_bg', '#ffffff'), foreground=theme_settings.get('entry_fg', '#000000'))
        self.style.configure('TCombobox', fieldbackground=theme_settings.get('entry_bg', '#ffffff'), foreground=theme_settings.get('entry_fg', '#000000'))
        self.style.configure('TCheckbutton', background=theme_settings.get('bg_primary', '#f0f0f0'), foreground=theme_settings.get('fg_primary', '#000000'))
        self.style.configure('TProgressbar', background=theme_settings.get('progress_bar_bg', '#007bff'))
        self.style.configure('TFrame', background=theme_settings.get('bg_primary', '#f0f0f0')) # Important for nested frames
        self.style.configure('TLabelframe', background=theme_settings.get('bg_card', '#ffffff'), bordercolor=theme_settings.get('border_color', '#cccccc'), relief='solid', borderwidth=1)
        self.style.configure('TLabelframe.Label', background=theme_settings.get('bg_card', '#ffffff'), foreground=theme_settings.get('fg_primary', '#000000'))

        self.text_widget_bg = theme_settings.get('text_widget_bg', '#FFFFFF')
        self.text_widget_fg = theme_settings.get('text_widget_fg', '#333333')
        self.log_widget_bg = theme_settings.get('log_widget_bg', '#f0f0f0')
        self.log_widget_fg = theme_settings.get('log_widget_fg', '#333333')
        self.status_bar_bg = theme_settings.get('status_bar_bg', '#e0e0e0')
        self.status_bar_fg = theme_settings.get('status_bar_fg', '#000000')

        if hasattr(self, 'log_output'):
            self._update_all_text_widget_colors()
        if hasattr(self, 'status_bar'):
            self.status_bar.config(background=self.status_bar_bg, foreground=self.status_bar_fg)
            
        self.ani_network._put_output(f"Theme set to: {theme_name}", tag="log")


    def _update_all_text_widget_colors(self):
        text_widgets = [
            self.sniffer_output, self.geo_output, self.ping_output,
            self.scan_output, self.dns_output, self.my_ip_output,
            self.recon_unified_output, # New unified output
        ]
        if hasattr(self, 'whois_output') and self.whois_output: text_widgets.append(self.whois_output) # Old individual removed
        if hasattr(self, 'traceroute_output') and self.traceroute_output: text_widgets.append(self.traceroute_output)
        if hasattr(self, 'arp_scan_output'): text_widgets.append(self.arp_scan_output)
        if hasattr(self, 'packet_craft_output'): text_widgets.append(self.packet_craft_output)
        if hasattr(self, 'subnet_calc_output'): text_widgets.append(self.subnet_calc_output)
        if hasattr(self, 'ip_range_scan_output'): text_widgets.append(self.ip_range_scan_output)
        if hasattr(self, 'subdomain_enum_output') and self.subdomain_enum_output: text_widgets.append(self.subdomain_enum_output)
        if hasattr(self, 'email_harvester_output') and self.email_harvester_output: text_widgets.append(self.email_harvester_output)
        if hasattr(self, 'web_fingerprint_output') and self.web_fingerprint_output: text_widgets.append(self.web_fingerprint_output)
        if hasattr(self, 'ssl_analyzer_output') and self.ssl_analyzer_output: text_widgets.append(self.ssl_analyzer_output)


        for widget in text_widgets:
            if widget.winfo_exists(): # Check if widget is still around
                widget.config(bg=self.text_widget_bg, fg=self.text_widget_fg)
        
        if self.log_output.winfo_exists():
            self.log_output.config(bg=self.log_widget_bg, fg=self.log_widget_fg)


    def _show_theme_selector(self):
        theme_names = get_available_themes()
        if not theme_names:
            messagebox.showinfo("Themes", "No custom themes found in 'gui/themes' directory. Check folder structure.")
            return

        top = tk.Toplevel(self.master)
        top.title("Select Theme")
        top.transient(self.master)
        top.grab_set()
        top.resizable(False, False)

        tk.Label(top, text="Choose a theme:").pack(pady=10)

        theme_var = tk.StringVar(top, value=self.current_theme_name)
        theme_dropdown = ttk.Combobox(top, textvariable=theme_var, values=theme_names, state="readonly")
        theme_dropdown.pack(pady=5, padx=10)

        def apply_selected_theme():
            selected_theme = theme_var.get()
            self._apply_theme(selected_theme)
            self.settings['current_theme'] = selected_theme
            save_settings(self.settings)
            top.destroy()

        ttk.Button(top, text="Apply Theme", command=apply_selected_theme).pack(pady=10)
        self.master.wait_window(top)


    # --- Settings Management ---
    def _load_settings_into_gui(self):
        # Sniffer Tab
        self.interface_var.set(self.settings.get('sniffer_interface', DEFAULT_SETTINGS['sniffer_interface']))
        self.bpf_filter_entry.delete(0, tk.END)
        self.bpf_filter_entry.insert(0, self.settings.get('sniffer_bpf_filter', DEFAULT_SETTINGS['sniffer_bpf_filter']))
        self.include_hex_dump_var.set(self.settings.get('sniffer_include_hex_dump', DEFAULT_SETTINGS['sniffer_include_hex_dump']))
        
        # Ping Tab
        self.ping_host_entry.delete(0, tk.END)
        self.ping_host_entry.insert(0, self.settings.get('ping_host', DEFAULT_SETTINGS['ping_host']))
        self.ping_count_entry.delete(0, tk.END)
        self.ping_count_entry.insert(0, str(self.settings.get('ping_count', DEFAULT_SETTINGS['ping_count'])))
        self.ping_timeout_entry.delete(0, tk.END)
        self.ping_timeout_entry.insert(0, str(self.settings.get('ping_timeout', DEFAULT_SETTINGS['ping_timeout'])))

        # Port Scanner Tab
        self.scan_ip_entry.delete(0, tk.END)
        self.scan_ip_entry.insert(0, self.settings.get('scan_target_ip', DEFAULT_SETTINGS['scan_target_ip']))
        self.scan_start_port_entry.delete(0, tk.END)
        self.scan_start_port_entry.insert(0, str(self.settings.get('scan_start_port', DEFAULT_SETTINGS['scan_start_port'])))
        self.scan_end_port_entry.delete(0, tk.END)
        self.scan_end_port_entry.insert(0, str(self.settings.get('scan_end_port', DEFAULT_SETTINGS['scan_end_port'])))
        self.scan_timeout_entry.delete(0, tk.END)
        self.scan_timeout_entry.insert(0, str(self.settings.get('scan_timeout', DEFAULT_SETTINGS['scan_timeout'])))

        # DNS Lookup Tab
        self.dns_entry.delete(0, tk.END)
        self.dns_entry.insert(0, self.settings.get('dns_query', DEFAULT_SETTINGS['dns_query']))

        # WHOIS Tab - now uses recon_unified_output, but still loads query
        self.whois_query_entry.delete(0, tk.END)
        self.whois_query_entry.insert(0, self.settings.get('whois_query', DEFAULT_SETTINGS['whois_query']))

        # Traceroute Tab
        self.traceroute_host_entry.delete(0, tk.END)
        self.traceroute_host_entry.insert(0, self.settings.get('traceroute_target', DEFAULT_SETTINGS['traceroute_target']))
        self.traceroute_hops_entry.delete(0, tk.END)
        self.traceroute_hops_entry.insert(0, str(self.settings.get('traceroute_max_hops', DEFAULT_SETTINGS['traceroute_max_hops'])))

        # ARP Scan Tab
        self.arp_timeout_entry.delete(0, tk.END)
        self.arp_timeout_entry.insert(0, str(self.settings.get('arp_scan_timeout', DEFAULT_SETTINGS['arp_scan_timeout'])))

        # Packet Crafting Tab
        self.craft_target_ip_entry.delete(0, tk.END)
        self.craft_target_ip_entry.insert(0, self.settings.get('packet_craft_ip', DEFAULT_SETTINGS['packet_craft_ip']))
        self.craft_protocol_var.set(self.settings.get('packet_craft_protocol', DEFAULT_SETTINGS['packet_craft_protocol']))
        self.craft_port_entry.delete(0, tk.END)
        self.craft_port_entry.insert(0, self.settings.get('packet_craft_port', DEFAULT_SETTINGS['packet_craft_port']))
        self.craft_payload_entry.delete(0, tk.END)
        self.craft_payload_entry.insert(0, self.settings.get('packet_craft_payload', DEFAULT_SETTINGS['packet_craft_payload']))

        # IP Range Scan Tab
        self.ip_range_scan_entry.delete(0, tk.END)
        self.ip_range_scan_entry.insert(0, self.settings.get('ip_range_scan_cidr', DEFAULT_SETTINGS['ip_range_scan_cidr']))

        # Subnet Calculator Tab
        self.subnet_input_entry.delete(0, tk.END)
        self.subnet_input_entry.insert(0, self.settings.get('subnet_calc_input', DEFAULT_SETTINGS['subnet_calc_input']))

        # Subdomain Enum Tab
        self.subdomain_enum_entry.delete(0, tk.END)
        self.subdomain_enum_entry.insert(0, self.settings.get('subdomain_enum_domain', DEFAULT_SETTINGS['subdomain_enum_domain']))

        # Email Harvester Tab
        self.email_harvester_entry.delete(0, tk.END)
        self.email_harvester_entry.insert(0, self.settings.get('email_harvester_domain', DEFAULT_SETTINGS['email_harvester_domain']))

        # Web Fingerprint Tab
        self.web_fingerprint_entry.delete(0, tk.END)
        self.web_fingerprint_entry.insert(0, self.settings.get('web_fingerprint_url', DEFAULT_SETTINGS['web_fingerprint_url']))
        
        # SSL Analyzer Tab
        self.ssl_analyzer_host_entry.delete(0, tk.END)
        self.ssl_analyzer_host_entry.insert(0, self.settings.get('ssl_analyzer_host', DEFAULT_SETTINGS['ssl_analyzer_host']))

        # Settings Tab
        self.ipinfo_api_key_entry.delete(0, tk.END)
        self.ipinfo_api_key_entry.insert(0, self.settings.get('ipinfo_api_key', ''))
        self.shodan_api_key_entry.delete(0, tk.END)
        self.shodan_api_key_entry.insert(0, self.settings.get('shodan_api_key', ''))


    def _save_settings_from_gui(self):
        self.settings['sniffer_interface'] = self.interface_var.get()
        self.settings['sniffer_bpf_filter'] = self.bpf_filter_entry.get().strip()
        self.settings['sniffer_include_hex_dump'] = self.include_hex_dump_var.get()
        
        self.settings['ping_host'] = self.ping_host_entry.get().strip()
        try: self.settings['ping_count'] = int(self.ping_count_entry.get().strip())
        except ValueError: self.settings['ping_count'] = DEFAULT_SETTINGS['ping_count']
        try: self.settings['ping_timeout'] = float(self.ping_timeout_entry.get().strip())
        except ValueError: self.settings['ping_timeout'] = DEFAULT_SETTINGS['ping_timeout']

        self.settings['scan_target_ip'] = self.scan_ip_entry.get().strip()
        try: self.settings['scan_start_port'] = int(self.scan_start_port_entry.get().strip())
        except ValueError: self.settings['scan_start_port'] = DEFAULT_SETTINGS['scan_start_port']
        try: self.settings['scan_end_port'] = int(self.scan_end_port_entry.get().strip())
        except ValueError: self.settings['scan_end_port'] = DEFAULT_SETTINGS['scan_end_port']
        try: self.settings['scan_timeout'] = float(self.scan_timeout_entry.get().strip())
        except ValueError: self.settings['scan_timeout'] = DEFAULT_SETTINGS['scan_timeout']

        self.settings['dns_query'] = self.dns_entry.get().strip()

        self.settings['whois_query'] = self.whois_query_entry.get().strip()
        
        self.settings['traceroute_target'] = self.traceroute_host_entry.get().strip()
        try: self.settings['traceroute_max_hops'] = int(self.traceroute_hops_entry.get().strip())
        except ValueError: self.settings['traceroute_max_hops'] = DEFAULT_SETTINGS['traceroute_max_hops']

        try: self.settings['arp_scan_timeout'] = float(self.arp_timeout_entry.get().strip())
        except ValueError: self.settings['arp_scan_timeout'] = DEFAULT_SETTINGS['arp_scan_timeout']

        self.settings['packet_craft_ip'] = self.craft_target_ip_entry.get().strip()
        self.settings['packet_craft_protocol'] = self.craft_protocol_var.get().strip()
        self.settings['packet_craft_port'] = self.craft_port_entry.get().strip()
        self.settings['packet_craft_payload'] = self.craft_payload_entry.get().strip()

        self.settings['ip_range_scan_cidr'] = self.ip_range_scan_entry.get().strip()
        try: self.settings['ip_range_scan_timeout'] = float(self.ip_range_scan_timeout_entry.get().strip())
        except ValueError: self.settings['ip_range_scan_timeout'] = DEFAULT_SETTINGS['ip_range_scan_timeout']


        self.settings['subnet_calc_input'] = self.subnet_input_entry.get().strip()

        self.settings['subdomain_enum_domain'] = self.subdomain_enum_entry.get().strip()

        self.settings['email_harvester_domain'] = self.email_harvester_entry.get().strip()

        self.settings['web_fingerprint_url'] = self.web_fingerprint_entry.get().strip()

        self.settings['ssl_analyzer_host'] = self.ssl_analyzer_host_entry.get().strip()


        api_key = self.ipinfo_api_key_entry.get().strip()
        self.settings['ipinfo_api_key'] = api_key
        self.ani_network.set_ipinfo_api_key(api_key)
        shodan_api_key = self.shodan_api_key_entry.get().strip()
        self.settings['shodan_api_key'] = shodan_api_key
        self.ani_network.set_shodan_api_key(shodan_api_key)


        self.settings['window_width'] = self.master.winfo_width()
        self.settings['window_height'] = self.master.winfo_height()
        self.settings['window_pos_x'] = self.master.winfo_x()
        self.settings['window_pos_y'] = self.master.winfo_y()

        save_settings(self.settings)
        self.ani_network._put_output("Settings saved.", tag="log")


    # --- GUI Widget Creation (All _setup_ methods defined below) ---
    def _create_widgets(self):
        menubar = Menu(self.master)
        self.master.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Settings", command=self._save_settings_from_gui)
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)

        options_menu = Menu(menubar, tearoff=0)
        options_menu.add_command(label="Select Theme", command=self._show_theme_selector)
        menubar.add_cascade(label="Options", menu=options_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about_dialog)
        menubar.add_cascade(label="Help", menu=help_menu)


        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(pady=10, expand=True, fill="both")

        # Create frames for each tab
        # Core Network Tools
        self._setup_sniffer_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_geolocation_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_ping_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_port_scanner_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_dns_lookup_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        
        # Reconnaissance Tools (Unified Output)
        self._setup_recon_tab(ttk.Frame(self.notebook, style='Card.TFrame'))

        # Local Network Tools
        self._setup_arp_scan_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_ip_range_scan_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_packet_craft_tab(ttk.Frame(self.notebook, style='Card.TFrame'))
        self._setup_subnet_calc_tab(ttk.Frame(self.notebook, style='Card.TFrame'))

        # Info & Settings
        self._setup_my_ip_tab(ttk.Frame(self.notebook, padding="10"))
        self._setup_settings_tab(ttk.Frame(self.notebook, padding="10"))


        log_frame = ttk.Labelframe(self.master, text="Application Log", style='Card.TLabelframe')
        log_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 5))
        self.log_output = CustomScrolledText(log_frame, wrap=tk.WORD, height=6, font=('Consolas', 9),
                                             bg=self.log_widget_bg, fg=self.log_widget_fg)
        self.log_output.pack(fill=tk.X, expand=False, side=tk.LEFT, padx=(0,5))
        self.log_output.tag_config('error_tag', foreground='red', font=('Consolas', 9, 'bold'))

        log_buttons_frame = tk.Frame(log_frame, bg=self.log_widget_bg) # Frame for buttons
        log_buttons_frame.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(log_buttons_frame, text="Clear Log", command=lambda: self.log_output.delete(1.0, tk.END)).pack(pady=2, fill=tk.X)
        ttk.Button(log_buttons_frame, text="Save Log", command=self._save_log_to_file).pack(pady=2, fill=tk.X)
        
        self.status_bar = tk.Label(self.master, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=('TkDefaultFont', 9),
                                   background=self.status_bar_bg, foreground=self.status_bar_fg)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _show_about_dialog(self):
        messagebox.showinfo("About Advanced Network Insight (ANI)",
                            "Advanced Network Insight (ANI)\n\n"
                            "Version: 1.4 (Sleek & Modern Edition)\n" # Updated version
                            "Developer: Mr.Bin/01780102802 (Educational Project)\n\n"
                            "A comprehensive network utility tool for educational purposes.\n"
                            "Includes Sniffer, Geolocation, Ping, Port Scanner, DNS, WHOIS, Traceroute, ARP Scan, Packet Crafting, Subnet Calculator,\n"
                            "IP Range Scan, Subdomain Enum, Email Harvester, Web Fingerprint, SSL Analyzer.\n\n"
                            "Disclaimer: Use responsibly and ethically. Requires admin/root privileges for many features.\n"
                            "Unauthorized network activity is illegal and unethical.")


    def _save_log_to_file(self):
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                      filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                                      title="Save Log As")
            if file_path:
                with open(file_path, "w") as f:
                    f.write(self.log_output.get(1.0, tk.END))
                self.ani_network._put_output(f"Log saved to: {file_path}", tag="log")
        except Exception as e:
            self.ani_network._put_output(f"Error saving log: {e}", tag="error")

    # --- Methods for Sniffer Tab ---
    def _setup_sniffer_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="📡 Sniffer")

        # Input Card
        input_card = ttk.Labelframe(parent_frame, text="Sniffer Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Network Interface:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.interface_dropdown = ttk.Combobox(input_card, textvariable=self.interface_var, state="readonly", width=50, style='TCombobox')
        self.interface_dropdown.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.interface_dropdown.bind("<<ComboboxSelected>>", self._on_interface_selected)
        ToolTip(self.interface_dropdown, "Select the network interface to sniff packets from. Requires admin/root privileges.")

        refresh_button = ttk.Button(input_card, text="🔄 Refresh", command=self._populate_interfaces, style='TButton')
        refresh_button.grid(row=row, column=2, sticky="e", pady=5, padx=5)
        ToolTip(refresh_button, "Click to refresh the list of available network interfaces.")

        row += 1
        ttk.Label(input_card, text="BPF Filter:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.bpf_filter_entry = ttk.Entry(input_card, width=70, style='TEntry')
        self.bpf_filter_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=5, padx=5)
        ToolTip(self.bpf_filter_entry, "Enter a Berkeley Packet Filter (BPF) string (e.g., 'tcp port 80', 'host 192.168.1.1', 'not arp').")

        row += 1
        hex_dump_checkbox = ttk.Checkbutton(input_card, text="Include Raw Hex Dump", variable=self.include_hex_dump_var, style='TCheckbutton')
        hex_dump_checkbox.grid(row=row, column=0, columnspan=3, sticky="w", pady=5, padx=5)
        ToolTip(hex_dump_checkbox, "Display the raw hexadecimal bytes of each captured packet. Useful for low-level analysis.")

        row += 1
        button_frame_sniffer = ttk.Frame(input_card)
        button_frame_sniffer.grid(row=row, column=0, columnspan=3, pady=10)

        self.start_sniffer_button = ttk.Button(button_frame_sniffer, text="▶ Start Sniffer", command=self._start_sniffer, style='TButton')
        self.start_sniffer_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.start_sniffer_button, "Start capturing network packets on the selected interface.")

        self.stop_sniffer_button = ttk.Button(button_frame_sniffer, text="■ Stop Sniffer", command=self._stop_sniffer, state=tk.DISABLED, style='TButton')
        self.stop_sniffer_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_sniffer_button, "Stop the packet sniffing process.")

        ttk.Button(button_frame_sniffer, text="🧹 Clear Output", command=lambda: self.sniffer_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)


        # Statistics Card
        stats_card = ttk.Labelframe(parent_frame, text="Packet Statistics", style='Card.TLabelframe', padding=(15,10,15,10))
        stats_card.pack(fill=tk.X, padx=10, pady=(0,10))
        stats_card.columnconfigure(0, weight=1) # Allow stats to spread

        stats_inner_frame = ttk.Frame(stats_card) # Use a frame inside labelframe for better control
        stats_inner_frame.pack(fill=tk.X)

        ttk.Label(stats_inner_frame, textvariable=self.sniffer_packet_count_var, font=('TkDefaultFont', 10, 'bold')).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_inner_frame, textvariable=self.sniffer_tcp_count_var, font=('TkDefaultFont', 9)).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_inner_frame, textvariable=self.sniffer_udp_count_var, font=('TkDefaultFont', 9)).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_inner_frame, textvariable=self.sniffer_icmp_count_var, font=('TkDefaultFont', 9)).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_inner_frame, textvariable=self.sniffer_arp_count_var, font=('TkDefaultFont', 9)).pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_inner_frame, textvariable=self.sniffer_other_count_var, font=('TkDefaultFont', 9)).pack(side=tk.LEFT, padx=10)


        # Output Card
        output_card = ttk.Labelframe(parent_frame, text="Sniffer Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(1, weight=1) # Make output area expandable

        search_frame = ttk.Frame(output_card)
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0,5))
        ttk.Label(search_frame, text="🔎 Search:").pack(side=tk.LEFT, padx=(0,5))
        self.sniffer_search_entry = ttk.Entry(search_frame, width=30, style='TEntry')
        self.sniffer_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.sniffer_search_entry.bind("<Return>", self._search_sniffer_output)
        ttk.Button(search_frame, text="Find Next", command=self._search_sniffer_output, style='TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Clear Search", command=self._clear_sniffer_search, style='TButton').pack(side=tk.LEFT)

        self.sniffer_output = CustomScrolledText(output_card, wrap=tk.WORD, font=('Consolas', 9),
                                                 bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.sniffer_output.grid(row=1, column=0, sticky="nsew")
        
        self.sniffer_last_search_pos = "1.0"


    def _start_sniffer(self):
        interface = self.interface_var.get().strip()
        bpf_filter = self.bpf_filter_entry.get().strip()
        include_hex_dump = self.include_hex_dump_var.get()

        # Extract the actual Scapy interface name (without the IP part in GUI display)
        if "(" in interface:
            scapy_iface_name = interface.split('(')[0].strip()
        else:
            scapy_iface_name = interface

        if not interface or "No interfaces found" in interface or "Error" in interface:
            messagebox.showerror("Input Error", "Please select a valid network interface before starting the sniffer.")
            return

        self.sniffer_output.delete(1.0, tk.END)
        self.sniffer_packet_count_var.set("Total: 0")
        self.sniffer_tcp_count_var.set("TCP: 0")
        self.sniffer_udp_count_var.set("UDP: 0")
        self.sniffer_icmp_count_var.set("ICMP: 0")
        self.sniffer_arp_count_var.set("ARP: 0")
        self.sniffer_other_count_var.set("Other: 0")

        self.ani_network.start_sniffer(scapy_iface_name, bpf_filter, include_hex_dump) # Pass Scapy-friendly name
        self.start_sniffer_button.config(state=tk.DISABLED)
        self.stop_sniffer_button.config(state=tk.NORMAL)
        self._save_settings_from_gui()

    def _stop_sniffer(self):
        self.ani_network.stop_sniffer()

    def _search_sniffer_output(self, event=None):
        query = self.sniffer_search_entry.get().strip()
        if not query:
            self._clear_sniffer_search()
            return

        self.sniffer_output.tag_remove("search", "1.0", tk.END)
        self.sniffer_output.tag_config("search", background="yellow", foreground="black")

        start_pos = self.sniffer_last_search_pos
        while True:
            idx = self.sniffer_output.search(query, start_pos, tk.END, nocase=1)
            if not idx:
                self.sniffer_last_search_pos = "1.0"
                self.ani_network._put_output(f"Search for '{query}' finished. No more matches found.", tag="log")
                break
            
            end_pos = f"{idx}+{len(query)}c"
            self.sniffer_output.tag_add("search", idx, end_pos)
            self.sniffer_output.see(idx)
            self.sniffer_last_search_pos = end_pos
            
            self.ani_network._put_output(f"Found '{query}' at {idx}", tag="log")
            break

    def _clear_sniffer_search(self):
        self.sniffer_output.tag_remove("search", "1.0", tk.END)
        self.sniffer_search_entry.delete(0, tk.END)
        self.sniffer_last_search_pos = "1.0"
        self.ani_network._put_output("Sniffer search cleared.", tag="log")


    def _populate_interfaces(self):
        self.ani_network._put_output("Refreshing interface list...", tag="log")
        interfaces = self.ani_network.get_interface_list()
        
        self.interface_dropdown['values'] = interfaces
        if hasattr(self, 'arp_interface_dropdown'):
             self.arp_interface_dropdown['values'] = interfaces
        
        saved_sniffer_interface = self.settings.get('sniffer_interface', '')
        if saved_sniffer_interface and saved_sniffer_interface in interfaces:
            self.interface_var.set(saved_sniffer_interface)
        elif interfaces:
            if 'Ethernet' in interfaces:
                self.interface_var.set('Ethernet')
            elif 'Wi-Fi' in interfaces:
                self.interface_var.set('Wi-Fi')
            elif 'lo' in interfaces:
                self.interface_var.set('lo')
            elif interfaces:
                self.interface_var.set(interfaces[0])
        else:
            self.interface_var.set("No interfaces found (check admin privs)")
            self.ani_network._put_output("No network interfaces detected. Please ensure you are running as administrator/root.", tag="error")

        if hasattr(self, 'arp_interface_var'):
            saved_arp_interface = self.settings.get('arp_scan_interface', '')
            if saved_arp_interface and saved_arp_interface in interfaces:
                self.arp_interface_var.set(saved_arp_interface)
            elif interfaces:
                if 'Ethernet' in interfaces:
                    self.arp_interface_var.set('Ethernet')
                elif 'Wi-Fi' in interfaces:
                    self.arp_interface_var.set('Wi-Fi')
                elif interfaces and 'lo' not in interfaces[0]:
                    self.arp_interface_var.set(interfaces[0])
            else:
                self.arp_interface_var.set("No interfaces found")


    def _on_interface_selected(self, event):
        self.ani_network._put_output(f"Selected interface: {self.interface_var.get()}", tag="log")

    # --- Methods for Geolocation Tab ---
    def _setup_geolocation_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="📍 Geolocation")

        input_card = ttk.Labelframe(parent_frame, text="Geolocation Query", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Enter IP Address:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.geo_ip_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.geo_ip_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.geo_ip_entry.insert(0, "8.8.8.8")
        ToolTip(self.geo_ip_entry, "Enter a public IPv4 or IPv6 address to look up its approximate location.")

        row += 1
        self.lookup_geo_button = ttk.Button(input_card, text="🌍 Lookup IP Location", command=self._lookup_geolocation, style='TButton')
        self.lookup_geo_button.grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(self.lookup_geo_button, "Fetch geographical information for the entered IP address. Results are cached.")

        output_card = ttk.Labelframe(parent_frame, text="Geolocation Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.geo_output = CustomScrolledText(output_card, wrap=tk.WORD, font=('Consolas', 9),
                                             bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.geo_output.grid(row=0, column=0, sticky="nsew")

    def _lookup_geolocation(self):
        ip_address = self.geo_ip_entry.get().strip()
        if not ip_address:
            messagebox.showerror("Input Error", "Please enter an IP address for geolocation.")
            return
        self.geo_output.delete(1.0, tk.END)
        self.ani_network.get_geolocation(ip_address)
        self._save_settings_from_gui()

    # --- Methods for Ping Tab ---
    def _setup_ping_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🏓 Ping")

        input_card = ttk.Labelframe(parent_frame, text="Ping Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Target Hostname/IP:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ping_host_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.ping_host_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.ping_host_entry.insert(0, "google.com")
        ToolTip(self.ping_host_entry, "Enter a hostname (e.g., google.com) or an IP address to ping.")

        row += 1
        ttk.Label(input_card, text="Ping Count:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ping_count_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.ping_count_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.ping_count_entry.insert(0, "4")
        ToolTip(self.ping_count_entry, "Number of ICMP echo requests to send.")

        row += 1
        ttk.Label(input_card, text="Timeout (seconds/ping):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ping_timeout_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.ping_timeout_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.ping_timeout_entry.insert(0, "1")
        ToolTip(self.ping_timeout_entry, "Maximum time to wait for each reply.")

        row += 1
        button_frame_ping = ttk.Frame(input_card)
        button_frame_ping.grid(row=row, column=0, columnspan=2, pady=10)

        self.start_ping_button = ttk.Button(button_frame_ping, text="▶ Start Ping", command=self._start_ping, style='TButton')
        self.start_ping_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.start_ping_button, "Start sending ICMP echo requests to the target host.")

        self.stop_ping_button = ttk.Button(button_frame_ping, text="■ Stop Ping", command=self._stop_ping, state=tk.DISABLED, style='TButton')
        self.stop_ping_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_ping_button, "Stop the ping process.")

        ttk.Button(button_frame_ping, text="🧹 Clear Output", command=lambda: self.ping_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)

        output_card = ttk.Labelframe(parent_frame, text="Ping Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.ping_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                             bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.ping_output.grid(row=0, column=0, sticky="nsew")

    def _start_ping(self):
        host = self.ping_host_entry.get().strip()
        count_str = self.ping_count_entry.get().strip()
        timeout_str = self.ping_timeout_entry.get().strip()

        if not host:
            messagebox.showerror("Input Error", "Please enter a hostname or IP for ping.")
            return
        try:
            count = int(count_str)
            timeout = float(timeout_str)
            if not (count > 0 and timeout > 0): raise ValueError("Values must be positive.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Ping count and timeout must be positive numbers. {e}")
            return

        self.ping_output.delete(1.0, tk.END)
        self.ani_network.ping_host(host, count, timeout)
        self.start_ping_button.config(state=tk.DISABLED)
        self.stop_ping_button.config(state=tk.NORMAL)
        self._save_settings_from_gui()

    def _stop_ping(self):
        self.ani_network.stop_ping()

    # --- Methods for Port Scanner Tab ---
    def _setup_port_scanner_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🔭 Port Scanner")
        
        input_card = ttk.Labelframe(parent_frame, text="Port Scan Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Target IP Address:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.scan_ip_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.scan_ip_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.scan_ip_entry.insert(0, "127.0.0.1")
        ToolTip(self.scan_ip_entry, "Enter the target IPv4 or IPv6 address for the port scan. Be ethical!")

        row += 1
        ttk.Label(input_card, text="Start Port:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.scan_start_port_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.scan_start_port_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.scan_start_port_entry.insert(0, "1")
        ToolTip(self.scan_start_port_entry, "The starting port number (1-65535).")

        row += 1
        ttk.Label(input_card, text="End Port:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.scan_end_port_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.scan_end_port_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.scan_end_port_entry.insert(0, "1024")
        ToolTip(self.scan_end_port_entry, "The ending port number (1-65535).")

        row += 1
        ttk.Label(input_card, text="Timeout (seconds/port):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.scan_timeout_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.scan_timeout_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.scan_timeout_entry.insert(0, "0.5")
        ToolTip(self.scan_timeout_entry, "Connection timeout per port. Lower value = faster scan, but might miss ports on slow networks.")

        row += 1
        button_frame_scan = ttk.Frame(input_card)
        button_frame_scan.grid(row=row, column=0, columnspan=2, pady=10)

        self.start_scan_button = ttk.Button(button_frame_scan, text="▶ Start Scan", command=self._start_scan, style='TButton')
        self.start_scan_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.start_scan_button, "Start scanning for open TCP ports on the target. Attempts banner grabbing.")

        self.stop_scan_button = ttk.Button(button_frame_scan, text="■ Stop Scan", command=self._stop_scan, state=tk.DISABLED, style='TButton')
        self.stop_scan_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_scan_button, "Stop the port scanning process.")

        ttk.Button(button_frame_scan, text="🧹 Clear Output", command=lambda: self.scan_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)
        
        # Progress Card
        progress_card = ttk.Labelframe(parent_frame, text="Scan Progress", style='Card.TLabelframe', padding=(15,10,15,10))
        progress_card.pack(fill=tk.X, padx=10, pady=(0,10))
        progress_card.columnconfigure(0, weight=1)

        self.scan_progressbar = ttk.Progressbar(progress_card, orient="horizontal", length=200, mode="determinate", variable=self.scan_progress_var, style='TProgressbar')
        self.scan_progressbar.grid(row=0, column=0, sticky="ew", pady=(5,0))
        self.scan_progress_label = ttk.Label(progress_card, text="Progress: 0.0%", font=('TkDefaultFont', 9))
        self.scan_progress_label.grid(row=1, column=0, sticky="ew", pady=(0,5))

        output_card = ttk.Labelframe(parent_frame, text="Port Scan Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.scan_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                              bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.scan_output.grid(row=0, column=0, sticky="nsew")

    def _start_scan(self):
        target_ip = self.scan_ip_entry.get().strip()
        start_port_str = self.scan_start_port_entry.get().strip()
        end_port_str = self.scan_end_port_entry.get().strip()
        timeout_str = self.scan_timeout_entry.get().strip()

        if not (target_ip and start_port_str and end_port_str and timeout_str):
            messagebox.showerror("Input Error", "Please fill all fields for port scan.")
            return
        try:
            start_port = int(start_port_str)
            end_port = int(end_port_str)
            timeout = float(timeout_str)
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port and timeout > 0):
                raise ValueError("Invalid port range or timeout. Check values.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input for ports or timeout: {e}")
            return

        self.scan_output.delete(1.0, tk.END)
        self.scan_progress_var.set(0)
        self.scan_progress_label.config(text="Progress: 0.0%")
        self.ani_network.scan_ports(target_ip, start_port, end_port, timeout)
        self.start_scan_button.config(state=tk.DISABLED)
        self.stop_scan_button.config(state=tk.NORMAL)
        self._save_settings_from_gui()

    def _stop_scan(self):
        self.ani_network.stop_scan()
        self.scan_progress_var.set(0)
        self.scan_progress_label.config(text="Progress: Stopped")


    # --- Methods for DNS Lookup Tab ---
    def _setup_dns_lookup_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🌐 DNS Lookup")

        input_card = ttk.Labelframe(parent_frame, text="DNS Query", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Hostname or IP:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.dns_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.dns_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.dns_entry.insert(0, "example.com")
        ToolTip(self.dns_entry, "Enter a hostname (e.g., example.com) for forward lookup, or an IP for reverse lookup.")

        row += 1
        self.lookup_dns_button = ttk.Button(input_card, text="🔍 Perform DNS Lookup", command=self._perform_dns_lookup, style='TButton')
        self.lookup_dns_button.grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(self.lookup_dns_button, "Resolve various DNS records (A, AAAA, MX, CNAME, NS, TXT, SOA, SRV, NSEC) for the query.")

        ttk.Button(input_card, text="🧹 Clear Output", command=lambda: self.dns_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=2, sticky="e", padx=5)


        output_card = ttk.Labelframe(parent_frame, text="DNS Lookup Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.dns_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                             bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.dns_output.grid(row=0, column=0, sticky="nsew")

    def _perform_dns_lookup(self):
        query = self.dns_entry.get().strip()
        if not query:
            messagebox.showerror("Input Error", "Please enter a hostname or IP for DNS lookup.")
            return
        self.dns_output.delete(1.0, tk.END)
        self.ani_network.dns_lookup(query)
        self._save_settings_from_gui()


    # --- New: Unified Reconnaissance Tab ---
    def _setup_recon_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🕵️ Reconnaissance")

        # Top Frame for Input Controls of each Recon Tool
        input_controls_frame = ttk.Frame(parent_frame, style='Card.TFrame') # No border, just a container
        input_controls_frame.pack(fill=tk.X, padx=10, pady=10)
        input_controls_frame.columnconfigure(1, weight=1) # Make input entries expand

        # WHOIS
        row = 0
        ttk.Label(input_controls_frame, text="WHOIS Query:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.whois_query_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.whois_query_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.whois_query_entry.insert(0, "google.com")
        ttk.Button(input_controls_frame, text="🔎 WHOIS", command=self._perform_whois_lookup, style='TButton').grid(row=row, column=2, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="🔎 WHOIS"), "Retrieve registration info for domain/IP. (Requires python-whois)")
        row += 1

        # Traceroute
        ttk.Label(input_controls_frame, text="Traceroute Target:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.traceroute_host_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.traceroute_host_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.traceroute_host_entry.insert(0, "google.com")
        ttk.Label(input_controls_frame, text="Max Hops:").grid(row=row, column=2, sticky="w", padx=5) # New Column
        self.traceroute_hops_entry = ttk.Entry(input_controls_frame, width=5, style='TEntry')
        self.traceroute_hops_entry.grid(row=row, column=3, sticky="w", padx=5)
        self.traceroute_hops_entry.insert(0, "30")
        ttk.Button(input_controls_frame, text="🌍 Trace", command=self._start_traceroute, style='TButton').grid(row=row, column=4, sticky="e", padx=5)
        ttk.Button(input_controls_frame, text="⏹️", command=self._stop_traceroute, style='TButton').grid(row=row, column=5, sticky="e", padx=5) # Stop button
        ttk.Button(input_controls_frame, text="🗺️ Map", command=self._open_traceroute_map, style='TButton').grid(row=row, column=6, sticky="e", padx=5) # Map button
        ToolTip(ttk.Button(input_controls_frame, text="🌍 Trace"), "Traceroute to target and optionally plot hops on a map (requires Folium).")
        row += 1

        # IP Range Scan
        ttk.Label(input_controls_frame, text="IP Range (CIDR):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ip_range_scan_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.ip_range_scan_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.ip_range_scan_entry.insert(0, "192.168.1.0/24")
        ttk.Label(input_controls_frame, text="Timeout:").grid(row=row, column=2, sticky="w", padx=5)
        self.ip_range_scan_timeout_entry = ttk.Entry(input_controls_frame, width=5, style='TEntry')
        self.ip_range_scan_timeout_entry.grid(row=row, column=3, sticky="w", padx=5)
        self.ip_range_scan_timeout_entry.insert(0, "0.1")
        ttk.Button(input_controls_frame, text="📡 Scan Range", command=self._start_ip_range_scan, style='TButton').grid(row=row, column=4, sticky="e", padx=5)
        ttk.Button(input_controls_frame, text="⏹️", command=self._stop_ip_range_scan, style='TButton').grid(row=row, column=5, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="📡 Scan Range"), "Ping every IP in the given range to find live hosts.")
        row += 1

        # Subdomain Enum
        ttk.Label(input_controls_frame, text="Subdomain Domain:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.subdomain_enum_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.subdomain_enum_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.subdomain_enum_entry.insert(0, "example.com")
        ttk.Button(input_controls_frame, text="🔍 Subdomains", command=self._enumerate_subdomains, style='TButton').grid(row=row, column=2, columnspan=5, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="🔍 Subdomains"), "Find subdomains using passive techniques (DNS, CT logs).")
        row += 1

        # Email Harvester
        ttk.Label(input_controls_frame, text="Email Harvest Domain:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.email_harvester_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.email_harvester_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.email_harvester_entry.insert(0, "example.com")
        ttk.Button(input_controls_frame, text="📧 Harvest Emails", command=self._harvest_emails, style='TButton').grid(row=row, column=2, columnspan=5, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="📧 Harvest Emails"), "Find publicly available emails for a domain via passive search.")
        row += 1

        # Web Server Fingerprinting
        ttk.Label(input_controls_frame, text="Web Fingerprint URL:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.web_fingerprint_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.web_fingerprint_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.web_fingerprint_entry.insert(0, "https://www.google.com")
        ttk.Button(input_controls_frame, text="🌐 Fingerprint", command=self._web_fingerprint, style='TButton').grid(row=row, column=2, columnspan=5, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="🌐 Fingerprint"), "Identify web server technologies passively from HTTP headers.")
        row += 1

        # SSL/TLS Analyzer
        ttk.Label(input_controls_frame, text="SSL Host:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ssl_analyzer_host_entry = ttk.Entry(input_controls_frame, width=40, style='TEntry')
        self.ssl_analyzer_host_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.ssl_analyzer_host_entry.insert(0, "google.com:443")
        ttk.Button(input_controls_frame, text="🔒 Analyze SSL", command=self._analyze_ssl_cert, style='TButton').grid(row=row, column=2, columnspan=5, sticky="e", padx=5)
        ToolTip(ttk.Button(input_controls_frame, text="🔒 Analyze SSL"), "Extract and display details from a host's SSL/TLS certificate.")
        row += 1

        # Common Clear Output Button for Recon Tab
        ttk.Button(input_controls_frame, text="🧹 Clear All Recon Output", command=lambda: self.recon_unified_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=0, columnspan=7, pady=10)
        row += 1
        
        # Unified Reconnaissance Output Area
        output_card = ttk.Labelframe(parent_frame, text="Unified Reconnaissance Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.recon_unified_output = CustomScrolledText(output_card, wrap=tk.WORD, font=('Consolas', 9),
                                                        bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.recon_unified_output.grid(row=0, column=0, sticky="nsew")

        # Progress bars for Traceroute and IP Range Scan (within Recon tab)
        progress_bar_frame = ttk.Frame(output_card, style='Card.TFrame')
        progress_bar_frame.grid(row=1, column=0, sticky="ew", pady=(5,0))
        progress_bar_frame.columnconfigure(0, weight=1)

        # Traceroute Progress
        self.traceroute_progressbar = ttk.Progressbar(progress_bar_frame, orient="horizontal", length=200, mode="determinate", variable=self.traceroute_progress_var, style='TProgressbar')
        self.traceroute_progressbar.grid(row=0, column=0, sticky="ew", pady=(2,0))
        self.traceroute_progress_label = ttk.Label(progress_bar_frame, text="Traceroute: 0.0%", font=('TkDefaultFont', 8))
        self.traceroute_progress_label.grid(row=1, column=0, sticky="ew", pady=(0,2))
        
        # IP Range Scan Progress
        self.ip_range_scan_progressbar = ttk.Progressbar(progress_bar_frame, orient="horizontal", length=200, mode="determinate", variable=self.ip_range_scan_progress_var, style='TProgressbar')
        self.ip_range_scan_progressbar.grid(row=2, column=0, sticky="ew", pady=(2,0))
        self.ip_range_scan_progress_label = ttk.Label(progress_bar_frame, text="IP Range Scan: 0.0%", font=('TkDefaultFont', 8))
        self.ip_range_scan_label_row = 3
        self.ip_range_scan_progress_label.grid(row=self.ip_range_scan_label_row, column=0, sticky="ew", pady=(0,2))


    def _perform_whois_lookup(self):
        query = self.whois_query_entry.get().strip()
        if not query:
            messagebox.showerror("Input Error", "Please enter a domain or IP for WHOIS lookup.")
            return
        self.ani_network.whois_lookup(query)
        self._save_settings_from_gui()

    def _open_traceroute_map(self):
        map_filepath = os.path.join(os.getcwd(), "traceroute_map.html")
        if os.path.exists(map_filepath):
            webbrowser.open_new_tab(f"file:///{os.path.abspath(map_filepath)}")
        else:
            messagebox.showinfo("Map Not Found", "Traceroute map not found. Please run a traceroute first. (Map requires 'folium' library.)")

    def _start_traceroute(self):
        target_host = self.traceroute_host_entry.get().strip()
        max_hops_str = self.traceroute_hops_entry.get().strip()

        if not target_host:
            messagebox.showerror("Input Error", "Please enter a target hostname or IP for traceroute.")
            return
        try:
            max_hops = int(max_hops_str)
            if not (1 <= max_hops <= 60): raise ValueError("Max hops must be between 1 and 60.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid Max Hops: {e}")
            return
        
        self.ani_network.traceroute_target(target_host, max_hops)
        self._save_settings_from_gui()

    def _stop_traceroute(self):
        self.ani_network.stop_traceroute()
        self.traceroute_progress_var.set(0)
        self.traceroute_progress_label.config(text="Traceroute: Stopped")

    def _start_ip_range_scan(self):
        cidr_range = self.ip_range_scan_entry.get().strip()
        timeout_str = self.ip_range_scan_timeout_entry.get().strip()
        
        if not cidr_range:
            messagebox.showerror("Input Error", "Please enter a CIDR range.")
            return
        try:
            timeout = float(timeout_str)
            if not timeout > 0: raise ValueError("Timeout must be a positive number.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid timeout: {e}")
            return
        
        self.ip_range_scan_progress_var.set(0)
        self.ip_range_scan_progress_label.config(text="IP Range Scan: 0.0%")
        self.ani_network.ip_range_scan(cidr_range, timeout)
        self._save_settings_from_gui()

    def _stop_ip_range_scan(self):
        self.ani_network.stop_ip_range_scan()
        self.ip_range_scan_progress_var.set(0)
        self.ip_range_scan_progress_label.config(text="IP Range Scan: Stopped")


    def _enumerate_subdomains(self):
        domain = self.subdomain_enum_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        self.ani_network.enumerate_subdomains(domain)
        self._save_settings_from_gui()

    def _harvest_emails(self):
        domain = self.email_harvester_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        self.ani_network.harvest_emails(domain)
        self._save_settings_from_gui()

    def _web_fingerprint(self):
        url = self.web_fingerprint_entry.get().strip()
        if not url:
            messagebox.showerror("Input Error", "Please enter a target URL.")
            return
        self.ani_network.web_fingerprint(url)
        self._save_settings_from_gui()

    def _analyze_ssl_cert(self):
        host_port = self.ssl_analyzer_host_entry.get().strip()
        if not host_port:
            messagebox.showerror("Input Error", "Please enter a host to analyze.")
            return
        
        host, port = host_port, 443
        if ':' in host_port:
            try:
                host, port_str = host_port.rsplit(':', 1)
                port = int(port_str)
            except ValueError:
                messagebox.showerror("Input Error", "Invalid port specified. Use hostname:port format.")
                return

        self.ani_network.analyze_ssl_cert(host, port)
        self._save_settings_from_gui()

    # --- Methods for ARP Scan Tab ---
    def _setup_arp_scan_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="📡 ARP Scan")
        
        input_card = ttk.Labelframe(parent_frame, text="ARP Scan Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Network Interface:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.arp_interface_dropdown = ttk.Combobox(input_card, textvariable=self.arp_interface_var, state="readonly", width=50, style='TCombobox')
        self.arp_interface_dropdown.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.arp_interface_dropdown.bind("<<ComboboxSelected>>", self._on_arp_interface_selected)
        ToolTip(self.arp_interface_dropdown, "Select the local network interface for the ARP scan. Requires admin/root.")

        refresh_arp_button = ttk.Button(input_card, text="🔄 Refresh", command=self._populate_interfaces, style='TButton')
        refresh_arp_button.grid(row=row, column=2, sticky="e", pady=5, padx=5)
        ToolTip(refresh_arp_button, "Click to refresh the list of available network interfaces for ARP scan.")

        row += 1
        ttk.Label(input_card, text="Timeout (seconds):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.arp_timeout_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.arp_timeout_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.arp_timeout_entry.insert(0, "2")
        ToolTip(self.arp_timeout_entry, "Timeout for the ARP scan. Longer timeout might find more hosts on slower networks.")

        row += 1
        button_frame_arp = ttk.Frame(input_card)
        button_frame_arp.grid(row=row, column=0, columnspan=3, pady=10)

        self.start_arp_button = ttk.Button(button_frame_arp, text="▶ Start ARP Scan", command=self._start_arp_scan, style='TButton')
        self.start_arp_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.start_arp_button, "Discover active hosts on your local network using ARP requests.")

        self.stop_arp_button = ttk.Button(button_frame_arp, text="■ Stop ARP Scan", command=self._stop_arp_scan, state=tk.DISABLED, style='TButton')
        self.stop_arp_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_arp_button, "Stop the ARP scanning process.")

        ttk.Button(button_frame_arp, text="🧹 Clear Output", command=lambda: self.arp_scan_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)
        
        output_card = ttk.Labelframe(parent_frame, text="ARP Scan Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.arp_scan_output = CustomScrolledText(output_card, wrap=tk.WORD, height=15, font=('Consolas', 9),
                                                  bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.arp_scan_output.grid(row=0, column=0, sticky="nsew")

    def _on_arp_interface_selected(self, event):
        self.ani_network._put_output(f"Selected ARP interface: {self.arp_interface_var.get()}", tag="log")

    def _start_arp_scan(self):
        interface = self.arp_interface_var.get().strip()
        timeout_str = self.arp_timeout_entry.get().strip()

        if not interface or "No interfaces found" in interface:
            messagebox.showerror("Input Error", "Please select a valid network interface for ARP scan.")
            return
        try:
            timeout = float(timeout_str)
            if not timeout > 0: raise ValueError("Timeout must be a positive number.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid timeout: {e}")
            return

        self.arp_scan_output.delete(1.0, tk.END)
        self.ani_network.arp_scan_network(interface, timeout)
        self.start_arp_button.config(state=tk.DISABLED)
        self.stop_arp_button.config(state=tk.NORMAL)
        self._save_settings_from_gui()

    def _stop_arp_scan(self):
        self.ani_network.stop_arp_scan()
        self.start_arp_button.config(state=tk.NORMAL)
        self.stop_arp_button.config(state=tk.DISABLED)

    # --- Methods for IP Range Scan (Ping Sweep) Tab ---
    def _setup_ip_range_scan_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="⚡ IP Range Scan")
        
        input_card = ttk.Labelframe(parent_frame, text="IP Range Scan Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="CIDR Range (e.g., 192.168.1.0/24):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ip_range_scan_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.ip_range_scan_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.ip_range_scan_entry.insert(0, "192.168.1.0/24")
        ToolTip(self.ip_range_scan_entry, "Enter an IP range in CIDR format to find live hosts via ping sweep. Requires admin/root.")

        row += 1
        ttk.Label(input_card, text="Timeout (seconds/host):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ip_range_scan_timeout_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.ip_range_scan_timeout_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.ip_range_scan_timeout_entry.insert(0, "0.1")
        ToolTip(self.ip_range_scan_timeout_entry, "Timeout for each ping probe. Shorter is faster but might miss slow hosts.")

        row += 1
        button_frame_ip_range = ttk.Frame(input_card)
        button_frame_ip_range.grid(row=row, column=0, columnspan=2, pady=10)

        self.start_ip_range_scan_button = ttk.Button(button_frame_ip_range, text="▶ Start IP Range Scan", command=self._start_ip_range_scan, style='TButton')
        self.start_ip_range_scan_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.start_ip_range_scan_button, "Ping every IP in the given range to find live hosts.")

        self.stop_ip_range_scan_button = ttk.Button(button_frame_ip_range, text="■ Stop Scan", command=self._stop_ip_range_scan, state=tk.DISABLED, style='TButton')
        self.stop_ip_range_scan_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.stop_ip_range_scan_button, "Stop the IP range scanning process.")

        ttk.Button(button_frame_ip_range, text="🧹 Clear Output", command=lambda: self.ip_range_scan_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)

        progress_card = ttk.Labelframe(parent_frame, text="Scan Progress", style='Card.TLabelframe', padding=(15,10,15,10))
        progress_card.pack(fill=tk.X, padx=10, pady=(0,10))
        progress_card.columnconfigure(0, weight=1)

        self.ip_range_scan_progressbar = ttk.Progressbar(progress_card, orient="horizontal", length=200, mode="determinate", variable=self.ip_range_scan_progress_var, style='TProgressbar')
        self.ip_range_scan_progressbar.grid(row=0, column=0, sticky="ew", pady=(5,0))
        self.ip_range_scan_progress_label = ttk.Label(progress_card, text="Progress: 0.0%", font=('TkDefaultFont', 9))
        self.ip_range_scan_progress_label.grid(row=1, column=0, sticky="ew", pady=(0,5))

        output_card = ttk.Labelframe(parent_frame, text="IP Range Scan Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.ip_range_scan_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                              bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.ip_range_scan_output.grid(row=0, column=0, sticky="nsew")

    def _start_ip_range_scan(self):
        cidr_range = self.ip_range_scan_entry.get().strip()
        timeout_str = self.ip_range_scan_timeout_entry.get().strip()
        
        if not cidr_range:
            messagebox.showerror("Input Error", "Please enter a CIDR range.")
            return
        try:
            timeout = float(timeout_str)
            if not timeout > 0: raise ValueError("Timeout must be a positive number.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid timeout: {e}")
            return
        
        self.ip_range_scan_output.delete(1.0, tk.END)
        self.ip_range_scan_progress_var.set(0)
        self.ip_range_scan_progress_label.config(text="Progress: 0.0%")
        self.ani_network.ip_range_scan(cidr_range, timeout)
        self.start_ip_range_scan_button.config(state=tk.DISABLED)
        self.stop_ip_range_scan_button.config(state=tk.NORMAL)
        self._save_settings_from_gui()

    def _stop_ip_range_scan(self):
        self.ani_network.stop_ip_range_scan()
        self.ip_range_scan_progress_var.set(0)
        self.ip_range_scan_progress_label.config(text="Progress: Stopped")

    # --- New: Subdomain Enumeration Tab ---
    def _setup_subdomain_enum_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🌳 Subdomain Enum")
        
        input_card = ttk.Labelframe(parent_frame, text="Subdomain Enumeration Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Domain Name:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.subdomain_enum_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.subdomain_enum_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.subdomain_enum_entry.insert(0, "example.com")
        ToolTip(self.subdomain_enum_entry, "Find subdomains for a given domain using passive techniques (DNS, CT logs).")

        row += 1
        ttk.Button(input_card, text="🔍 Enumerate Subdomains", command=self._enumerate_subdomains, style='TButton').grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(ttk.Button(input_card, text="Enumerate Subdomains"), "Start the passive subdomain enumeration process.")

        ttk.Button(input_card, text="🧹 Clear Output", command=lambda: self.recon_unified_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=2, sticky="e", padx=5) # Clears unified recon output


        # This tab will output to the unified recon output. No separate output widget here.


    def _enumerate_subdomains(self):
        domain = self.subdomain_enum_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        # Subdomain output goes to unified recon output now
        self.ani_network.enumerate_subdomains(domain)
        self._save_settings_from_gui()

    # --- New: Email Harvester Tab ---
    def _setup_email_harvester_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="📧 Email Harvester")
        
        input_card = ttk.Labelframe(parent_frame, text="Email Harvester Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Domain Name:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.email_harvester_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.email_harvester_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.email_harvester_entry.insert(0, "example.com")
        ToolTip(self.email_harvester_entry, "Find publicly available email addresses associated with a domain. Uses passive techniques.")

        row += 1
        ttk.Button(input_card, text="📧 Harvest Emails", command=self._harvest_emails, style='TButton').grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(ttk.Button(input_card, text="Harvest Emails"), "Start harvesting email addresses from public sources.")

        ttk.Button(input_card, text="🧹 Clear Output", command=lambda: self.recon_unified_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=2, sticky="e", padx=5)

        # Output to unified recon output

    def _harvest_emails(self):
        domain = self.email_harvester_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        self.ani_network.harvest_emails(domain)
        self._save_settings_from_gui()

    # --- New: Web Server Fingerprinting Tab ---
    def _setup_web_fingerprint_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🕸️ Web Fingerprint")

        input_card = ttk.Labelframe(parent_frame, text="Web Fingerprint Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Target URL:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.web_fingerprint_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.web_fingerprint_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.web_fingerprint_entry.insert(0, "https://www.google.com")
        ToolTip(self.web_fingerprint_entry, "Attempt to identify web server technologies (e.g., Apache, Nginx, PHP) from HTTP headers.")

        row += 1
        ttk.Button(input_card, text="🌐 Fingerprint Web Server", command=self._web_fingerprint, style='TButton').grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(ttk.Button(input_card, text="Fingerprint Web Server"), "Perform passive web server fingerprinting.")

        ttk.Button(input_card, text="🧹 Clear Output", command=lambda: self.recon_unified_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=2, sticky="e", padx=5)

        # Output to unified recon output

    def _web_fingerprint(self):
        url = self.web_fingerprint_entry.get().strip()
        if not url:
            messagebox.showerror("Input Error", "Please enter a target URL.")
            return
        self.ani_network.web_fingerprint(url)
        self._save_settings_from_gui()

    # --- New: SSL/TLS Certificate Analyzer Tab ---
    def _setup_ssl_analyzer_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🔒 SSL/TLS Analyzer")
        
        input_card = ttk.Labelframe(parent_frame, text="SSL/TLS Analyzer Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Host to Analyze (e.g., google.com:443):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ssl_analyzer_host_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.ssl_analyzer_host_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.ssl_analyzer_host_entry.insert(0, "google.com:443")
        ToolTip(self.ssl_analyzer_host_entry, "Enter hostname or IP with optional port (default 443) to analyze its SSL/TLS certificate.")

        row += 1
        ttk.Button(input_card, text="✅ Analyze SSL/TLS Cert", command=self._analyze_ssl_cert, style='TButton').grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(ttk.Button(input_card, text="Analyze SSL/TLS Cert"), "Extract and display details from the host's SSL/TLS certificate.")

        ttk.Button(input_card, text="🧹 Clear Output", command=lambda: self.recon_unified_output.delete(1.0, tk.END), style='TButton').grid(row=row, column=2, sticky="e", padx=5)

        # Output to unified recon output

    def _analyze_ssl_cert(self):
        host_port = self.ssl_analyzer_host_entry.get().strip()
        if not host_port:
            messagebox.showerror("Input Error", "Please enter a host to analyze.")
            return
        
        host, port = host_port, 443
        if ':' in host_port:
            try:
                host, port_str = host_port.rsplit(':', 1)
                port = int(port_str)
            except ValueError:
                messagebox.showerror("Input Error", "Invalid port specified. Use hostname:port format.")
                return

        self.ani_network.analyze_ssl_cert(host, port)
        self._save_settings_from_gui()


    # --- Methods for Packet Crafting Tab ---
    def _setup_packet_craft_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🔨 Packet Crafting")

        input_card = ttk.Labelframe(parent_frame, text="Packet Crafting Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="Target IP:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.craft_target_ip_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.craft_target_ip_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.craft_target_ip_entry.insert(0, "127.0.0.1")
        ToolTip(self.craft_target_ip_entry, "The destination IP address for the crafted packet.")

        row += 1
        ttk.Label(input_card, text="Protocol:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.craft_protocol_dropdown = ttk.Combobox(input_card, textvariable=self.craft_protocol_var,
                                                    values=["TCP", "UDP", "ICMP"], state="readonly", width=10, style='TCombobox')
        self.craft_protocol_dropdown.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.craft_protocol_dropdown.set("ICMP")
        ToolTip(self.craft_protocol_dropdown, "Select the Layer 4 protocol for the crafted packet.")

        row += 1
        ttk.Label(input_card, text="Port (TCP/UDP only):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.craft_port_entry = ttk.Entry(input_card, width=10, style='TEntry')
        self.craft_port_entry.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.craft_port_entry.insert(0, "80")
        ToolTip(self.craft_port_entry, "Destination port for TCP/UDP packets. Ignored for ICMP.")

        row += 1
        ttk.Label(input_card, text="Payload (text):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.craft_payload_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.craft_payload_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.craft_payload_entry.insert(0, "Hello ANI!")
        ToolTip(self.craft_payload_entry, "Text payload to include in the packet.")

        row += 1
        button_frame_craft = ttk.Frame(input_card)
        button_frame_craft.grid(row=row, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame_craft, text="✉️ Send Packet", command=self._send_crafted_packet, style='TButton').pack(side=tk.LEFT, padx=5)
        ToolTip(ttk.Button(button_frame_craft, text="Send Packet"), "Craft and send the packet. Requires admin/root.")
        ttk.Button(button_frame_craft, text="🧹 Clear Output", command=lambda: self.packet_craft_output.delete(1.0, tk.END), style='TButton').pack(side=tk.LEFT, padx=5)

        output_card = ttk.Labelframe(parent_frame, text="Packet Crafting Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.packet_craft_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                                      bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.packet_craft_output.grid(row=0, column=0, sticky="nsew")

    def _send_crafted_packet(self):
        target_ip = self.craft_target_ip_entry.get().strip()
        protocol = self.craft_protocol_var.get().strip()
        port_str = self.craft_port_entry.get().strip()
        payload = self.craft_payload_entry.get().strip()

        if not target_ip:
            messagebox.showerror("Input Error", "Target IP cannot be empty.")
            return
        if protocol.lower() in ["tcp", "udp"] and not port_str:
            messagebox.showerror("Input Error", "Port is required for TCP/UDP packets.")
            return
        try:
            port = int(port_str) if protocol.lower() in ["tcp", "udp"] else 0
            if not (0 <= port <= 65535): raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Port must be a number between 0 and 65535.")
            return

        self.packet_craft_output.delete(1.0, tk.END)
        self.ani_network.send_crafted_packet(target_ip, protocol, port, payload)

    # --- Methods for Subnet Calculator Tab ---
    def _setup_subnet_calc_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="🧮 Subnet Calculator")

        input_card = ttk.Labelframe(parent_frame, text="Subnet Calculation Input", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="IP Address / CIDR:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.subnet_input_entry = ttk.Entry(input_card, width=50, style='TEntry')
        self.subnet_input_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        self.subnet_input_entry.insert(0, "192.168.1.0/24")
        ToolTip(self.subnet_input_entry, "Enter an IP address and CIDR (e.g., 192.168.1.50/24) or just network/CIDR.")

        row += 1
        ttk.Button(input_card, text="⚙️ Calculate Subnet", command=self._calculate_subnet, style='TButton').grid(row=row, column=0, columnspan=2, pady=10)
        ToolTip(ttk.Button(input_card, text="Calculate Subnet"), "Calculate network address, broadcast, host range, etc.")

        output_card = ttk.Labelframe(parent_frame, text="Subnet Calculation Output", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.subnet_calc_output = CustomScrolledText(output_card, wrap=tk.WORD, height=15, font=('Consolas', 9),
                                                    bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.subnet_calc_output.grid(row=0, column=0, sticky="nsew")

    def _calculate_subnet(self):
        ip_cidr = self.subnet_input_entry.get().strip()
        if not ip_cidr:
            messagebox.showerror("Input Error", "Please enter an IP address or CIDR for subnet calculation.")
            return
        self.subnet_calc_output.delete(1.0, tk.END)
        self.ani_network.calculate_subnet(ip_cidr)
        self._save_settings_from_gui()

    # --- Methods for My IP Info Tab ---
    def _setup_my_ip_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="👤 My IP Info")
        parent_frame.columnconfigure(0, weight=1)

        output_card = ttk.Labelframe(parent_frame, text="My IP Information", style='Card.TLabelframe', padding=(15,10,15,10))
        output_card.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(0, weight=1)

        self.my_ip_output = CustomScrolledText(output_card, wrap=tk.WORD, height=10, font=('Consolas', 9),
                                               bg=self.text_widget_bg, fg=self.text_widget_fg)
        self.my_ip_output.grid(row=0, column=0, sticky="nsew")

        row = 1
        button_frame = ttk.Frame(output_card)
        button_frame.grid(row=row, column=0, sticky="ew", pady=10)
        self.get_my_ip_button = ttk.Button(button_frame, text="🔎 Get My IP Info", command=self._get_my_ip_info, style='TButton')
        self.get_my_ip_button.pack(side=tk.LEFT, padx=5)
        ToolTip(self.get_my_ip_button, "Retrieve and display your local and public IP addresses and associated details.")


    def _get_my_ip_info(self):
        self.my_ip_output.delete(1.0, tk.END)
        self.ani_network.get_my_ip_info()

    # --- New: Settings Tab ---
    def _setup_settings_tab(self, parent_frame):
        self.notebook.add(parent_frame, text="⚙️ Settings")
        parent_frame.columnconfigure(1, weight=1)

        input_card = ttk.Labelframe(parent_frame, text="API Keys Configuration", style='Card.TLabelframe', padding=(15,10,15,10))
        input_card.pack(fill=tk.X, padx=10, pady=10)
        input_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(input_card, text="ipinfo.io API Key (Optional):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.ipinfo_api_key_entry = ttk.Entry(input_card, width=60, style='TEntry', show="*" if self.settings.get('ipinfo_api_key') else "")
        self.ipinfo_api_key_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        ToolTip(self.ipinfo_api_key_entry, "Enter your ipinfo.io API key for higher rate limits. Get one from ipinfo.io/signup.")
        
        self.show_ipinfo_key_var = tk.BooleanVar()
        self.show_ipinfo_key_checkbutton = ttk.Checkbutton(input_card, text="Show", variable=self.show_ipinfo_key_var,
                                                        command=self._toggle_ipinfo_api_key_visibility, style='TCheckbutton')
        self.show_ipinfo_key_checkbutton.grid(row=row, column=2, sticky="w", padx=5)

        row += 1
        ttk.Label(input_card, text="Shodan.io API Key (Optional):").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.shodan_api_key_entry = ttk.Entry(input_card, width=60, style='TEntry', show="*" if self.settings.get('shodan_api_key') else "")
        self.shodan_api_key_entry.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        ToolTip(self.shodan_api_key_entry, "Enter your Shodan.io API key for Shodan search features. Get one from shodan.io/dashboard.")

        self.show_shodan_key_var = tk.BooleanVar()
        self.show_shodan_key_checkbutton = ttk.Checkbutton(input_card, text="Show", variable=self.show_shodan_key_var,
                                                        command=self._toggle_shodan_api_key_visibility, style='TCheckbutton')
        self.show_shodan_key_checkbutton.grid(row=row, column=2, sticky="w", padx=5)


        row += 1
        ttk.Button(input_card, text="💾 Save All Settings", command=self._save_settings_from_gui, style='TButton').grid(row=row, column=0, columnspan=3, pady=10)
        ToolTip(ttk.Button(input_card, text="Save All Settings"), "Save all current input field values and window state to configuration file.")

        theme_card = ttk.Labelframe(parent_frame, text="Theme Settings", style='Card.TLabelframe', padding=(15,10,15,10))
        theme_card.pack(fill=tk.X, padx=10, pady=10)
        theme_card.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(theme_card, text="Theme Selection:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        theme_names = get_available_themes()
        self.theme_selector_var = tk.StringVar(theme_card, value=self.current_theme_name)
        self.theme_selector_dropdown = ttk.Combobox(theme_card, textvariable=self.theme_selector_var,
                                                     values=theme_names, state="readonly", width=20, style='TCombobox')
        self.theme_selector_dropdown.grid(row=row, column=1, sticky="w", pady=5, padx=5)
        self.theme_selector_dropdown.bind("<<ComboboxSelected>>", self._on_theme_selected_via_settings)
        ToolTip(self.theme_selector_dropdown, "Select a visual theme for the application.")


    def _toggle_ipinfo_api_key_visibility(self):
        if self.show_ipinfo_key_var.get():
            self.ipinfo_api_key_entry.config(show="")
        else:
            self.ipinfo_api_key_entry.config(show="*")

    def _toggle_shodan_api_key_visibility(self):
        if self.show_shodan_key_var.get():
            self.shodan_api_key_entry.config(show="")
        else:
            self.shodan_api_key_entry.config(show="*")

    def _on_theme_selected_via_settings(self, event):
        selected_theme = self.theme_selector_var.get()
        self._apply_theme(selected_theme)
        self.settings['current_theme'] = selected_theme

    # --- Queue Checking and GUI Update ---
    def _check_queue(self):
        try:
            while True:
                message_item = self.output_queue.get_nowait()
                message = message_item["message"]
                tag = message_item.get("tag")

                if tag == "sniffer_packet":
                    self.sniffer_output.insert(tk.END, message + "\n")
                    self.sniffer_output.see(tk.END)
                elif tag == "sniffer_stats_update":
                    stats = message
                    self.sniffer_packet_count_var.set(f"Total: {stats['total_packets']}")
                    self.sniffer_tcp_count_var.set(f"TCP: {stats['tcp_packets']}")
                    self.sniffer_udp_count_var.set(f"UDP: {stats['udp_packets']}")
                    self.sniffer_icmp_count_var.set(f"ICMP: {stats['icmp_packets']}")
                    self.sniffer_arp_count_var.set(f"ARP: {stats['arp_packets']}")
                    self.sniffer_other_count_var.set(f"Other: {stats['other_packets']}")
                elif tag == "sniffer_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "Sniffer stopped" in message or "Sniffing error" in message:
                        self.start_sniffer_button.config(state=tk.NORMAL)
                        self.stop_sniffer_button.config(state=tk.DISABLED)
                elif tag == "geo_result":
                    self.geo_output.insert(tk.END, message)
                elif tag == "geo_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "ping_result":
                    self.ping_output.insert(tk.END, message + "\n")
                    self.ping_output.see(tk.END)
                elif tag == "ping_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "Ping finished" in message or "Ping stopped" in message:
                        self.start_ping_button.config(state=tk.NORMAL)
                        self.stop_ping_button.config(state=tk.DISABLED)
                elif tag.startswith("scan_progress"):
                    parts = message.split(':')
                    if len(parts) == 3 and parts[0] == "PROGRESS":
                        current, total = map(int, parts[1].split('/'))
                        percent = float(parts[2])
                        self.scan_progress_var.set(percent)
                        self.scan_progress_label.config(text=f"Progress: {percent:.1f}% ({current}/{total})")
                    else:
                        self.scan_output.insert(tk.END, message + "\n")
                        self.scan_output.see(tk.END)
                elif tag == "scan_result":
                    self.scan_output.insert(tk.END, message + "\n")
                    self.scan_output.see(tk.END)
                elif tag == "scan_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "Port scan finished" in message or "Port scan stopped" in message:
                        self.start_scan_button.config(state=tk.NORMAL)
                        self.stop_scan_button.config(state=tk.DISABLED)
                        self.scan_progress_var.set(0)
                        self.scan_progress_label.config(text="Progress: Complete" if "finished" in message else "Progress: Stopped")
                elif tag == "dns_result":
                    self.dns_output.insert(tk.END, message)
                elif tag == "dns_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "recon_output": # Unified Recon Output
                    self.recon_unified_output.insert(tk.END, message + "\n")
                    self.recon_unified_output.see(tk.END)
                elif tag == "recon_status": # Unified Recon Status
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag.startswith("traceroute_progress"):
                    parts = message.split(':')
                    if len(parts) == 3 and parts[0] == "PROGRESS":
                        current, total = map(int, parts[1].split('/'))
                        percent = float(parts[2])
                        self.traceroute_progress_var.set(percent)
                        self.traceroute_progress_label.config(text=f"Traceroute: {percent:.1f}% ({current}/{total})")
                    else:
                        self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                        self.recon_unified_output.see(tk.END)
                elif tag == "traceroute_result":
                    self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                    self.recon_unified_output.see(tk.END)
                elif tag == "traceroute_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "Traceroute finished" in message or "Traceroute stopped" in message:
                        self.traceroute_progress_var.set(0)
                        self.traceroute_progress_label.config(text="Traceroute: Complete" if "finished" in message else "Traceroute: Stopped")
                elif tag == "arp_scan_result":
                    self.arp_scan_output.insert(tk.END, message + "\n")
                    self.arp_scan_output.see(tk.END)
                elif tag == "arp_scan_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "ARP scan finished" in message or "ARP scan stopped" in message:
                        self.start_arp_button.config(state=tk.NORMAL)
                        self.stop_arp_button.config(state=tk.DISABLED)
                elif tag.startswith("ip_range_scan_progress"):
                    parts = message.split(':')
                    if len(parts) == 3 and parts[0] == "PROGRESS":
                        current, total = map(int, parts[1].split('/'))
                        percent = float(parts[2])
                        self.ip_range_scan_progress_var.set(percent)
                        self.ip_range_scan_progress_label.config(text=f"IP Range Scan: {percent:.1f}% ({current}/{total})")
                    else:
                        self.ip_range_scan_output.insert(tk.END, message + "\n")
                        self.ip_range_scan_output.see(tk.END)
                elif tag == "ip_range_scan_result":
                    self.ip_range_scan_output.insert(tk.END, message + "\n")
                    self.ip_range_scan_output.see(tk.END)
                elif tag == "ip_range_scan_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                    if "IP Range Scan finished" in message or "IP Range Scan stopped" in message:
                        self.start_ip_range_scan_button.config(state=tk.NORMAL)
                        self.stop_ip_range_scan_button.config(state=tk.DISABLED)
                        self.ip_range_scan_progress_var.set(0)
                        self.ip_range_scan_progress_label.config(text="Progress: Complete" if "finished" in message else "Progress: Stopped")
                elif tag == "packet_craft_result":
                    self.packet_craft_output.insert(tk.END, message + "\n")
                    self.packet_craft_output.see(tk.END)
                elif tag == "packet_craft_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "subnet_result":
                    self.subnet_calc_output.insert(tk.END, message)
                elif tag == "subnet_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "subdomain_result":
                    self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                    self.recon_unified_output.see(tk.END)
                elif tag == "subdomain_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "email_harvester_result":
                    self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                    self.recon_unified_output.see(tk.END)
                elif tag == "email_harvester_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "web_fingerprint_result":
                    self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                    self.recon_unified_output.see(tk.END)
                elif tag == "web_fingerprint_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "ssl_analyzer_result":
                    self.recon_unified_output.insert(tk.END, message + "\n") # Redirect to unified
                    self.recon_unified_output.see(tk.END)
                elif tag == "ssl_analyzer_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "myip_result":
                    self.my_ip_output.insert(tk.END, message)
                elif tag == "myip_status":
                    self.status_bar.config(text=message)
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "log":
                    self.log_output.insert(tk.END, message + "\n")
                    self.log_output.see(tk.END)
                elif tag == "error":
                    messagebox.showerror("Error", message)
                    self.status_bar.config(text=f"Error: {message}")
                    self.log_output.insert(tk.END, f"ERROR: {message}\n", 'error_tag')
                    self.log_output.see(tk.END)
                elif tag == "open_browser":
                    file_path = message
                    try:
                        webbrowser.open_new_tab(f"file:///{os.path.abspath(file_path)}")
                        self.ani_network._put_output(f"Opened map in browser: {file_path}", tag="log")
                    except Exception as e:
                        self.ani_network._put_output(f"Could not open map in browser: {e}. File: {file_path}", tag="error")


                self.output_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self._check_queue)

    def on_closing(self):
        self.settings['window_width'] = self.master.winfo_width()
        self.settings['window_height'] = self.master.winfo_height()
        self.settings['window_pos_x'] = self.master.winfo_x()
        self.settings['window_pos_y'] = self.master.winfo_y()
        self._save_settings_from_gui()

        self.ani_network.stop_sniffer()
        self.ani_network.stop_ping()
        self.ani_network.stop_scan()
        self.ani_network.stop_traceroute()
        self.ani_network.stop_arp_scan()
        self.ani_network.stop_ip_range_scan()
        self.ani_network.stop_subdomain_enum()
        self.ani_network.stop_email_harvester()
        self.ani_network.stop_web_fingerprint()
        self.ani_network.stop_ssl_analyzer()
        
        time.sleep(0.3)
        self.master.destroy()