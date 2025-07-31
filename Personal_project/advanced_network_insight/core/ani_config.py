# core/ani_config.py
import json
import os

CONFIG_DIR = 'config'
CONFIG_FILE = os.path.join(CONFIG_DIR, 'ani_settings.json')
THEMES_DIR = 'gui/themes'

DEFAULT_SETTINGS = {
    'sniffer_interface': '',
    'sniffer_bpf_filter': '',
    'sniffer_include_hex_dump': False,
    'ping_host': 'google.com',
    'ping_count': 4,
    'ping_timeout': 1.0,
    'scan_target_ip': '127.0.0.1',
    'scan_start_port': 1,
    'scan_end_port': 1024,
    'scan_timeout': 0.5,
    'dns_query': 'example.com',
    'whois_query': 'google.com',
    'traceroute_target': 'google.com',
    'traceroute_max_hops': 30,
    'arp_scan_timeout': 2,
    'packet_craft_ip': '127.0.0.1',
    'packet_craft_protocol': 'ICMP',
    'packet_craft_port': '80',
    'packet_craft_payload': 'Hello ANI!',
    'ip_range_scan_cidr': '192.168.1.0/24',
    'ip_range_scan_timeout': 0.1, # New default
    'subnet_calc_input': '192.168.1.0/24',
    'subdomain_enum_domain': 'example.com',
    'email_harvester_domain': 'example.com',
    'web_fingerprint_url': 'https://www.google.com',
    'ssl_analyzer_host': 'google.com',
    'window_width': 1000,
    'window_height': 750,
    'window_pos_x': 100,
    'window_pos_y': 100,
    'current_theme': 'Light',
    'ipinfo_api_key': '',
    'shodan_api_key': ''
}

def load_settings():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                settings = json.load(f)
            return {**DEFAULT_SETTINGS, **settings}
        except json.JSONDecodeError:
            print(f"Warning: Corrupted {CONFIG_FILE}. Loading default settings.")
            return DEFAULT_SETTINGS
    return DEFAULT_SETTINGS

def save_settings(settings):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(settings, f, indent=4)

def load_theme(theme_name):
    theme_file = os.path.join(THEMES_DIR, f"{theme_name.lower()}_theme.json")
    if os.path.exists(theme_file):
        try:
            with open(theme_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: Corrupted theme file {theme_file}. Using default styles.")
    return {}

def get_available_themes():
    themes = []
    if os.path.exists(THEMES_DIR):
        for filename in os.listdir(THEMES_DIR):
            if filename.endswith('_theme.json'):
                theme_name = filename.replace('_theme.json', '').replace('_', ' ').title()
                themes.append(theme_name)
    return sorted(themes)