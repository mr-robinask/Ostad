# main.py
import tkinter as tk
from gui.ani_main_window import ANIMainWindow

# Create config/themes directories if they don't exist
import os
from core.ani_config import CONFIG_DIR, THEMES_DIR

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(THEMES_DIR, exist_ok=True)

# Create default theme files if they don't exist
# This is a bit manual, but ensures themes are there on first run
# In a larger app, you'd have a deployment script for this.
if not os.path.exists(os.path.join(THEMES_DIR, 'light_theme.json')):
    with open(os.path.join(THEMES_DIR, 'light_theme.json'), 'w') as f:
        f.write('''{
            "TNotebook.Tab": {"font": ["TkDefaultFont", 10, "bold"]},
            "TLabel": {"font": ["TkDefaultFont", 10]},
            "TButton": {"font": ["TkDefaultFont", 10]},
            "TEntry": {"font": ["TkDefaultFont", 10]},
            "TCombobox": {"font": ["TkDefaultFont", 10]},
            "TCheckbutton": {"font": ["TkDefaultFont", 10]},
            "TProgressbar": {"background": "#007bff"},
            "text_widget_bg": "#FFFFFF",
            "text_widget_fg": "#333333",
            "log_widget_bg": "#f0f0f0",
            "log_widget_fg": "#333333",
            "status_bar_bg": "#e0e0e0",
            "status_bar_fg": "#000000"
        }''')
if not os.path.exists(os.path.join(THEMES_DIR, 'dark_theme.json')):
    with open(os.path.join(THEMES_DIR, 'dark_theme.json'), 'w') as f:
        f.write('''{
            "TNotebook.Tab": {"font": ["TkDefaultFont", 10, "bold"]},
            "TLabel": {"font": ["TkDefaultFont", 10]},
            "TButton": {"font": ["TkDefaultFont", 10]},
            "TEntry": {"font": ["TkDefaultFont", 10]},
            "TCombobox": {"font": ["TkDefaultFont", 10]},
            "TCheckbutton": {"font": ["TkDefaultFont", 10]},
            "TProgressbar": {"background": "#00aaff"},
            "text_widget_bg": "#2b2b2b",
            "text_widget_fg": "#f0f0f0",
            "log_widget_bg": "#3c3c3c",
            "log_widget_fg": "#e0e0e0",
            "status_bar_bg": "#333333",
            "status_bar_fg": "#ffffff"
        }''')


if __name__ == "__main__":
    root = tk.Tk()
    app = ANIMainWindow(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()