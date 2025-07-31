# gui/ani_widgets.py
import tkinter as tk
from tkinter import ttk, Menu, scrolledtext

# --- ToolTip Class ---
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = 0
        self.y = 0
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave) # Hide if clicked

    def enter(self, event=None):
        self.x = self.widget.winfo_rootx() + 20
        self.y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.id = self.widget.after(700, self.show_tip) # Show after 700ms

    def leave(self, event=None):
        self.hide_tip()
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def show_tip(self):
        if self.tip_window or not self.text:
            return
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True) # No window decorations
        self.tip_window.wm_geometry(f"+{self.x}+{self.y}")

        label = tk.Label(self.tip_window, text=self.text, background="#FFFFDD", relief=tk.SOLID, borderwidth=1,
                         font=("Arial", "9", "normal"))
        label.pack(padx=1)

    def hide_tip(self):
        if self.tip_window:
            self.tip_window.destroy()
        self.tip_window = None

# --- Custom ScrolledText with Context Menu ---
class CustomScrolledText(scrolledtext.ScrolledText):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self._create_context_menu()

    def _create_context_menu(self):
        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self._copy_selected_text)
        self.context_menu.add_command(label="Select All", command=self._select_all_text)
        self.bind("<Button-3>", self._show_context_menu)

    def _copy_selected_text(self):
        try:
            selected_text = self.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def _select_all_text(self):
        self.tag_add(tk.SEL, "1.0", tk.END)
        self.mark_set(tk.INSERT, "1.0")
        self.see(tk.INSERT)

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()