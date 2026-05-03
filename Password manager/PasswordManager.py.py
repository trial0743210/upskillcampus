"""
Secure Password Manager
=======================
A single-file desktop password manager built with Python.

Features:
  • Master-password gate on every launch
  • AES-128 encryption via cryptography.Fernet
  • Passwords stored in an encrypted JSON vault (vault.json)
  • Strong random password generator (12 characters)
  • Clean tkinter GUI

Dependencies:
  pip install cryptography

Author : Harsh
Date   : 2026-04-27
"""

# ──────────────────────────────────────────────
# Imports
# ──────────────────────────────────────────────
import os
import sys
import json
import string
import random
import hashlib
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from cryptography.fernet import Fernet

# ──────────────────────────────────────────────
# Configuration Constants
# ──────────────────────────────────────────────
VAULT_FILE = "vault.json"          # Encrypted password store
KEY_FILE   = "secret.key"         # Fernet symmetric key
MASTER_HASH_FILE = "master.hash"  # SHA-256 hash of the master password
PASSWORD_LENGTH  = 12             # Length for generated passwords


# ══════════════════════════════════════════════
#  Encryption Helpers
# ══════════════════════════════════════════════

def load_or_create_key() -> bytes:
    """
    Load the Fernet key from disk.
    If the key file does not exist yet, generate a fresh key and persist it.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key


def encrypt_password(plain_text: str, fernet: Fernet) -> str:
    """Encrypt a plain-text password and return the token as a UTF-8 string."""
    return fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_password(cipher_text: str, fernet: Fernet) -> str:
    """Decrypt a Fernet token back to the original plain-text password."""
    return fernet.decrypt(cipher_text.encode("utf-8")).decode("utf-8")


# ══════════════════════════════════════════════
#  Vault (JSON) Helpers
# ══════════════════════════════════════════════

def load_vault() -> dict:
    """
    Load the vault from disk.
    Returns an empty dict if the file doesn't exist or is corrupt.
    """
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_vault(vault: dict) -> None:
    """Persist the vault dictionary to disk as formatted JSON."""
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=4)


# ══════════════════════════════════════════════
#  Password Generator
# ══════════════════════════════════════════════

def generate_strong_password(length: int = PASSWORD_LENGTH) -> str:
    """
    Generate a cryptographically reasonable random password.

    Guarantees at least one character from each category:
      • uppercase letter
      • lowercase letter
      • digit
      • special symbol
    """
    if length < 4:
        length = 4  # Minimum to satisfy all categories

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits    = string.digits
    symbols   = string.punctuation

    # Ensure at least one of each type
    password_chars = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(symbols),
    ]

    # Fill the remaining characters from the combined pool
    all_chars = uppercase + lowercase + digits + symbols
    password_chars += [random.choice(all_chars) for _ in range(length - 4)]

    # Shuffle to avoid predictable positions
    random.shuffle(password_chars)
    return "".join(password_chars)


# ══════════════════════════════════════════════
#  Master Password Gate
# ══════════════════════════════════════════════

def hash_master(password: str) -> str:
    """Return the SHA-256 hex digest of the given master password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_or_set_master() -> bool:
    """
    Show a tkinter dialog asking for the master password.

    • First run  → asks the user to CREATE a master password (confirmed twice).
    • Later runs → asks the user to ENTER the existing master password.

    Returns True if authentication succeeds, False otherwise.
    """
    if os.path.exists(MASTER_HASH_FILE):
        # ── Returning user: verify ──
        with open(MASTER_HASH_FILE, "r") as f:
            stored_hash = f.read().strip()

        entered = simpledialog.askstring(
            "🔐 Master Password",
            "Enter your Master Password:",
            show="*",
        )
        if entered is None:
            return False  # User cancelled the dialog

        if hash_master(entered) == stored_hash:
            return True
        else:
            messagebox.showerror("Access Denied", "Incorrect master password.")
            return False
    else:
        # ── First-time setup: create master password ──
        new_pass = simpledialog.askstring(
            "🔐 Create Master Password",
            "Set a new Master Password for the vault:",
            show="*",
        )
        if not new_pass:
            messagebox.showwarning("Cancelled", "Master password is required.")
            return False

        confirm = simpledialog.askstring(
            "🔐 Confirm Master Password",
            "Re-enter the Master Password to confirm:",
            show="*",
        )
        if confirm is None or confirm != new_pass:
            messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
            return False

        # Persist the hash
        with open(MASTER_HASH_FILE, "w") as f:
            f.write(hash_master(new_pass))

        messagebox.showinfo("Success", "Master password created successfully!")
        return True


# ══════════════════════════════════════════════
#  Main GUI Application
# ══════════════════════════════════════════════

class PasswordManagerApp:
    """Tkinter-based GUI for the Secure Password Manager."""

    # ── Colour palette ──
    BG_DARK      = "#1e1e2e"
    BG_CARD      = "#2a2a3d"
    FG_TEXT       = "#cdd6f4"
    FG_DIM        = "#7f849c"
    ACCENT_BLUE   = "#89b4fa"
    ACCENT_GREEN  = "#a6e3a1"
    ACCENT_RED    = "#f38ba8"
    ACCENT_MAUVE  = "#cba6f7"
    ENTRY_BG      = "#313244"
    ENTRY_FG      = "#cdd6f4"

    def __init__(self, master: tk.Tk, fernet: Fernet):
        self.master = master
        self.fernet = fernet
        self.vault  = load_vault()

        # ── Window configuration ──
        self.master.title("🔐 Secure Password Manager")
        self.master.geometry("560x520")
        self.master.resizable(False, False)
        self.master.configure(bg=self.BG_DARK)

        self._build_ui()

    # ──────────────────────────────────────────
    #  UI Construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        """Assemble all widgets."""

        # ── Title banner ──
        title_frame = tk.Frame(self.master, bg=self.BG_DARK)
        title_frame.pack(fill="x", pady=(18, 6))

        tk.Label(
            title_frame,
            text="🔐  Secure Password Manager",
            font=("Segoe UI", 18, "bold"),
            fg=self.ACCENT_BLUE,
            bg=self.BG_DARK,
        ).pack()

        tk.Label(
            title_frame,
            text="Your passwords, encrypted & safe.",
            font=("Segoe UI", 10),
            fg=self.FG_DIM,
            bg=self.BG_DARK,
        ).pack(pady=(2, 0))

        # ── Input card ──
        card = tk.Frame(self.master, bg=self.BG_CARD, bd=0, highlightthickness=1,
                        highlightbackground="#45475a")
        card.pack(padx=28, pady=14, fill="x")

        # Website / Account Name
        tk.Label(
            card, text="Website / Account Name",
            font=("Segoe UI", 10, "bold"), fg=self.FG_TEXT, bg=self.BG_CARD,
        ).grid(row=0, column=0, padx=16, pady=(16, 4), sticky="w")

        self.entry_website = tk.Entry(
            card, font=("Segoe UI", 11), width=36,
            bg=self.ENTRY_BG, fg=self.ENTRY_FG, insertbackground=self.FG_TEXT,
            relief="flat", bd=6,
        )
        self.entry_website.grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 10), sticky="we")

        # Password
        tk.Label(
            card, text="Password",
            font=("Segoe UI", 10, "bold"), fg=self.FG_TEXT, bg=self.BG_CARD,
        ).grid(row=2, column=0, padx=16, pady=(6, 4), sticky="w")

        self.entry_password = tk.Entry(
            card, font=("Segoe UI", 11), width=36,
            bg=self.ENTRY_BG, fg=self.ENTRY_FG, insertbackground=self.FG_TEXT,
            relief="flat", bd=6, show="•",
        )
        self.entry_password.grid(row=3, column=0, columnspan=2, padx=16, pady=(0, 6), sticky="we")

        # Show / hide password toggle
        self._show_pw = False
        self.btn_toggle = tk.Button(
            card, text="👁 Show", font=("Segoe UI", 9),
            bg=self.BG_CARD, fg=self.FG_DIM, bd=0, cursor="hand2",
            activebackground=self.BG_CARD, activeforeground=self.ACCENT_BLUE,
            command=self._toggle_password_visibility,
        )
        self.btn_toggle.grid(row=4, column=0, padx=16, pady=(0, 14), sticky="w")

        card.columnconfigure(0, weight=1)

        # ── Action buttons ──
        btn_frame = tk.Frame(self.master, bg=self.BG_DARK)
        btn_frame.pack(pady=8)

        self._make_button(btn_frame, "➕  Add Password",
                          self.ACCENT_GREEN, "#1e1e2e", self._add_password, 0)
        self._make_button(btn_frame, "🔍  Search Password",
                          self.ACCENT_BLUE, "#1e1e2e", self._search_password, 1)
        self._make_button(btn_frame, "🎲  Generate Password",
                          self.ACCENT_MAUVE, "#1e1e2e", self._generate_password, 2)

        # ── Output / status area ──
        self.output_frame = tk.Frame(self.master, bg=self.BG_DARK)
        self.output_frame.pack(padx=28, pady=(10, 4), fill="x")

        self.lbl_status = tk.Label(
            self.output_frame, text="", font=("Segoe UI", 10),
            fg=self.FG_DIM, bg=self.BG_DARK, wraplength=500, justify="left",
        )
        self.lbl_status.pack(anchor="w")

        # ── Vault list ──
        list_label = tk.Label(
            self.master, text="📋  Saved Accounts",
            font=("Segoe UI", 11, "bold"), fg=self.FG_TEXT, bg=self.BG_DARK,
        )
        list_label.pack(padx=28, anchor="w", pady=(10, 4))

        list_frame = tk.Frame(self.master, bg=self.BG_CARD, bd=0,
                              highlightthickness=1, highlightbackground="#45475a")
        list_frame.pack(padx=28, pady=(0, 16), fill="both", expand=True)

        self.listbox = tk.Listbox(
            list_frame, font=("Consolas", 10),
            bg=self.BG_CARD, fg=self.FG_TEXT,
            selectbackground=self.ACCENT_BLUE, selectforeground="#1e1e2e",
            relief="flat", bd=6, highlightthickness=0,
        )
        self.listbox.pack(fill="both", expand=True, padx=4, pady=4)

        # Double-click to search
        self.listbox.bind("<Double-Button-1>", lambda _: self._search_from_list())

        self._refresh_listbox()

    # ──────────────────────────────────────────
    #  Widget Helpers
    # ──────────────────────────────────────────
    def _make_button(self, parent, text, bg, fg, command, col):
        """Create a styled action button inside a grid."""
        btn = tk.Button(
            parent, text=text, font=("Segoe UI", 10, "bold"),
            bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
            relief="flat", bd=0, padx=14, pady=8, cursor="hand2",
            command=command,
        )
        btn.grid(row=0, column=col, padx=6)

        # Hover effects
        btn.bind("<Enter>", lambda e, b=btn, c=bg: b.configure(bg=self._lighten(c)))
        btn.bind("<Leave>", lambda e, b=btn, c=bg: b.configure(bg=c))

    @staticmethod
    def _lighten(hex_color: str, factor: float = 0.15) -> str:
        """Return a slightly lighter version of a hex colour."""
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, int(r + (255 - r) * factor))
        g = min(255, int(g + (255 - g) * factor))
        b = min(255, int(b + (255 - b) * factor))
        return f"#{r:02x}{g:02x}{b:02x}"

    def _toggle_password_visibility(self):
        """Toggle between showing and hiding the password field."""
        self._show_pw = not self._show_pw
        self.entry_password.configure(show="" if self._show_pw else "•")
        self.btn_toggle.configure(text="🙈 Hide" if self._show_pw else "👁 Show")

    def _refresh_listbox(self):
        """Reload the account list from the in-memory vault."""
        self.listbox.delete(0, tk.END)
        for name in sorted(self.vault.keys(), key=str.lower):
            self.listbox.insert(tk.END, f"  {name}")

    def _set_status(self, message: str, color: str = None):
        """Update the status label beneath the buttons."""
        self.lbl_status.configure(text=message, fg=color or self.FG_DIM)

    # ──────────────────────────────────────────
    #  Core Actions
    # ──────────────────────────────────────────
    def _add_password(self):
        """Encrypt and store a new website/password entry in the vault."""
        website  = self.entry_website.get().strip()
        password = self.entry_password.get().strip()

        if not website or not password:
            messagebox.showwarning("Missing Info", "Please fill in both fields.")
            return

        # Warn if the entry already exists
        if website.lower() in (k.lower() for k in self.vault):
            overwrite = messagebox.askyesno(
                "Duplicate Entry",
                f"An entry for '{website}' already exists.\nOverwrite it?",
            )
            if not overwrite:
                return

        # Encrypt & save
        encrypted = encrypt_password(password, self.fernet)
        self.vault[website] = encrypted
        save_vault(self.vault)

        # Clear fields & refresh
        self.entry_website.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)
        self._refresh_listbox()

        self._set_status(f"✅  Password for '{website}' saved successfully.", self.ACCENT_GREEN)

    def _search_password(self):
        """Look up a website and decrypt its password."""
        website = self.entry_website.get().strip()
        if not website:
            messagebox.showwarning("Missing Info", "Enter a Website/Account Name to search.")
            return

        # Case-insensitive lookup
        match = None
        for key in self.vault:
            if key.lower() == website.lower():
                match = key
                break

        if match is None:
            self._set_status(f"❌  No entry found for '{website}'.", self.ACCENT_RED)
            return

        try:
            decrypted = decrypt_password(self.vault[match], self.fernet)
        except Exception:
            self._set_status("⚠️  Decryption failed. The vault may be corrupted.", self.ACCENT_RED)
            return

        # Populate the password field with the decrypted password
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, decrypted)

        # Also copy to clipboard for convenience
        self.master.clipboard_clear()
        self.master.clipboard_append(decrypted)

        self._set_status(
            f"🔓  Password for '{match}' retrieved & copied to clipboard.",
            self.ACCENT_BLUE,
        )

    def _search_from_list(self):
        """Handle double-click on the listbox: populate fields and search."""
        selection = self.listbox.curselection()
        if not selection:
            return
        website = self.listbox.get(selection[0]).strip()
        self.entry_website.delete(0, tk.END)
        self.entry_website.insert(0, website)
        self._search_password()

    def _generate_password(self):
        """Generate a strong password and populate the Password entry field."""
        password = generate_strong_password(PASSWORD_LENGTH)
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)
        self._set_status(
            f"🎲  Strong {PASSWORD_LENGTH}-char password generated.",
            self.ACCENT_MAUVE,
        )


# ══════════════════════════════════════════════
#  Entry Point
# ══════════════════════════════════════════════

def main():
    """Bootstrap the application: authenticate → launch GUI."""

    # Create a hidden root just for the master-password dialog
    root = tk.Tk()
    root.withdraw()

    # ── Master password gate ──
    if not verify_or_set_master():
        root.destroy()
        sys.exit(0)

    # ── Prepare encryption ──
    key    = load_or_create_key()
    fernet = Fernet(key)

    # ── Show the main application window ──
    root.deiconify()
    PasswordManagerApp(root, fernet)
    root.mainloop()


if __name__ == "__main__":
    main()
