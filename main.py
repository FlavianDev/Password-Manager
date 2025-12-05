import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import string
import logging
from pathlib import Path
import pyperclip
import time
import hashlib

# Configure logging
logging.basicConfig(
    filename='password_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EncryptionManager:
    # Handles encryption/decryption of credentials.
    
    def __init__(self, master_password: str, image_path: str):
        self.master_password = master_password
        self.image_path = image_path
        self.cipher = self._generate_cipher()
    
    def _image_hash(self):
        if not self.image_path:
            return None
        try:
            if not os.path.exists(self.image_path):
                logging.warning(f"Image file not found: {self.image_path}")
                return None
            with open(self.image_path, 'rb') as f:
                data = f.read()
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            logging.error(f"Error hashing image: {e}")
            return None

    def _generate_cipher(self):
        image_hash = self._image_hash()
        if image_hash is None:
            image_hash = ''
        combined_password = (self.master_password + image_hash)
        salt = b'flaviandev_2025'  # Placeholder salt; use a secure random salt and store it safely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(combined_password.encode()))
        return Fernet(key)
    
    def encrypt(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        return self.cipher.decrypt(encrypted_data.encode()).decode()

class PasswordGenerator:
    # Generates strong random passwords.
    
    @staticmethod
    def generate(length: int = 16, use_uppercase: bool = True,
                use_lowercase: bool = True, use_numbers: bool = True,
                use_symbols: bool = True) -> str:
        characters = ''
        if not characters:
            characters = string.ascii_letters

        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

class Credential:
    # Represents a credential entry.
    
    def __init__(self, service: str, username: str, password: str,
                 notes: str = "", tags: str = "", created_date: str = None):
        self.service = service
        self.username = username
        self.password = password
        self.notes = notes
        self.tags = tags
        self.created_date = created_date or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def to_dict(self):
        return {
            'service': self.service,
            'username': self.username,
            'password': self.password,
            'notes': self.notes,
            'tags': self.tags,
            'created_date': self.created_date
        }
    
    @staticmethod
    def from_dict(data):
        return Credential(**data)

class CredentialManager:
    # Manages credential storage and retrieval.
    
    def __init__(self, encryption_manager: EncryptionManager, filepath: str = "credentials.enc"):
        self.encryption_manager = encryption_manager
        self.filepath = filepath
        self.credentials = []
        self.failed_load = False
    
    def load_credentials(self, silent: bool = False):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    encrypted_data = f.read()
                    decrypted_data = self.encryption_manager.decrypt(encrypted_data)
                    data = json.loads(decrypted_data)
                    self.credentials = [Credential.from_dict(cred) for cred in data]
                    if not silent:
                        logging.info("Credentials loaded successfully")
            except Exception as e:
                if not silent:
                    logging.error(f"Error loading credentials: {e}")
                    messagebox.showerror("Error", "Failed to load credentials")
                self.failed_load = True
    
    def save_credentials(self):
        try:
            data = [cred.to_dict() for cred in self.credentials]
            encrypted_data = self.encryption_manager.encrypt(json.dumps(data))
            with open(self.filepath, 'w') as f:
                f.write(encrypted_data)
            logging.info("Credentials saved successfully")
        except Exception as e:
            logging.error(f"Error saving credentials: {e}")
            messagebox.showerror("Error", "Failed to save credentials")
    
    def add_credential(self, credential: Credential):
        self.credentials.append(credential)
        self.save_credentials()
        logging.info(f"Credential added for service: [{credential.service} | {credential.username}]")
    
    def update_credential(self, index: int, credential: Credential):
        if 0 <= index < len(self.credentials):
            self.credentials[index] = credential
            self.save_credentials()
            logging.info(f"Credential updated: [{credential.service} | {credential.username}]")
    
    def delete_credential(self, index: int):
        if 0 <= index < len(self.credentials):
            service = self.credentials[index].service
            username = self.credentials[index].username
            del self.credentials[index]
            self.save_credentials()
            logging.info(f"Credential deleted: [{service} | {username}]")
    
    def search_credentials(self, query: str) -> list:
        query = query.lower()
        return [cred for cred in self.credentials
                if query in cred.service.lower() or
                   query in cred.username.lower() or
                   query in cred.tags.lower()]
    
    def get_credentials_by_tag(self, tag: str) -> list:
        return [cred for cred in self.credentials if tag.lower() in cred.tags.lower()]

class LoginWindow(tk.Tk):
    # Master password login window.
    
    def __init__(self):
        super().__init__()
        self.title("Password Manager - Login")
        self.geometry("500x250")
        self.resizable(False, False)
        self.result = None
        
        self._create_widgets()
        self.center_window()
    
    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Password section
        ttk.Label(main_frame, text="Master Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        self.password_entry = ttk.Entry(main_frame, show="•", width=50)
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.bind("<Return>", lambda e: self.login())
        
        # Image section
        ttk.Label(main_frame, text="Image-Based Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.image_path_var = tk.StringVar(value="")
        image_entry = ttk.Entry(img_frame, textvariable=self.image_path_var, width=40, state='readonly')
        image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(img_frame, text="Browse", command=self.browse_image, width=12).pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Login", command=self.login, width=20).pack(padx=5, pady=5)
        ttk.Button(button_frame, text="Exit", command=self.quit, width=20).pack(padx=5, pady=5)
        ttk.Label(button_frame, text="Password Manager v1.0 • Made by @flaviandev, 2025", font=('Segoe UI', 8)).pack()
    
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def browse_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")],
            title="Select image for image-based password"
        )
        if path:
            self.image_path_var.set(path)
        self.attributes('-topmost', True)
        self.after(0, lambda: self.attributes('-topmost', False))

    def login(self):
        password = self.password_entry.get()
        image_path = self.image_path_var.get() or None

        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return
        if len(password) < 8:
            messagebox.showwarning("Warning", "Password must be at least 8 characters long")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return

        self.result = {'password': password, 'image_path': image_path}
        self.destroy()

class VerifyWindowWindow(tk.Toplevel):
    # Master password verify window.
    
    def __init__(self):
        super().__init__()
        self.title("Verify Master Password")
        self.geometry("400x240")
        self.resizable(False, False)
        self.result = None

        self._create_widgets()
        self.center_window()
    
    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Password section
        ttk.Label(main_frame, text="Master Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        self.password_entry = ttk.Entry(main_frame, show="•", width=50)
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.password_entry.bind("<Return>", lambda e: self.verify)
        
        # Image section
        ttk.Label(main_frame, text="Image-Based Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.image_path_var = tk.StringVar(value="")
        image_entry = ttk.Entry(img_frame, textvariable=self.image_path_var, width=40, state='readonly')
        image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(img_frame, text="Browse", command=self.browse_image, width=12).pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Verify", command=self.verify, width=20).pack(padx=5, pady=5)
        ttk.Button(button_frame, text="Exit", command=self.exit, width=20).pack(padx=5, pady=5)
    
    def browse_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg"), ("All files", "*.*")],
            title="Select image for image-based password"
        )
        if path:
            self.image_path_var.set(path)
        self.attributes('-topmost', True)
        self.after(0, lambda: self.attributes('-topmost', False))

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def verify(self):
        password = self.password_entry.get()
        image_path = self.image_path_var.get() or None
        if not password:
            messagebox.showwarning("Warning", "Please enter a password")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return

        self.result = {'password': password, 'image_path': image_path}
        self.destroy()
    
    def exit(self):
        self.result = None
        self.destroy()

class CredentialDialog(tk.Toplevel):
    # Dialog for adding/editing credentials.
    
    def __init__(self, parent, credential: Credential = None):
        super().__init__(parent)
        self.title("Add Credential" if credential is None else "Edit Credential")
        self.geometry("500x300")
        self.resizable(False, False)
        self.result = None

        self.credential = credential
        self._create_widgets()
    
    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Service
        ttk.Label(main_frame, text="Service Name *", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.service_entry = ttk.Entry(main_frame, width=40)
        self.service_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        # Username
        ttk.Label(main_frame, text="Username *", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(main_frame, width=40)
        self.username_entry.grid(row=1, column=1, sticky=tk.EW, pady=5)
        
        # Password
        ttk.Label(main_frame, text="Password *", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=5)
        password_frame = ttk.Frame(main_frame)
        password_frame.grid(row=2, column=1, sticky=tk.EW, pady=5)
        
        self.password_entry = ttk.Entry(password_frame, width=30, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(password_frame, text="Generate", width=10,
                  command=self.generate_password).pack(side=tk.LEFT, padx=3)

        # Tags
        ttk.Label(main_frame, text="Tags", font=('Segoe UI', 10, 'bold')).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.tags_entry = ttk.Entry(main_frame, width=40)
        self.tags_entry.grid(row=3, column=1, sticky=tk.EW, pady=5)
        
        # Notes
        ttk.Label(main_frame, text="Notes", font=('Segoe UI', 10, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=5)
        self.notes_text = tk.Text(main_frame, height=5, width=37)
        self.notes_text.grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT, padx=5)
        
        main_frame.columnconfigure(1, weight=1)
        
        if self.credential:
            self.service_entry.insert(0, self.credential.service)
            self.username_entry.insert(0, self.credential.username)
            self.password_entry.insert(0, self.credential.password)
            self.tags_entry.insert(0, self.credential.tags)
            self.notes_text.insert("1.0", self.credential.notes)

    def generate_password(self):
        gen_window = tk.Toplevel(self)
        gen_window.title("Generate Password")
        gen_window.geometry("250x250")
        gen_window.resizable(False, False)
        
        frame = ttk.Frame(gen_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password Length:", font=('Segoe UI', 10, 'bold')).pack()
        length_var = tk.IntVar(value=16)
        ttk.Spinbox(frame, from_=8, to=64, textvariable=length_var, width=10).pack(pady=5)
        
        upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Uppercase", variable=upper_var).pack()
        
        lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Lowercase", variable=lower_var).pack()
        
        num_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Numbers", variable=num_var).pack()
        
        sym_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Symbols", variable=sym_var).pack(pady=(0, 20))
        
        def generate():
            password = PasswordGenerator.generate(
                length=length_var.get(),
                use_uppercase=upper_var.get(),
                use_lowercase=lower_var.get(),
                use_numbers=num_var.get(),
                use_symbols=sym_var.get()
            )
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
            gen_window.destroy()
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
        
        ttk.Button(frame, text="Generate", command=generate, width=20).pack()
    
    def save(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        tags = self.tags_entry.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        if not service or not username or not password:
            messagebox.showwarning("Warning", "Please fill in all required fields")
            return
        
        verifyDialog = VerifyWindowWindow()
        self.wait_window(verifyDialog)
        
        if verifyDialog.result:
            try:
                encryption_manager = EncryptionManager(verifyDialog.result['password'], verifyDialog.result['image_path'])
                encrypted_password = encryption_manager.encrypt(password)
                self.result = Credential(service, username, encrypted_password, notes, tags,
                                        self.credential.created_date if self.credential else None)
                self.destroy()
            except Exception as e:
                messagebox.showerror("Error", "Incorrect Master Password")
                logging.error(f"Error saving credential: [{service} | {username}] - {e}")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
            finally:
                verifyDialog.destroy()
    
    def cancel(self):
        self.destroy()

class PasswordManagerApp(tk.Tk):
    # Main application window.
    
    def __init__(self, credential_manager: CredentialManager):
        super().__init__()
        self.title("Password Manager")
        self.geometry("1000x650")
        self.credential_manager = credential_manager
        self.is_locked = False
        self.dialog_open = False
        self.verify_in_progress = False
        
        self.clipboard_timer = 0
        self.idle_timer = 60000
        self.idle_timeout = None

        self._create_widgets()
        self.refresh_table()
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bind("<Unmap>", self.on_minimize)
        self.bind("<Map>", self.on_restore)
        self.bind("<Motion>", self.reset_idle_timer)
        self.bind("<KeyPress>", self.reset_idle_timer)
        self.bind_all("<Motion>", self.reset_idle_timer)
        self.bind_all("<KeyPress>", self.reset_idle_timer)
    
    def lock_application(self):
        self.is_locked = True
        
        self.add_button.config(state=tk.DISABLED)
        self.edit_button.config(state=tk.DISABLED)
        self.delete_button.config(state=tk.DISABLED)
        self.refresh_button.config(state=tk.DISABLED)
        self.copy_password_button.config(state=tk.DISABLED)
        self.search_entry.config(state=tk.DISABLED)
    
    def unlock_application(self):
        self.is_locked = False
        
        self.add_button.config(state=tk.NORMAL)
        self.edit_button.config(state=tk.NORMAL)
        self.delete_button.config(state=tk.NORMAL)
        self.refresh_button.config(state=tk.NORMAL)
        self.copy_password_button.config(state=tk.NORMAL)
        self.search_entry.config(state=tk.NORMAL)

    def reset_idle_timer(self, event=None):
        if self.dialog_open or self.is_locked:
            self.after_cancel(self.idle_timeout)
            return

        if self.idle_timeout:
            self.after_cancel(self.idle_timeout)
        
        if not self.is_locked:
            self.idle_timeout = self.after(self.idle_timer, self.lock_on_idle)

    def on_minimize(self, event=None):
        if self.idle_timer:
            self.after_cancel(self.idle_timer)

        if not self.is_locked:
            self.lock_application()
            self.status_var.set("Application locked due to being minimized - please re-verify to unlock")
            logging.info("Application minimized - locked")
    
    def lock_on_idle(self):
        if not self.is_locked and not self.verify_in_progress:
            self.verify_in_progress = True
            self.lock_application()
            
            self.status_var.set("Application locked due to inactivity - please re-verify to unlock")
            logging.info("Application locked due to inactivity")
            
            self.verify_and_unlock()

    def on_restore(self, event=None):
        if self.is_locked and not self.verify_in_progress:
            self.verify_in_progress = True
            self.verify_and_unlock()

    def verify_and_unlock(self):
        self.dialog_open = True
        verifyDialog = VerifyWindowWindow()
        self.wait_window(verifyDialog)
        self.dialog_open = False

        if verifyDialog.result:
            try:
                test_manager = EncryptionManager(verifyDialog.result['password'], verifyDialog.result['image_path'])
                if self.credential_manager.credentials:
                    test_manager.decrypt(self.credential_manager.credentials[0].password)
                
                self.encryption_manager = test_manager
                
                self.dialog_open = False
                self.verify_in_progress = False

                self.unlock_application()

                self.refresh_table()
                messagebox.showinfo("Success", "Application unlocked")
                logging.info("Application unlocked successfully")

                self.reset_idle_timer()
            except Exception as e:
                messagebox.showerror("Error", "Incorrect Master Password or Image")
                logging.error(f"Failed to unlock application: {e}")
        else:
            self.is_locked = True
            self.verify_in_progress = False
            self.destroy()

    def _create_widgets(self):
        # Menu bar
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Backup", menu=file_menu)
        file_menu.add_command(label="Export Backup", command=self.export_backup)
        file_menu.add_command(label="Import Backup", command=self.import_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Top frame
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=15, pady=15)
        
        ttk.Label(top_frame, text="🔍 Search:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(top_frame, width=35)
        self.search_entry.pack(side=tk.LEFT, padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_credentials())
        
        self.add_button = ttk.Button(top_frame, text="➕ Add", command=self.add_credential, width=10)
        self.add_button.pack(side=tk.LEFT, padx=2)
        self.edit_button = ttk.Button(top_frame, text="✏️ Edit", command=self.edit_credential, width=10)
        self.edit_button.pack(side=tk.LEFT, padx=2)
        self.delete_button = ttk.Button(top_frame, text="❌ Delete", command=self.delete_credential, width=10)
        self.delete_button.pack(side=tk.LEFT, padx=2)
        self.refresh_button = ttk.Button(top_frame, text="↻ Refresh", command=self.refresh_table, width=10)
        self.refresh_button.pack(side=tk.LEFT, padx=2)

        self.copy_password_button = ttk.Button(top_frame, text="Copy Password", command=self.copy_password, width=15)
        self.copy_password_button.pack(side=tk.RIGHT, padx=2)

        self.clipboard_label = ttk.Label(top_frame, text="", font=('Segoe UI', 9))
        self.clipboard_label.pack(side=tk.RIGHT, padx=10)
        
        # Table frame
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        columns = ("Service", "Username", "Tags", "Created Date")
        self.tree = ttk.Treeview(table_frame, columns=columns, height=18, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=200)
        
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, padx=15, pady=(10, 5))

    def update_clipboard_timer(self):
        if self.clipboard_timer > 0:
            self.clipboard_label.config(text=f"Clipboard cleared in {self.clipboard_timer}s")
            self.clipboard_timer -= 1
            self.copy_password_button.config(state=tk.DISABLED)
            self.after(1000, self.update_clipboard_timer)
            if self.clipboard_timer == 0:
                pyperclip.copy("")
                self.copy_password_button.config(state=tk.NORMAL)
                logging.info("Clipboard cleared after timeout")
        else:
            self.clipboard_label.config(text="")

    def refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for cred in self.credential_manager.credentials:
            self.tree.insert("", tk.END, values=(
                cred.service, cred.username, cred.tags, cred.created_date
            ))
        
        self.status_var.set(f"Total credentials: {len(self.credential_manager.credentials)}")
    
    def search_credentials(self):
        query = self.search_entry.get()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        results = self.credential_manager.search_credentials(query) if query else self.credential_manager.credentials
        
        for cred in results:
            self.tree.insert("", tk.END, values=(
                cred.service, cred.username, cred.tags, cred.created_date
            ))
        
        self.status_var.set(f"Found: {len(results)} credential(s)")
    
    def add_credential(self):
        self.dialog_open = True
        self.lock_application()
        dialog = CredentialDialog(self)
        self.wait_window(dialog)
        self.dialog_open = False
        self.unlock_application()
        
        if dialog.result:
            self.credential_manager.add_credential(dialog.result)
            self.refresh_table()
            messagebox.showinfo("Success", "Credential added successfully")
            logging.info(f"Credential added via UI: [{dialog.result.service} | {dialog.result.username}]")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
    
    def edit_credential(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential to edit")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return
        
        index = self.tree.index(selection[0])
        credential = self.credential_manager.credentials[index]
        
        self.dialog_open = True
        self.lock_application()
        verifyDialog = VerifyWindowWindow()
        self.wait_window(verifyDialog)
        self.dialog_open = False
        self.unlock_application()

        if verifyDialog.result:
            try:
                encryption_manager = EncryptionManager(verifyDialog.result['password'], verifyDialog.result['image_path'])
                decrypted_password = encryption_manager.decrypt(credential.password)
                credential.password = decrypted_password
                
                dialog = CredentialDialog(self, credential)
                self.wait_window(dialog)
        
                if dialog.result:
                    self.credential_manager.update_credential(index, dialog.result)
                    self.refresh_table()
                    messagebox.showinfo("Success", "Credential updated successfully")
                    logging.info(f"Credential edited via UI: [{dialog.result.service} | {dialog.result.username}]")
                    self.attributes('-topmost', True)
                    self.after(0, lambda: self.attributes('-topmost', False))
            except Exception as e:
                messagebox.showerror("Error", "Incorrect Master Password")
                logging.error(f"Error editing credential: [{credential.service} | {credential.username}] - {e}")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))

    def delete_credential(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential to delete")
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return
        
        self.dialog_open = True
        self.lock_application()
        verifyDialog = VerifyWindowWindow()
        self.wait_window(verifyDialog)
        self.dialog_open = False
        self.unlock_application()

        if verifyDialog.result:
            try:
                encryption_manager = EncryptionManager(verifyDialog.result['password'], verifyDialog.result['image_path'])
                index = self.tree.index(selection[0])
                credential = self.credential_manager.credentials[index]
                
                # Verify password works by attempting decryption
                encryption_manager.decrypt(credential.password)
                
                if messagebox.askyesno("Confirm", "Are you sure you want to delete this credential?"):
                    self.credential_manager.delete_credential(index)
                    self.refresh_table()
                    messagebox.showinfo("Success", "Credential deleted successfully")
                    logging.info(f"Credential deleted via UI: [{credential.service} | {credential.username}]")
                    self.attributes('-topmost', True)
                    self.after(0, lambda: self.attributes('-topmost', False))
            except Exception as e:
                messagebox.showerror("Error", "Incorrect Master Password")
                logging.error(f"Error deleting credential - {e}")
                verifyDialog.destroy()
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
    
    def copy_password(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential")
            return
        
        index = self.tree.index(selection[0])
        service = self.credential_manager.credentials[index].service
        username = self.credential_manager.credentials[index].username
        password = self.credential_manager.credentials[index].password
        
        self.dialog_open = True
        self.lock_application()
        verifyDialog = VerifyWindowWindow()
        self.wait_window(verifyDialog)
        self.dialog_open = False
        self.unlock_application()

        if verifyDialog.result:
            try:
                encryption_manager = EncryptionManager(verifyDialog.result['password'], verifyDialog.result['image_path'])
                decrypted_password = encryption_manager.decrypt(password)
                
                pyperclip.copy(decrypted_password)
                logging.info(f"Password copied to clipboard: [{service} | {username}]")
                self.copy_password_button.config(state=tk.DISABLED)
                self.clipboard_timer = 30
                self.update_clipboard_timer()
                messagebox.showinfo("Success", "Password copied to clipboard")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
            except Exception as e:
                messagebox.showerror("Error", f"Incorrect Master Password or failed to copy: {str(e)}")
                logging.error(f"Error copying password: [{service} | {username}] - {e}")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
            finally:
                self.dialog_open = False
                verifyDialog.destroy()
            
    def sort_tree(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        items.sort()
        
        for index, (val, k) in enumerate(items):
            self.tree.move(k, "", index)
    
    def export_backup(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(self.credential_manager.filepath, 'r') as src:
                    with open(filepath, 'w') as dst:
                        dst.write(src.read())
                messagebox.showinfo("Success", "Backup exported successfully")
                logging.info(f"Backup exported to: [{filepath}]")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export backup: {e}")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
    
    def import_backup(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as src:
                    with open(self.credential_manager.filepath, 'w') as dst:
                        dst.write(src.read())
                self.credential_manager.load_credentials()
                self.refresh_table()
                messagebox.showinfo("Success", "Backup imported successfully")
                logging.info(f"Backup imported from: [{filepath}]")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import backup: {e}")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
    
    def on_closing(self):
        if self.clipboard_timer > 0:
            pyperclip.copy("")
            self.clipboard_timer = 0
            self.update_clipboard_timer()
            self.copy_password_button.config(state=tk.NORMAL)

        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            logging.info("Application closed by user")
            self.destroy()


def main():
    logging.info("Application opened")
    login = LoginWindow()
    login.mainloop()
    
    if login.result:
        try:
            encryption_manager = EncryptionManager(login.result['password'], login.result['image_path'])
            credential_manager = CredentialManager(encryption_manager)
            credential_manager.load_credentials()
            app = PasswordManagerApp(credential_manager)
            app.mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize application: {e}")
            logging.error(f"Initialization error: {e}")

if __name__ == "__main__":
    main()