import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, colorchooser
import pyperclip
import time
import os
import threading
import sys
import subprocess
from datetime import datetime

from auth_service import AuthService
from storage_service import StorageService, Credential
from validation_service import ValidationService
from config_service import ConfigService
from logger_service import LoggerService
from password_generator import PasswordGenerator
from ui_components import LoginWindow, PasswordRevealDialog, ReauthDialog


class PasswordManagerApp(tk.Tk):
    """
    Main application window with session-based authentication.
    """

    def __init__(self, auth_service: AuthService, storage_service: StorageService,
                 validation_service: ValidationService, config_service: ConfigService,
                 logger_service: LoggerService):
        super().__init__()

        self.auth_service = auth_service
        self.storage_service = storage_service
        self.validation_service = validation_service
        self.config_service = config_service
        self.logger_service = logger_service

        self.title("Password Manager")
        self.geometry("1000x600")
        self.resizable(False, False)

        # Session management
        self.session_check_id = None
        self.clipboard_timer = 0
        self.clipboard_timer_id = None
        self.session_ended_by_minimize = False

        # UI state
        self.dialog_open = False
        self.hide_favorites = tk.BooleanVar(self, False)
        self.hide_nonfavorites = tk.BooleanVar(self, False)

        self._create_widgets()
        self._setup_session_monitoring()
        self.refresh_table()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bind("<Unmap>", self.on_minimize)
        self.bind("<Map>", self.on_restore)
        self.bind("<Motion>", self.reset_session)
        self.bind("<KeyPress>", self.reset_session)

        self.logger_service.log_system_event("Application started")

    def _create_widgets(self):
        # Menu bar
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Backup", command=self.export_backup)
        file_menu.add_command(label="Import Backup", command=self.import_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="View Logs", command=self.open_logs)
        view_menu.add_command(label="Refresh", command=self.refresh_table)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Hide Favorites", variable=self.hide_favorites, command=self.refresh_table)
        view_menu.add_checkbutton(label="Hide Non-Favorites", variable=self.hide_nonfavorites, command=self.refresh_table)

        # Top frame
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=15, pady=15)

        # Search section
        ttk.Label(top_frame, text="🔍 Search:", font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(top_frame, width=35)
        self.search_entry.pack(side=tk.LEFT, padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_credentials())

        # Action buttons
        self.add_button = ttk.Button(top_frame, text="➕ Add", command=self.add_credential, width=10)
        self.add_button.pack(side=tk.LEFT, padx=2)
        self.edit_button = ttk.Button(top_frame, text="✏️ Edit", command=self.edit_credential, width=10)
        self.edit_button.pack(side=tk.LEFT, padx=2)
        self.delete_button = ttk.Button(top_frame, text="❌ Delete", command=self.delete_credential, width=10)
        self.delete_button.pack(side=tk.LEFT, padx=2)
        self.refresh_button = ttk.Button(top_frame, text="↻ Refresh", command=self.refresh_table, width=10)
        self.refresh_button.pack(side=tk.LEFT, padx=2)

        # Copy password button
        self.copy_password_button = ttk.Button(top_frame, text="Copy Password", command=self.copy_password, width=15)
        self.copy_password_button.pack(side=tk.RIGHT, padx=2)

        # Clipboard status
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
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=15, pady=(10, 5))

        # Session status
        self.session_status_var = tk.StringVar(value="")
        #session_status_bar = ttk.Label(self, textvariable=self.session_status_var,
        #                             relief=tk.SUNKEN, anchor=tk.E, foreground='blue')
        #session_status_bar.pack(fill=tk.X, padx=15, pady=(0, 5))

    def _setup_session_monitoring(self):
        """Setup session timeout monitoring."""
        self._update_session_status()
        self.session_check_id = self.after(1000, self._check_session_timeout)  # Check every second

    def _stop_session_monitoring(self):
        """Stop session timeout monitoring."""
        if self.session_check_id:
            self.after_cancel(self.session_check_id)
            self.session_check_id = None

    def _check_session_timeout(self):
        """Check if session has timed out."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
        else:
            self._update_session_status()
            self.session_check_id = self.after(1000, self._check_session_timeout)

    def _handle_session_timeout(self):
        """Handle session timeout by clearing data and prompting re-auth."""
        # Stop session monitoring
        self._stop_session_monitoring()
        
        # Reset minimization flag
        self.session_ended_by_minimize = False
        
        # Clear sensitive data from memory
        self.storage_service.credentials.clear()

        # Update UI
        self.refresh_table()
        self.status_var.set("Session expired - please re-authenticate")
        self.session_status_var.set("🔒 SESSION EXPIRED")

        # Prompt for re-authentication
        self._reauthenticate()

    def _reauthenticate(self, skip_confirmation=False):
        """Prompt user to re-authenticate."""
        if skip_confirmation or messagebox.askyesno("Session Expired",
                             "Your session has expired. Would you like to re-authenticate?"):
            # Show re-authentication dialog
            reauth_dialog = ReauthDialog(self, self.auth_service, self.validation_service, self.logger_service)
            self.wait_window(reauth_dialog)

            if reauth_dialog.result:
                # Reload data
                self.storage_service.load_credentials()
                self.refresh_table()
                self.auth_service.refresh_session()
                self._setup_session_monitoring()
                self.session_ended_by_minimize = False  # Reset flag
                
                self.status_var.set("Re-authenticated successfully")
                self.logger_service.log_auth_event("Session re-authentication successful")
            else:
                self.destroy()
        else:
            self.destroy()

    def _update_session_status(self):
        """Update session status display."""
        if self.auth_service.is_authenticated:
            timeout = self.config_service.get_session_timeout()
            if timeout > 0:
                # Calculate remaining time
                elapsed = (datetime.now() - self.auth_service.session_start_time).total_seconds()
                remaining = max(0, timeout - elapsed)
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                self.session_status_var.set(f"⏱️ Session: {minutes:02d}:{seconds:02d}")
            else:
                self.session_status_var.set("🔓 Session: Active")
        else:
            self.session_status_var.set("🔒 Not Authenticated")

    def reset_session(self, event=None):
        """Reset session timer on user activity."""
        if self.auth_service.is_authenticated:
            self.auth_service.refresh_session()

    def refresh_table(self):
        """Refresh the credentials table."""
        self.search_entry.delete(0, len(self.search_entry.get()))

        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Sort credentials: favorites first, then others
        sorted_credentials = sorted(self.storage_service.credentials, key=lambda x: not x.favorite)
        
        favorite_count = 0
        non_favorite_count = 0
        for idx, cred in enumerate(sorted_credentials):
            # Create a unique tag for this credential's colors
            tag_name = f"color_{idx}"
            
            # Configure the tag with the credential's colors
            fg_color = cred.text_color if cred.text_color else "black"
            bg_color = cred.row_bg_color if cred.row_bg_color else "white"
            favorite_bold = cred.favorite if cred.favorite else False

            self.tree.tag_configure(tag_name, foreground=fg_color, background=bg_color)
            self.tree.tag_configure(tag_name, font=('',9,''))
            if favorite_bold: self.tree.tag_configure(tag_name, font=('',10,'bold'))

            if cred.favorite:
                favorite_count += 1
            else:
                non_favorite_count += 1

            # Insert the item with the color tag
            if (cred.favorite and self.hide_favorites.get() == False) or (not cred.favorite and self.hide_nonfavorites.get() == False):
                self.tree.insert("", tk.END, values=(
                    cred.service, cred.username, cred.tags, cred.created_date
                ), tags=(tag_name,))

        count = len(self.storage_service.credentials)
        self.status_var.set(f"Total credential(s): {count} | favorite(s): {favorite_count} | non-favorite(s): {non_favorite_count}")

    def search_credentials(self):
        """Search credentials based on current query."""
        query = self.search_entry.get().strip()

        # Validate search query
        valid, error = self.validation_service.validate_search_query(query)
        if not valid:
            self.status_var.set(f"Search error: {error}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        results = self.storage_service.search_credentials(query) if query else self.storage_service.credentials
        
        # Sort results: favorites first, then others
        results = sorted(results, key=lambda x: not x.favorite)

        favorite_count = 0
        non_favorite_count = 0

        for idx, cred in enumerate(results):
            # Create a unique tag for this credential's colors
            tag_name = f"color_{idx}"
            
            # Configure the tag with the credential's colors
            fg_color = cred.text_color if cred.text_color else "black"
            bg_color = cred.row_bg_color if cred.row_bg_color else "white"
            favorite_bold = cred.favorite if cred.favorite else False
            
            self.tree.tag_configure(tag_name, foreground=fg_color, background=bg_color)
            self.tree.tag_configure(tag_name, font=('',9,''))
            if favorite_bold: self.tree.tag_configure(tag_name, font=('',10,'bold'))
            
            if cred.favorite:
                favorite_count += 1
            else:
                non_favorite_count += 1

            if (cred.favorite and self.hide_favorites.get() == False) or (not cred.favorite and self.hide_nonfavorites.get() == False):
                self.tree.insert("", tk.END, values=(
                    cred.service, cred.username, cred.tags, cred.created_date
                ), tags=(tag_name,))

        self.status_var.set(f"Found: {len(results)} total credential(s) | {favorite_count} favorite(s) | {non_favorite_count} non-favorite(s)")

    def add_credential(self):
        """Add a new credential."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        dialog = CredentialDialog(self, validation_service=self.validation_service,
                                config_service=self.config_service)
        self.dialog_open = True
        self.wait_window(dialog)
        self.dialog_open = False

        if dialog.result:
            success = self.storage_service.add_credential(dialog.result)
            if success:
                self.refresh_table()
                messagebox.showinfo("Success", "Credential added successfully")
                self.logger_service.log_credential_operation("ADD", dialog.result.service, dialog.result.username)
                
                # Create backup if auto backup is enabled
                if self.config_service.get_auto_backup_enabled():
                    self.storage_service.create_auto_backup()
            else:
                messagebox.showerror("Error", "Failed to add credential")

    def edit_credential(self):
        """Edit an existing credential."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential to edit")
            return

        # Get the selected row values from tree
        values = self.tree.item(selection[0])['values']
        selected_service = values[0]
        selected_username = values[1]
        selected_date = values[3]
        
        # Find the matching credential in storage by service and username
        index = None
        for i, cred in enumerate(self.storage_service.credentials):
            if cred.service == selected_service and cred.username == selected_username and cred.created_date == selected_date:
                index = i
                break
        
        if index is None:
            messagebox.showerror("Error", "Could not find selected credential")
            return
        
        original_credential = self.storage_service.credentials[index]
        
        # Create a copy to avoid modifying the original in storage
        from copy import deepcopy
        credential = deepcopy(original_credential)

        # Decrypt password for editing
        try:
            cipher = self.auth_service.get_cipher()
            decrypted_password = cipher.decrypt(credential.password.encode()).decode()
            credential.password = decrypted_password
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt password for editing")
            self.logger_service.error(f"Failed to decrypt password for editing: {e}")
            return

        dialog = CredentialDialog(self, credential, validation_service=self.validation_service,
                                config_service=self.config_service)
        self.dialog_open = True
        self.wait_window(dialog)
        self.dialog_open = False

        if dialog.result:
            success = self.storage_service.update_credential(index, dialog.result)
            if success:
                self.refresh_table()
                messagebox.showinfo("Success", "Credential updated successfully")
                self.logger_service.log_credential_operation("UPDATE", dialog.result.service, dialog.result.username)
                
                # Create backup if auto backup is enabled
                if self.config_service.get_auto_backup_enabled():
                    self.storage_service.create_auto_backup()
            else:
                messagebox.showerror("Error", "Failed to update credential")

    def delete_credential(self):
        """Delete a credential."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential to delete")
            return

        if messagebox.askyesno("Confirm", "Are you sure you want to delete this credential?"):
            # Get the selected row values from tree
            values = self.tree.item(selection[0])['values']
            selected_service = values[0]
            selected_username = values[1]
            selected_date = values[3]
            
            # Find the matching credential in storage by service and username
            index = None
            for i, cred in enumerate(self.storage_service.credentials):
                if cred.service == selected_service and cred.username == selected_username and cred.created_date == selected_date:
                    index = i
                    break
            
            if index is None:
                messagebox.showerror("Error", "Could not find selected credential")
                return
            
            credential = self.storage_service.credentials[index]

            success = self.storage_service.delete_credential(index)
            if success:
                self.refresh_table()
                messagebox.showinfo("Success", "Credential deleted successfully")
                self.logger_service.log_credential_operation("DELETE", credential.service, credential.username)
                
                # Create backup if auto backup is enabled
                if self.config_service.get_auto_backup_enabled():
                    self.storage_service.create_auto_backup()
            else:
                messagebox.showerror("Error", "Failed to delete credential")

    def copy_password(self):
        """Copy password to clipboard with temporary access."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a credential")
            return

        values = self.tree.item(selection[0])['values']
        selected_service = values[0]
        selected_username = values[1]
        selected_date = values[3]
            
        # Find the matching credential in storage by service and username
        index = None
        for i, cred in enumerate(self.storage_service.credentials):
            if cred.service == selected_service and cred.username == selected_username and cred.created_date == selected_date:
                index = i
                break
            
        if index is None:
            messagebox.showerror("Error", "Could not find selected credential")
            return
            
        credential = self.storage_service.credentials[index]

        try:
            cipher = self.auth_service.get_cipher()
            decrypted_password = cipher.decrypt(credential.password.encode()).decode()

            pyperclip.copy(decrypted_password)
            self.logger_service.log_credential_operation("COPY", credential.service, credential.username)

            # Start clipboard timer
            clipboard_timeout = self.config_service.get_clipboard_timeout()
            if clipboard_timeout > 0:
                self.clipboard_timer = clipboard_timeout
                self._update_clipboard_timer()
            else:
                self.clipboard_label.config(text="Password copied")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")
            self.logger_service.error(f"Failed to copy password: {e}")

    def _update_clipboard_timer(self):
        """Update clipboard countdown timer."""
        if self.clipboard_timer > 0:
            self.clipboard_label.config(text=f"Clipboard clears in {self.clipboard_timer}s")
            self.clipboard_timer -= 1
            self.clipboard_timer_id = self.after(1000, self._update_clipboard_timer)
        else:
            pyperclip.copy("")
            self.clipboard_label.config(text="Clipboard cleared")
            self.logger_service.info("Clipboard cleared after timeout")

    def sort_tree(self, col):
        """Sort treeview by column while keeping favorites on top."""
        items = []
        favorites = []
        
        # Separate items into favorites and non-favorites
        for k in self.tree.get_children():
            index = self.tree.index(k)
            cred = self.storage_service.credentials[index]
            val = self.tree.set(k, col)
            
            if cred.favorite:
                favorites.append((val, k))
            else:
                items.append((val, k))
        
        # Sort both lists
        favorites.sort()
        items.sort()
        
        # Reorder: favorites first, then others
        all_items = favorites + items
        for index, (val, k) in enumerate(all_items):
            self.tree.move(k, "", index)

    def open_logs(self):
        """Open log file."""
        if not self.logger_service.open_logs():
            messagebox.showwarning("Warning", "Could not open log file")

    def open_settings(self):
        """Open settings dialog."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        settings_window = SettingsWindow(self, self.config_service, self.logger_service)
        self.dialog_open = True
        self.wait_window(settings_window)
        self.dialog_open = False

    def export_backup(self):
        """Export encrypted backup."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )

        if filepath:
            success = self.storage_service.export_backup(filepath)
            if success:
                messagebox.showinfo("Success", "Backup exported successfully")
            else:
                messagebox.showerror("Error", "Failed to export backup")

    def import_backup(self):
        """Import encrypted backup."""
        if not self.auth_service.is_session_valid():
            self._handle_session_timeout()
            return
        
        messagebox.showwarning("Warning", "When you import a backup, you must use the same master password and encryption salt that were used when the backup was originally created; otherwise, the backup cannot be decrypted.")

        filepath = filedialog.askopenfilename(
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )

        if filepath:
            if messagebox.askyesno("Confirm", "This will replace all current data. Continue?"):
                success = self.storage_service.import_backup(filepath)
                if success:
                    self.refresh_table()
                    messagebox.showinfo("Success", "Backup imported successfully")
                else:
                    messagebox.showerror("Error", "Failed to import backup")

    def on_minimize(self, event=None):
        """Handle window minimization."""
        if self.config_service.get_minimize_ends_session():
            # Stop session monitoring
            self._stop_session_monitoring()
            
            # Clear sensitive data from memory
            self.storage_service.credentials.clear()
            # Update UI
            self.refresh_table()
            self.status_var.set("Session ended - please re-authenticate")
            self.session_status_var.set("🔒 SESSION ENDED")
            
            # Mark that session was ended by minimization
            self.session_ended_by_minimize = True

    def on_restore(self, event=None):
        """Handle window restoration."""
        if self.session_ended_by_minimize:
            # Session was ended by minimization, show reauth dialog
            self.session_ended_by_minimize = False  # Reset flag
            self._reauthenticate(skip_confirmation=True)
        elif not self.auth_service.is_session_valid():
            self._handle_session_timeout()

    def on_closing(self):
        """Handle application closing."""
        # Clear clipboard
        if self.clipboard_timer > 0:
            pyperclip.copy("")
            self.clipboard_timer = 0

        # Cancel timers
        if self.session_check_id:
            self.after_cancel(self.session_check_id)
        if self.clipboard_timer_id:
            self.after_cancel(self.clipboard_timer_id)

        self.logger_service.log_system_event("Application closed")

        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.destroy()


class CredentialDialog(tk.Toplevel):
    """
    Dialog for adding/editing credentials with validation and secure password display.
    """

    def __init__(self, parent, credential=None, validation_service=None, config_service=None):
        super().__init__(parent)
        self.credential = credential
        self.validation_service = validation_service
        self.config_service = config_service
        self.selected_text_color = credential.text_color if credential else "black"
        self.selected_bg_color = credential.row_bg_color if credential else "white"

        self.title("Add Credential" if credential is None else "Edit Credential")
        self.geometry("550x350")
        self.resizable(False, False)
        self.result = None

        self._create_widgets()

        if self.credential:
            self._load_credential_data()

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

        self.password_entry = ttk.Entry(password_frame, width=25, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(password_frame, text="Show", command=self.toggle_password_visibility, width=8).pack(side=tk.LEFT, padx=3)
        ttk.Button(password_frame, text="Generate", width=10, command=self.generate_password).pack(side=tk.LEFT, padx=3)

        # Tags
        ttk.Label(main_frame, text="Tags", font=('Segoe UI', 10, 'bold')).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.tags_entry = ttk.Entry(main_frame, width=40)
        self.tags_entry.grid(row=3, column=1, sticky=tk.EW, pady=5)

        # Colors (Text and Background)
        ttk.Label(main_frame, text="Colors", font=('Segoe UI', 10, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=5)
        colors_frame = ttk.Frame(main_frame)
        colors_frame.grid(row=4, column=1, sticky=tk.EW, pady=5)
        
        # Text Color Display and Button
        ttk.Label(colors_frame, text="Text:", font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(colors_frame, text="Choose", command=lambda: self.choose_color('text'), width=10).pack(side=tk.LEFT, padx=(0, 10))
        
        # Background Color Display and Button
        ttk.Label(colors_frame, text="Background:", font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(colors_frame, text="Choose", command=lambda: self.choose_color('bg'), width=10).pack(side=tk.LEFT, padx=(0, 10))
        self.color_display = tk.Label(colors_frame, text="Example Text", bg="white", fg="black", borderwidth=0, width=25, height=1)
        self.color_display.pack(side=tk.LEFT)
        
        # Update displays if colors already selected
        if self.selected_text_color:
            self.color_display.config(fg=self.selected_text_color)
        if self.selected_bg_color:
            self.color_display.config(bg=self.selected_bg_color)

        # Notes
        ttk.Label(main_frame, text="Notes", font=('Segoe UI', 10, 'bold')).grid(row=5, column=0, sticky=tk.NW, pady=5)
        self.notes_text = tk.Text(main_frame, height=4, width=37, wrap=tk.WORD)
        self.notes_text.grid(row=5, column=1, sticky=tk.EW, pady=5)
        
        # Favorite
        self.favorite_var = tk.BooleanVar(value=False)
        ttk.Label(main_frame, text="Favorite", font=('Segoe UI', 10, 'bold')).grid(row=6, column=0, sticky=tk.W, pady=5)
        ttk.Checkbutton(main_frame, text='Favorited credetials are bolded and get priority when sorted.', variable=self.favorite_var).grid(row=6, column=1, sticky=tk.W, pady=5)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT, padx=5)

        main_frame.columnconfigure(1, weight=1)

    def _load_credential_data(self):
        """Load existing credential data into form."""
        self.service_entry.insert(0, self.credential.service)
        self.username_entry.insert(0, self.credential.username)
        self.password_entry.insert(0, self.credential.password)
        self.tags_entry.insert(0, self.credential.tags)
        self.notes_text.insert("1.0", self.credential.notes)
        self.favorite_var.set(self.credential.favorite)

    def choose_color(self, color_type):
        """Open color chooser dialog for text or background color."""
        current_color = self.selected_text_color if color_type == 'text' else self.selected_bg_color
        title = "Choose Text Color" if color_type == 'text' else "Choose Background Color"
        
        color = colorchooser.askcolor(color=current_color if current_color else "white", 
                                     title=title)
        if color[1]:  # If a color was selected (color[1] is the hex value)
            if color_type == 'text':
                self.selected_text_color = color[1]
                self.color_display.config(fg=self.selected_text_color)
            else:
                self.selected_bg_color = color[1]
                self.color_display.config(bg=self.selected_bg_color)
        self.focus_set()

    def toggle_password_visibility(self):
        """Temporarily show/hide password."""
        current_show = self.password_entry.cget('show')
        if current_show == '•':
            self.password_entry.config(show='')
            self.after(3000, lambda: self.password_entry.config(show='•'))  # Hide after 3 seconds
        else:
            self.password_entry.config(show='•')

    def generate_password(self):
        """Generate a new password."""
        gen_window = tk.Toplevel(self)
        gen_window.title("Generate Password")
        gen_window.geometry("300x220")
        gen_window.resizable(False, False)

        frame = ttk.Frame(gen_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Password Length:", font=('Segoe UI', 10, 'bold')).pack()

        settings = self.config_service.get_password_generator_settings()
        length_var = tk.IntVar(value=settings['length'])
        ttk.Spinbox(frame, from_=8, to=64, textvariable=length_var, width=10).pack(pady=5)

        upper_var = tk.BooleanVar(value=settings['use_uppercase'])
        ttk.Checkbutton(frame, text="Uppercase", variable=upper_var).pack()

        lower_var = tk.BooleanVar(value=settings['use_lowercase'])
        ttk.Checkbutton(frame, text="Lowercase", variable=lower_var).pack()

        num_var = tk.BooleanVar(value=settings['use_numbers'])
        ttk.Checkbutton(frame, text="Numbers", variable=num_var).pack()

        sym_var = tk.BooleanVar(value=settings['use_symbols'])
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

        ttk.Button(frame, text="Generate", command=generate, width=20).pack()

    def save(self):
        """Save the credential after validation."""
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        tags = self.tags_entry.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        favorite = self.favorite_var.get()

        # Validate all fields
        valid, error = self.validation_service.validate_credential_data(service, username, password, tags, notes)
        if not valid:
            messagebox.showwarning("Validation Error", error)
            return

        # Encrypt password
        try:
            from auth_service import AuthService
            # Get cipher from parent app's auth service
            cipher = self.master.auth_service.get_cipher()
            encrypted_password = cipher.encrypt(password.encode()).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt password: {e}")
            return

        self.result = Credential(service, username, encrypted_password, notes, tags, 
                                self.credential.created_date if self.credential else None, 
                                self.selected_text_color, self.selected_bg_color, favorite)
        self.destroy()

    def cancel(self):
        """Cancel the dialog."""
        self.destroy()


class SettingsWindow(tk.Toplevel):
    """
    Settings window for application configuration.
    """

    def __init__(self, parent, config_service, logger_service):
        super().__init__(parent)
        self.config_service = config_service
        self.logger_service = logger_service

        self.title("Settings")
        self.geometry("550x630")
        self.resizable(False, False)

        self._create_widgets()
        self.center_window()

        self.grab_set()
        self.focus_set()

    def _create_widgets(self):
        settings_frame = ttk.Frame(self, padding=15)
        settings_frame.pack(fill=tk.BOTH, expand=True)

        # Password Generator Settings
        pass_frame = ttk.LabelFrame(settings_frame, text="Password Generator", padding=10)
        pass_frame.pack(fill=tk.X, expand=True, pady=8)

        frame = ttk.Frame(pass_frame)
        frame.pack(fill=tk.X, pady=5)

        # Password length
        length_row = ttk.Frame(frame)
        length_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(length_row, text="Default Length:").pack(side=tk.LEFT)
        settings = self.config_service.get_password_generator_settings()
        self.length_var = tk.IntVar(value=settings['length'])
        ttk.Spinbox(length_row, from_=8, to=64, textvariable=self.length_var, width=6).pack(side=tk.LEFT, padx=10)

        # Character options
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)

        self.upper_var = tk.BooleanVar(value=settings['use_uppercase'])
        self.lower_var = tk.BooleanVar(value=settings['use_lowercase'])
        self.num_var = tk.BooleanVar(value=settings['use_numbers'])
        self.sym_var = tk.BooleanVar(value=settings['use_symbols'])

        for text, var in [
            ("Uppercase", self.upper_var),
            ("Lowercase", self.lower_var),
            ("Numbers", self.num_var),
            ("Symbols", self.sym_var),
        ]:
            ttk.Checkbutton(options_frame, text=text, variable=var).pack(anchor=tk.W, pady=2)

        # Security Settings
        security_frame = ttk.LabelFrame(settings_frame, text="Security", padding=10)
        security_frame.pack(fill=tk.X, expand=True, pady=8)

        # Session timeout
        timeout_row = ttk.Frame(security_frame)
        timeout_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(timeout_row, text="Session Timeout (seconds):").pack(side=tk.LEFT)
        self.session_timeout_var = tk.IntVar(value=self.config_service.get_session_timeout())
        ttk.Spinbox(timeout_row, from_=60, to=3600, textvariable=self.session_timeout_var, width=8).pack(side=tk.LEFT, padx=10)

        # Clipboard timeout
        clipboard_row = ttk.Frame(security_frame)
        clipboard_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(clipboard_row, text="Clipboard Clear (seconds):").pack(side=tk.LEFT)
        self.clipboard_var = tk.IntVar(value=self.config_service.get_clipboard_timeout())
        ttk.Spinbox(clipboard_row, from_=0, to=600, textvariable=self.clipboard_var, width=6).pack(side=tk.LEFT, padx=10)

        # Minimize ends session
        minimize_row = ttk.Frame(security_frame)
        minimize_row.pack(fill=tk.X, pady=(0, 10))

        self.minimize_ends_session_var = tk.BooleanVar(value=self.config_service.get_minimize_ends_session())
        ttk.Checkbutton(minimize_row, text="End session when window is minimized", variable=self.minimize_ends_session_var).pack(anchor=tk.W)

        # Auto backup
        backup_row = ttk.Frame(security_frame)
        backup_row.pack(fill=tk.X, pady=(0, 10))

        self.auto_backup_var = tk.BooleanVar(value=self.config_service.get_auto_backup_enabled())
        ttk.Checkbutton(backup_row, text="Enable automatic backups", variable=self.auto_backup_var).pack(anchor=tk.W)

        # Data Management
        data_frame = ttk.LabelFrame(settings_frame, text="Data Management", padding=10)
        data_frame.pack(fill=tk.X, expand=True, pady=8)

        ttk.Button(data_frame, text="Clear All Data", command=self.clear_data).pack(pady=10)
        ttk.Label(data_frame, text="Warning!\n" \
        "When you import a backup, you must use the same master password and encryption salt that \n" \
        "were used when the backup was originally created in order to decrypt it.").pack()

        # Buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, pady=20)

        ttk.Button(button_frame, text="Save", command=self.save_settings, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, width=20).pack(side=tk.LEFT, padx=5)

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def save_settings(self):
        """Save settings."""
        # Password generator settings
        pg_settings = {
            'length': self.length_var.get(),
            'use_uppercase': self.upper_var.get(),
            'use_lowercase': self.lower_var.get(),
            'use_numbers': self.num_var.get(),
            'use_symbols': self.sym_var.get()
        }

        success = self.config_service.update_password_generator_settings(pg_settings)
        success &= self.config_service.set_session_timeout(self.session_timeout_var.get())
        success &= self.config_service.set('clipboard_timeout', self.clipboard_var.get())
        success &= self.config_service.set('minimize_ends_session', self.minimize_ends_session_var.get())
        success &= self.config_service.set('auto_backup', self.auto_backup_var.get())

        if success:
            messagebox.showinfo("Success", "Settings saved successfully")
            self.logger_service.info("Settings updated")
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to save settings")

    def clear_data(self):
        """Clear all stored data."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all data? This action cannot be undone."):
            # Delete data files
            files_to_delete = ['user_data.enc', 'credentials.enc', 'settings.json', 'salt.json']
            for file in files_to_delete:
                try:
                    if os.path.exists(file):
                        os.remove(file)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete {file}: {e}")
                    return
            
            messagebox.showinfo("Success", "All data cleared. The application will now restart.")
            
            # Destroy windows
            self.destroy()
            self.master.destroy()
            
            # Restart the application
            subprocess.Popen([sys.executable, 'main.py'])