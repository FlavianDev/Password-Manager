import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os


class LoginWindow(tk.Tk):
    """
    Master password login window with first-time setup.
    """

    def __init__(self, auth_service, validation_service, logger_service):
        super().__init__()
        self.auth_service = auth_service
        self.validation_service = validation_service
        self.logger_service = logger_service

        self.title("Password Manager - Login")
        self.geometry("500x260")
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
        pass_frame = ttk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 15))
        self.password_entry = ttk.Entry(pass_frame, show="•", width=40)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.password_entry.bind("<Return>", lambda e: self.login())

        ttk.Button(pass_frame, text="Show", command=self.toggle_password_visibility, width=8).pack(side=tk.LEFT)

        # Confirm password (only shown for first-time setup)
        self.confirm_label = ttk.Label(main_frame, text="Confirm Master Password:", font=('Segoe UI', 10, 'bold'))
        self.confirm_entry = ttk.Entry(main_frame, show="•", width=50)

        # Check if this is first run
        self._check_first_run()

        # Image section
        ttk.Label(main_frame, text="Image-Based Password (Optional):", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
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

        ttk.Label(button_frame, text="Password Manager v2.0 • Dinca Flavian",
                 font=('Segoe UI', 8)).pack()

    def toggle_password_visibility(self):
        """Temporarily show/hide password."""
        current_show = self.password_entry.cget('show')
        if current_show == '•':
            self.password_entry.config(show='')
            self.after(3000, lambda: self.password_entry.config(show='•'))  # Hide after 3 seconds
        else:
            self.password_entry.config(show='•')

    def _check_first_run(self):
        """Check if this is first run and show confirmation field if needed."""
        
        is_first_run = True
        if os.path.exists("user_data.enc"):
            is_first_run = False

        if is_first_run:
            self.title("Password Manager - Setup")
            self.geometry("500x320")
            self.confirm_label.pack(anchor=tk.W, pady=(0, 5))
            self.confirm_entry.pack(fill=tk.X, pady=(0, 10))
            self.confirm_entry.bind("<Return>", lambda e: self.login())

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

        # Validate master password
        valid, error = self.validation_service.validate_master_password(password)
        if not valid:
            messagebox.showwarning("Warning", error)
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))
            return

        # Check if first run and validate confirmation
        is_first_run = True
        if os.path.exists("user_data.enc"):
            is_first_run = False

        if is_first_run:
            confirm_password = self.confirm_entry.get()
            if password != confirm_password:
                messagebox.showwarning("Warning", "Passwords do not match")
                self.attributes('-topmost', True)
                self.after(0, lambda: self.attributes('-topmost', False))
                return

        # Attempt authentication
        if self.auth_service.authenticate(password, image_path):
            self.result = {'password': password, 'image_path': image_path}
            self.logger_service.log_auth_event("User login successful")
            self.destroy()
        else:
            messagebox.showerror("Error", "Authentication failed. Please check your master password and image.")
            self.logger_service.log_auth_event("User login failed", success=False)
            self.attributes('-topmost', True)
            self.after(0, lambda: self.attributes('-topmost', False))


class PasswordRevealDialog(tk.Toplevel):
    """
    Dialog for temporarily revealing passwords.
    """

    def __init__(self, parent, password: str, title: str = "Password"):
        super().__init__(parent)
        self.password = password
        self.title(title)
        self.geometry("400x150")
        self.resizable(False, False)

        self._create_widgets()
        self.center_window()

        # Auto-close after 30 seconds
        self.after(30000, self.destroy)

    def _create_widgets(self):
        frame = ttk.Frame(self, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)

        # Password display
        self.password_var = tk.StringVar(value=self.password)
        password_entry = ttk.Entry(frame, textvariable=self.password_var,
                                 state='readonly', width=50)
        password_entry.pack(fill=tk.X, pady=(5, 10))

        # Warning
        warning_label = ttk.Label(frame,
                                text="⚠️ This dialog will close automatically in 30 seconds",
                                font=('Segoe UI', 8), foreground='red')
        warning_label.pack(anchor=tk.W, pady=(0, 10))

        # Close button
        ttk.Button(frame, text="Close", command=self.destroy).pack()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")


class ReauthDialog(tk.Toplevel):
    """
    Dialog for re-authentication when session expires.
    """

    def __init__(self, parent, auth_service, validation_service, logger_service):
        super().__init__(parent)
        self.auth_service = auth_service
        self.validation_service = validation_service
        self.logger_service = logger_service

        self.title("Session Expired - Re-authenticate")
        self.geometry("450x270")
        self.resizable(False, False)
        self.result = None

        self._create_widgets()
        self.center_window()
        self.grab_set()  # Make it modal
        self.focus_set()

        # Bind Enter key to login
        self.bind("<Return>", lambda e: self.login())
        self.bind("<Escape>", lambda e: self.cancel())

    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Warning message
        warning_frame = ttk.Frame(main_frame)
        warning_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(warning_frame, text="🔒", font=('Segoe UI', 20)).pack(side=tk.LEFT, padx=(0, 10))
        warning_text = ttk.Frame(warning_frame)
        warning_text.pack(side=tk.LEFT)

        ttk.Label(warning_text, text="Session Expired",
                 font=('Segoe UI', 12, 'bold'), foreground='red').pack(anchor=tk.W)
        ttk.Label(warning_text, text="Please re-enter your master password to continue",
                 font=('Segoe UI', 9)).pack(anchor=tk.W)

        # Password section
        ttk.Label(main_frame, text="Master Password:", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        pass_frame = ttk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 15))
        self.password_entry = ttk.Entry(pass_frame, show="•", width=40)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.password_entry.focus() 
        self.password_entry.bind("<Return>", lambda e: self.login())

        ttk.Button(pass_frame, text="Show", command=self.toggle_reauth_visibility, width=8).pack(side=tk.LEFT)

        # Image section
        ttk.Label(main_frame, text="Image-Based Password (Optional):", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
        img_frame = ttk.Frame(main_frame)
        img_frame.pack(fill=tk.X, pady=(0, 15))

        self.image_path_var = tk.StringVar(value="")
        image_entry = ttk.Entry(img_frame, textvariable=self.image_path_var, width=35, state='readonly')
        image_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Button(img_frame, text="Browse", command=self.browse_image, width=10).pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(button_frame, text="Re-authenticate", command=self.login, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=self.cancel, width=10).pack(side=tk.LEFT)

    def toggle_reauth_visibility(self):
        """Temporarily show/hide password."""
        current_show = self.password_entry.cget('show')
        if current_show == '•':
            self.password_entry.config(show='')
            self.after(3000, lambda: self.password_entry.config(show='•'))  # Hide after 3 seconds
        else:
            self.password_entry.config(show='•')


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

    def login(self):
        password = self.password_entry.get()
        image_path = self.image_path_var.get() or None

        # Validate master password
        valid, error = self.validation_service.validate_master_password(password)
        if not valid:
            messagebox.showwarning("Warning", error)
            return

        # Attempt authentication
        if self.auth_service.authenticate(password, image_path):
            self.result = {'password': password, 'image_path': image_path}
            self.logger_service.log_auth_event("Session re-authentication successful")
            self.destroy()
        else:
            messagebox.showerror("Error", "Authentication failed. Please check your master password and image.")
            self.logger_service.log_auth_event("Session re-authentication failed", success=False)

    def cancel(self):
        self.result = None
        self.destroy()