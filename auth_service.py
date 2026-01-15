import os
import json
import base64
import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path


class AuthService:
    """
    Service responsible for authentication, master-password verification,
    key derivation, and session timeout management.
    """

    def __init__(self, config_service):
        self.config_service = config_service
        self.session_start_time = None
        self.is_authenticated = False
        self.master_password_hash = None
        self.encryption_key = None
        self.salt = None
        self.salt_file = "salt.json"
        self.user_data_file = "user_data.enc"

        # Load or create salt
        self._load_or_create_salt()

    def _load_or_create_salt(self):
        """Load existing salt from JSON file or create new if first run."""
        if os.path.exists(self.salt_file):
            try:
                with open(self.salt_file, 'r') as f:
                    salt_data = json.load(f)
                self.salt = base64.b64decode(salt_data['salt'])
            except Exception as e:
                # If we can't load the salt, generate a new one
                print(f"Warning: Could not load salt file: {e}. Generating new salt.")
                self._generate_and_save_salt()
        else:
            # First run - generate new salt
            self._generate_and_save_salt()

    def _generate_and_save_salt(self):
        """Generate a new salt and save it to JSON file."""
        self.salt = secrets.token_bytes(64)
        salt_data = {
            'salt': base64.b64encode(self.salt).decode(),
            'created_date': datetime.now().isoformat(),
            'version': '1.0'
        }

        try:
            with open(self.salt_file, 'w') as f:
                json.dump(salt_data, f, indent=4)
        except Exception as e:
            raise Exception(f"Failed to save salt file: {e}")

    def authenticate(self, master_password: str, image_path: str = None) -> bool:
        """
        Authenticate user with master password and optional image.
        Returns True if authentication successful.
        """
        if not master_password or len(master_password) < 8:
            return False

        try:
            # Salt is already loaded/generated in __init__

            # Create image hash if provided
            image_hash = ""
            if image_path and os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    data = f.read()
                image_hash = hashlib.sha256(data).hexdigest()

            # Combine password with image hash
            combined_password = master_password + image_hash

            # Derive key using the loaded salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(combined_password.encode()))
            self.encryption_key = key

            # Create hash for password verification
            self.master_password_hash = hashlib.sha256((master_password + str(self.salt)).encode()).hexdigest()

            # Try to load existing data to verify
            if os.path.exists(self.user_data_file):
                try:
                    with open(self.user_data_file, 'r') as f:
                        encrypted_data = f.read()
                    cipher = Fernet(key)
                    decrypted_data = cipher.decrypt(encrypted_data.encode())
                    user_data = json.loads(decrypted_data.decode())

                    # Verify stored hash matches
                    if user_data.get('password_hash') != self.master_password_hash:
                        return False

                    self.session_start_time = datetime.now()
                    self.is_authenticated = True
                    return True
                except Exception:
                    # If decryption fails, this might be first run or wrong password
                    return False
            else:
                # First run - create user data
                self._create_user_data()
                self.session_start_time = datetime.now()
                self.is_authenticated = True
                return True

        except Exception:
            return False

    def _create_user_data(self):
        """Create initial user data file."""
        user_data = {
            'password_hash': self.master_password_hash,
            'created_date': datetime.now().isoformat(),
            'version': '1.0'
        }

        cipher = Fernet(self.encryption_key)
        encrypted_data = cipher.encrypt(json.dumps(user_data).encode())

        with open(self.user_data_file, 'w') as f:
            f.write(encrypted_data.decode())

    def is_session_valid(self) -> bool:
        """Check if current session is still valid based on timeout."""
        if not self.is_authenticated or not self.session_start_time:
            return False

        session_timeout = self.config_service.get_session_timeout()
        if session_timeout <= 0:
            return True  # No timeout

        elapsed = datetime.now() - self.session_start_time
        return elapsed < timedelta(seconds=session_timeout)

    def refresh_session(self):
        """Refresh the session timer."""
        if self.is_authenticated:
            self.session_start_time = datetime.now()

    def logout(self):
        """Clear authentication state."""
        self.is_authenticated = False
        self.session_start_time = None
        self.encryption_key = None
        self.master_password_hash = None

    def get_cipher(self) -> Fernet:
        """Get the encryption cipher for current session."""
        if not self.is_authenticated or not self.encryption_key:
            raise ValueError("Not authenticated")
        return Fernet(self.encryption_key)

    def change_master_password(self, old_password: str, new_password: str, image_path: str = None) -> bool:
        """Change master password. Requires current authentication."""
        if not self.is_authenticated:
            return False

        # Verify old password
        if not self.authenticate(old_password, image_path):
            return False

        # Set new password (salt remains the same)
        return self.authenticate(new_password, image_path)