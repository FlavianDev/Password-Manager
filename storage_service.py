import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from cryptography.fernet import Fernet

from auth_service import AuthService


class Credential:
    """Represents a credential entry."""

    def __init__(self, service: str, username: str, password: str,
                 notes: str = "", tags: str = "", created_date: str = None, 
                 text_color: str = "", row_bg_color: str = "", favorite: bool = False):
        self.service = service
        self.username = username
        self.password = password
        self.notes = notes
        self.tags = tags
        self.text_color = text_color
        self.row_bg_color = row_bg_color
        self.favorite = favorite
        self.created_date = created_date or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            'service': self.service,
            'username': self.username,
            'password': self.password,
            'notes': self.notes,
            'tags': self.tags,
            'text_color': self.text_color,
            'row_bg_color': self.row_bg_color,
            'favorite': self.favorite,
            'created_date': self.created_date
        }

    @staticmethod
    def from_dict(data):
        return Credential(**data)


class StorageService:
    """
    Service responsible for encrypted persistence, add/edit/delete operations,
    backups, and restores.
    """

    def __init__(self, auth_service: AuthService, logger_service, filepath: str = "credentials.enc"):
        self.auth_service = auth_service
        self.logger_service = logger_service
        self.filepath = filepath
        self.credentials: List[Credential] = []
        self.failed_load = False

    def load_credentials(self, silent: bool = False) -> bool:
        """Load credentials from encrypted file."""
        if not self.auth_service.is_authenticated:
            if not silent:
                self.logger_service.error("Cannot load credentials: not authenticated")
            return False

        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    encrypted_data = f.read()

                cipher = self.auth_service.get_cipher()
                decrypted_data = cipher.decrypt(encrypted_data.encode())
                data = json.loads(decrypted_data.decode())
                self.credentials = [Credential.from_dict(cred) for cred in data]
                self.failed_load = False

                if not silent:
                    self.logger_service.info("Credentials loaded successfully")
                return True

            except Exception as e:
                if not silent:
                    self.logger_service.error(f"Error loading credentials: {e}")
                self.failed_load = True
                return False
        else:
            # No existing file, start with empty credentials
            self.credentials = []
            return True

    def save_credentials(self) -> bool:
        """Save credentials to encrypted file."""
        if not self.auth_service.is_authenticated:
            self.logger_service.error("Cannot save credentials: not authenticated")
            return False

        try:
            data = [cred.to_dict() for cred in self.credentials]
            cipher = self.auth_service.get_cipher()
            encrypted_data = cipher.encrypt(json.dumps(data).encode())

            with open(self.filepath, 'w') as f:
                f.write(encrypted_data.decode())

            self.logger_service.info("Credentials saved successfully")
            return True

        except Exception as e:
            self.logger_service.error(f"Error saving credentials: {e}")
            return False

    def add_credential(self, credential: Credential) -> bool:
        """Add a new credential."""
        self.credentials.append(credential)
        success = self.save_credentials()
        if success:
            self.logger_service.info(f"Credential added for service: [{credential.service} | {credential.username}]")
        return success

    def update_credential(self, index: int, credential: Credential) -> bool:
        """Update existing credential at index."""
        if 0 <= index < len(self.credentials):
            old_service = self.credentials[index].service
            old_username = self.credentials[index].username
            self.credentials[index] = credential
            success = self.save_credentials()
            if success:
                self.logger_service.info(f"Credential updated: [{old_service} | {old_username}] -> [{credential.service} | {credential.username}]")
            return success
        return False

    def delete_credential(self, index: int) -> bool:
        """Delete credential at index."""
        if 0 <= index < len(self.credentials):
            service = self.credentials[index].service
            username = self.credentials[index].username
            del self.credentials[index]
            success = self.save_credentials()
            if success:
                self.logger_service.info(f"Credential deleted: [{service} | {username}]")
            return success
        return False

    def search_credentials(self, query: str) -> List[Credential]:
        """Search credentials by service, username, or tags."""
        if not query:
            return self.credentials

        query = query.lower()
        return [cred for cred in self.credentials
                if query in cred.service.lower() or
                   query in cred.username.lower() or
                   query in cred.tags.lower() or
                   query in cred.created_date.lower()]

    def get_credentials_by_tag(self, tag: str) -> List[Credential]:
        """Get credentials filtered by tag."""
        return [cred for cred in self.credentials if tag.lower() in cred.tags.lower()]

    def export_backup(self, filepath: str) -> bool:
        """Export encrypted credentials to backup file."""
        try:
            if os.path.exists(self.filepath):
                shutil.copy2(self.filepath, filepath)
                self.logger_service.info(f"Backup exported to: {filepath}")
                return True
            else:
                self.logger_service.error("No credentials file to backup")
                return False
        except Exception as e:
            self.logger_service.error(f"Error exporting backup: {e}")
            return False

    def create_auto_backup(self) -> bool:
        """Create automatic backup with timestamp."""
        try:
            if not os.path.exists(self.filepath):
                return True  # No data to backup yet

            # Create backups directory if it doesn't exist
            backup_dir = "backups"
            os.makedirs(backup_dir, exist_ok=True)

            # Create timestamped filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"credentials_backup_{timestamp}.enc"
            backup_path = os.path.join(backup_dir, backup_filename)

            # Copy the encrypted file
            shutil.copy2(self.filepath, backup_path)

            # Clean up old backups (keep only last 10)
            self._cleanup_old_backups(backup_dir)

            self.logger_service.info(f"Auto backup created: {backup_path}")
            return True

        except Exception as e:
            self.logger_service.error(f"Error creating auto backup: {e}")
            return False

    def _cleanup_old_backups(self, backup_dir: str, max_backups: int = 10):
        """Clean up old backup files, keeping only the most recent ones."""
        try:
            backup_files = [f for f in os.listdir(backup_dir) if f.startswith("credentials_backup_") and f.endswith(".enc")]
            if len(backup_files) > max_backups:
                # Sort by modification time (newest first)
                backup_files.sort(key=lambda x: os.path.getmtime(os.path.join(backup_dir, x)), reverse=True)
                # Remove excess files
                for old_file in backup_files[max_backups:]:
                    os.remove(os.path.join(backup_dir, old_file))
                    self.logger_service.info(f"Removed old backup: {old_file}")
        except Exception as e:
            self.logger_service.error(f"Error cleaning up old backups: {e}")

    def import_backup(self, filepath: str) -> bool:
        """Import encrypted credentials from backup file."""
        try:
            if os.path.exists(filepath):
                shutil.copy2(filepath, self.filepath)
                success = self.load_credentials()
                if success:
                    self.logger_service.info(f"Backup imported from: {filepath}")
                return success
            else:
                self.logger_service.error("Backup file does not exist")
                return False
        except Exception as e:
            self.logger_service.error(f"Error importing backup: {e}")
            return False

    def clear_all_data(self) -> bool:
        """Clear all stored credentials."""
        try:
            if os.path.exists(self.filepath):
                os.remove(self.filepath)
            self.credentials = []
            self.logger_service.info("All data cleared")
            return True
        except Exception as e:
            self.logger_service.error(f"Error clearing data: {e}")
            return False