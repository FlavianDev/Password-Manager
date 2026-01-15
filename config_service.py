import os
import json
from typing import Any, Dict


class ConfigService:
    """
    Service responsible for configuration management.
    """

    DEFAULT_CONFIG = {
        "password_length": 16,
        "use_uppercase": True,
        "use_lowercase": True,
        "use_numbers": True,
        "use_symbols": True,
        "session_timeout": 120,  # 2 minutes in seconds
        "idle_timeout": 60000,   # 1 minute in milliseconds (for UI)
        "minimize_ends_session": True,
        "clipboard_timeout": 30,
        "auto_backup": True
    }

    def __init__(self, config_file: str = "settings.json"):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or return defaults."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                # Merge with defaults to ensure all keys exist
                config = self.DEFAULT_CONFIG.copy()
                config.update(loaded_config)
                return config
            except Exception:
                # If loading fails, use defaults
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            self._save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception:
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        """Set configuration value and save."""
        self.config[key] = value
        return self._save_config(self.config)

    def get_session_timeout(self) -> int:
        """Get session timeout in seconds."""
        return self.get("session_timeout", 120)

    def set_session_timeout(self, seconds: int) -> bool:
        """Set session timeout in seconds."""
        return self.set("session_timeout", seconds)

    def get_idle_timeout(self) -> int:
        """Get idle timeout in milliseconds."""
        return self.get("idle_timeout", 60000)

    def get_clipboard_timeout(self) -> int:
        """Get clipboard timeout in seconds."""
        return self.get("clipboard_timeout", 30)

    def get_minimize_ends_session(self) -> bool:
        """Get minimize ends session setting."""
        return self.get("minimize_ends_session", True)

    def get_auto_backup_enabled(self) -> bool:
        """Get auto backup enabled setting."""
        return self.get("auto_backup", True)
    
    def get_password_generator_settings(self) -> Dict[str, Any]:
        """Get password generator settings."""
        return {
            "length": self.get("password_length", 16),
            "use_uppercase": self.get("use_uppercase", True),
            "use_lowercase": self.get("use_lowercase", True),
            "use_numbers": self.get("use_numbers", True),
            "use_symbols": self.get("use_symbols", True)
        }

    def update_password_generator_settings(self, settings: Dict[str, Any]) -> bool:
        """Update password generator settings."""
        # Map short keys to full config keys
        key_mapping = {
            'length': 'password_length',
            'use_uppercase': 'use_uppercase',
            'use_lowercase': 'use_lowercase',
            'use_numbers': 'use_numbers',
            'use_symbols': 'use_symbols'
        }

        success = True
        for key, value in settings.items():
            config_key = key_mapping.get(key, key)
            success &= self.set(config_key, value)
        return success

    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults."""
        self.config = self.DEFAULT_CONFIG.copy()
        return self._save_config(self.config)

    def get_all_settings(self) -> Dict[str, Any]:
        """Get all current settings."""
        return self.config.copy()