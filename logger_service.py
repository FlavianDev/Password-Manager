import logging
import os
import ctypes
from datetime import datetime
from pathlib import Path


class LoggerService:
    """
    Service responsible for logging operations.
    """

    def __init__(self, log_file: str = "password_manager.log", level: int = logging.INFO):
        self.log_file = log_file
        self.level = level
        self._setup_logger()

    def _setup_logger(self):
        """Setup the logger with file and console handlers."""
        # Create logger
        self.logger = logging.getLogger('PasswordManager')
        self.logger.setLevel(self.level)

        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )

        # File handler
        try:
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            file_handler.setLevel(self.level)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
            # Make the log file hidden on Windows
            if os.name == 'nt':
                ctypes.windll.kernel32.SetFileAttributesW(self.log_file, 2)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")

        # Console handler (optional, for debugging)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)  # Only show warnings and errors in console
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(message)

    def info(self, message: str):
        """Log info message."""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message."""
        self.logger.error(message)

    def critical(self, message: str):
        """Log critical message."""
        self.logger.critical(message)

    def log_auth_event(self, event: str, success: bool = True):
        """Log authentication-related events."""
        status = "SUCCESS" if success else "FAILED"
        self.info(f"AUTH {status}: {event}")

    def log_credential_operation(self, operation: str, service: str, username: str, success: bool = True):
        """Log credential operations."""
        status = "SUCCESS" if success else "FAILED"
        self.info(f"CREDENTIAL {status} - {operation}: [{service} | {username}]")

    def log_security_event(self, event: str):
        """Log security-related events."""
        self.warning(f"SECURITY: {event}")

    def log_system_event(self, event: str):
        """Log system-related events."""
        self.info(f"SYSTEM: {event}")

    def get_log_path(self) -> str:
        """Get the path to the log file."""
        return os.path.abspath(self.log_file)

    def open_logs(self) -> bool:
        """Open the log file in the default application."""
        try:
            log_path = self.get_log_path()
            if os.path.exists(log_path):
                os.startfile(log_path)  # Windows specific
                return True
            else:
                self.warning("Log file does not exist")
                return False
        except Exception as e:
            self.error(f"Failed to open log file: {e}")
            return False