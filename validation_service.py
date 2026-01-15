import re
import string
from typing import Optional, Tuple


class ValidationService:
    """
    Service responsible for input sanitization and validation.
    """

    # Maximum lengths for various fields
    MAX_SERVICE_LENGTH = 100
    MAX_USERNAME_LENGTH = 100
    MAX_PASSWORD_LENGTH = 100
    MAX_TAGS_LENGTH = 200
    MAX_NOTES_LENGTH = 1000
    MAX_SEARCH_LENGTH = 100

    # Minimum lengths
    MIN_PASSWORD_LENGTH = 8

    def __init__(self, logger_service):
        self.logger_service = logger_service

    def sanitize_text(self, text: str, max_length: int = None) -> str:
        """
        Sanitize text input by removing dangerous characters and trimming.
        """
        if not text:
            return ""

        # Remove null bytes and other dangerous characters
        text = text.replace('\x00', '').replace('\r', '').replace('\n', ' ')

        # Trim whitespace
        text = text.strip()

        # Limit length if specified
        if max_length and len(text) > max_length:
            text = text[:max_length]
            self.logger_service.warning(f"Text truncated to {max_length} characters")

        return text

    def validate_service_name(self, service: str) -> Tuple[bool, str]:
        """
        Validate service name.
        Returns (is_valid, error_message)
        """
        if not service:
            return False, "Service name is required"

        service = self.sanitize_text(service, self.MAX_SERVICE_LENGTH)

        if len(service) == 0:
            return False, "Service name cannot be empty"

        if len(service) > self.MAX_SERVICE_LENGTH:
            return False, f"Service name too long (max {self.MAX_SERVICE_LENGTH} characters)"

        # Allow alphanumeric, spaces, hyphens, underscores, dots
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', service):
            return False, "Service name contains invalid characters"

        return True, ""

    def validate_username(self, username: str) -> Tuple[bool, str]:
        """
        Validate username.
        Returns (is_valid, error_message)
        """
        if not username:
            return False, "Username is required"

        username = self.sanitize_text(username, self.MAX_USERNAME_LENGTH)

        if len(username) == 0:
            return False, "Username cannot be empty"

        if len(username) > self.MAX_USERNAME_LENGTH:
            return False, f"Username too long (max {self.MAX_USERNAME_LENGTH} characters)"

        # Allow most characters but prevent obviously dangerous ones
        dangerous_chars = ['<', '>', '"', "'", '\x00', '\r', '\n']
        if any(char in username for char in dangerous_chars):
            return False, "Username contains invalid characters"

        return True, ""

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password.
        Returns (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"

        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters long"

        if len(password) > self.MAX_PASSWORD_LENGTH:
            return False, f"Password too long (max {self.MAX_PASSWORD_LENGTH} characters)"

        return True, ""

    def validate_tags(self, tags: str) -> Tuple[bool, str]:
        """
        Validate tags string.
        Returns (is_valid, error_message)
        """
        if not tags:
            return True, ""  # Tags are optional

        tags = self.sanitize_text(tags, self.MAX_TAGS_LENGTH)

        if len(tags) > self.MAX_TAGS_LENGTH:
            return False, f"Tags too long (max {self.MAX_TAGS_LENGTH} characters)"

        # Allow alphanumeric, spaces, commas, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9\s\-_,]*$', tags):
            return False, "Tags contain invalid characters"

        return True, ""

    def validate_notes(self, notes: str) -> Tuple[bool, str]:
        """
        Validate notes.
        Returns (is_valid, error_message)
        """
        if not notes:
            return True, ""  # Notes are optional

        notes = self.sanitize_text(notes, self.MAX_NOTES_LENGTH)

        if len(notes) > self.MAX_NOTES_LENGTH:
            return False, f"Notes too long (max {self.MAX_NOTES_LENGTH} characters)"

        return True, ""

    def validate_search_query(self, query: str) -> Tuple[bool, str]:
        """
        Validate search query.
        Returns (is_valid, error_message)
        """
        if not query:
            return True, ""  # Empty search is valid

        query = self.sanitize_text(query, self.MAX_SEARCH_LENGTH)

        if len(query) > self.MAX_SEARCH_LENGTH:
            return False, f"Search query too long (max {self.MAX_SEARCH_LENGTH} characters)"

        # Allow most characters for search
        dangerous_chars = ['<', '>', '"', "'", '\x00']
        if any(char in query for char in dangerous_chars):
            return False, "Search query contains invalid characters"

        return True, ""

    def validate_master_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate master password.
        Returns (is_valid, error_message)
        """
        if not password:
            return False, "Master password is required"

        if len(password) < 8:
            return False, "Master password must be at least 8 characters long"

        if len(password) > 128:  # Reasonable limit for master password
            return False, "Master password too long (max 128 characters)"

        return True, ""

    def validate_credential_data(self, service: str, username: str, password: str,
                               tags: str = "", notes: str = "") -> Tuple[bool, str]:
        """
        Validate all credential data at once.
        Returns (is_valid, error_message)
        """
        # Validate service
        valid, error = self.validate_service_name(service)
        if not valid:
            return False, error

        # Validate username
        valid, error = self.validate_username(username)
        if not valid:
            return False, error

        # Validate password
        valid, error = self.validate_password(password)
        if not valid:
            return False, error

        # Validate tags
        valid, error = self.validate_tags(tags)
        if not valid:
            return False, error

        # Validate notes
        valid, error = self.validate_notes(notes)
        if not valid:
            return False, error

        return True, ""