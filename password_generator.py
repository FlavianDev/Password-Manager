import secrets
import string


class PasswordGenerator:
    """
    Utility class for generating strong random passwords.
    """

    @staticmethod
    def generate(length: int = 16, use_uppercase: bool = True,
                use_lowercase: bool = True, use_numbers: bool = True,
                use_symbols: bool = True) -> str:

        if length < 1:
            raise ValueError("Password length must be at least 1")

        characters = ''

        # Ensure at least one character set is selected
        if not any([use_uppercase, use_lowercase, use_numbers, use_symbols]):
            # Default to all character sets if none specified
            use_uppercase = use_lowercase = use_numbers = use_symbols = True

        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if not characters:
            characters = string.ascii_letters + string.digits + string.punctuation

        # Generate password
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    @staticmethod
    def generate_with_requirements(length: int = 16, requirements: dict = None) -> str:
        
        if requirements is None:
            requirements = {
                'uppercase': True,
                'lowercase': True,
                'numbers': True,
                'symbols': True
            }

        return PasswordGenerator.generate(
            length=length,
            use_uppercase=requirements.get('uppercase', True),
            use_lowercase=requirements.get('lowercase', True),
            use_numbers=requirements.get('numbers', True),
            use_symbols=requirements.get('symbols', True)
        )