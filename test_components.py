#!/usr/bin/env python3
"""
Test script to validate the refactored password manager components.
"""

def print_progress(current: int = 0, max: int = 1, bar_length: int = 20):
    if max <= 0:
        print("Progress: N/A (max must be > 0)")
        return
    
    progress = (current / max) * 100
    filled = int(bar_length * current / max)
    bar = "#" * filled + "-" * (bar_length - filled)
    print(f"[{bar}] {progress:.1f}%")

def test_imports():
    """Test that all modules can be imported."""
    try:
        from auth_service import AuthService
        print_progress(current=1, max=8)
        from storage_service import StorageService, Credential
        print_progress(current=2, max=8)
        from validation_service import ValidationService
        print_progress(current=3, max=8)
        from config_service import ConfigService
        print_progress(current=4, max=8)
        from logger_service import LoggerService
        print_progress(current=5, max=8)
        from password_generator import PasswordGenerator
        print_progress(current=6, max=8)
        from ui_components import LoginWindow
        print_progress(current=7, max=8)
        from main_app import PasswordManagerApp
        print_progress(current=8, max=8)
        print("✓ All imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_services():
    """Test basic service initialization and basic functionality."""
    try:
        from config_service import ConfigService
        print_progress(current=1, max=12)
        from logger_service import LoggerService
        print_progress(current=2, max=12)
        from validation_service import ValidationService
        print_progress(current=3, max=12)
        from auth_service import AuthService
        print_progress(current=4, max=12)

        logger = LoggerService()
        print_progress(current=5, max=12)
        config = ConfigService()
        print_progress(current=6, max=12)
        validation = ValidationService(logger)
        print_progress(current=7, max=12)
        auth = AuthService(config)
        print_progress(current=8, max=12)

        # Test logger has log method
        assert hasattr(logger, 'log_system_event'), "Logger should have log_system_event method"
        print_progress(current=9, max=12)

        # Test config has get/set methods
        assert hasattr(config, 'get'), "Config should have get method"
        assert hasattr(config, 'set'), "Config should have set method"
        print_progress(current=10, max=12)

        # Test validation has validate methods
        assert hasattr(validation, 'validate_master_password'), "Validation should have validate_master_password method"
        print_progress(current=11, max=12)

        # Test auth has basic methods
        assert hasattr(auth, 'is_authenticated'), "Auth should have is_authenticated property"
        print_progress(current=12, max=12)

        print("✓ Services initialized and basic functionality tested successfully")
        return True
    except Exception as e:
        print(f"✗ Service initialization error: {e}")
        return False

def test_validation():
    """Test input validation."""
    try:
        from validation_service import ValidationService
        print_progress(current=1, max=20)
        from logger_service import LoggerService
        print_progress(current=2, max=20)

        logger = LoggerService()
        print_progress(current=3, max=20)
        validation = ValidationService(logger)
        print_progress(current=4, max=20)

        # Test master password validation
        valid, error = validation.validate_master_password("ValidPass123!")
        assert valid, f"Should be valid: {error}"
        print_progress(current=5, max=20)

        valid, error = validation.validate_master_password("short")
        assert not valid, "Should be invalid"
        print_progress(current=6, max=20)

        valid, error = validation.validate_master_password("")
        assert not valid, "Empty password should be invalid"
        print_progress(current=7, max=20)

        # Test service name validation
        valid, error = validation.validate_service_name("Google")
        assert valid, f"Valid service: {error}"
        print_progress(current=8, max=20)

        valid, error = validation.validate_service_name("")
        assert not valid, "Empty service should be invalid"
        print_progress(current=9, max=20)

        valid, error = validation.validate_service_name("Service@Invalid")
        assert not valid, "Service with invalid chars should be invalid"
        print_progress(current=10, max=20)

        # Test username validation
        valid, error = validation.validate_username("user@example.com")
        assert valid, f"Valid username: {error}"
        print_progress(current=11, max=20)

        valid, error = validation.validate_username("")
        assert not valid, "Empty username should be invalid"
        print_progress(current=12, max=20)

        valid, error = validation.validate_username("user<script>")
        assert not valid, "Username with dangerous chars should be invalid"
        print_progress(current=13, max=20)

        # Test password validation
        valid, error = validation.validate_password("short")
        assert not valid, "Short password should be invalid"
        print_progress(current=14, max=20)

        valid, error = validation.validate_password("ThisIsALongEnoughPassword123!")
        assert valid, f"Valid password: {error}"
        print_progress(current=15, max=20)

        # Test tags validation
        valid, error = validation.validate_tags("work, personal")
        assert valid, f"Valid tags: {error}"
        print_progress(current=16, max=20)

        valid, error = validation.validate_tags("tag@invalid")
        assert not valid, "Tags with invalid chars should be invalid"
        print_progress(current=17, max=20)

        # Test search query validation
        valid, error = validation.validate_search_query("google")
        assert valid, f"Valid search: {error}"
        print_progress(current=18, max=20)

        valid, error = validation.validate_search_query("query<script>")
        assert not valid, "Search with dangerous chars should be invalid"
        print_progress(current=19, max=20)

        # Test credential data validation
        valid, error = validation.validate_credential_data("Google", "user", "password123", "work", "notes")
        assert valid, f"Valid credential data: {error}"
        print_progress(current=20, max=20)

        print("✓ Validation tests passed")
        return True
    except Exception as e:
        print(f"✗ Validation test error: {e}")
        return False

def test_password_generator():
    """Test password generation."""
    try:
        from password_generator import PasswordGenerator

        # Test basic length
        password = PasswordGenerator.generate(length=12)
        assert len(password) == 12, f"Expected length 12, got {len(password)}"
        print_progress(current=1, max=12)

        # Test minimum length
        password = PasswordGenerator.generate(length=1)
        assert len(password) == 1, f"Expected length 1, got {len(password)}"
        print_progress(current=2, max=12)

        # Test lowercase only
        password = PasswordGenerator.generate(length=10, use_uppercase=False, use_numbers=False, use_symbols=False)
        assert all(char.islower() for char in password), f"Expected all lowercase, got {password}"
        print_progress(current=3, max=12)

        # Test uppercase only
        password = PasswordGenerator.generate(length=10, use_lowercase=False, use_numbers=False, use_symbols=False)
        assert all(char.isupper() for char in password), f"Expected all uppercase, got {password}"
        print_progress(current=4, max=12)

        # Test numbers only
        password = PasswordGenerator.generate(length=10, use_uppercase=False, use_lowercase=False, use_symbols=False)
        assert all(char.isdigit() for char in password), f"Expected all digits, got {password}"
        print_progress(current=5, max=12)

        # Test symbols only
        password = PasswordGenerator.generate(length=10, use_uppercase=False, use_lowercase=False, use_numbers=False)
        assert all(not char.isalnum() for char in password), f"Expected all symbols, got {password}"
        print_progress(current=6, max=12)

        # Test all types enabled
        password = PasswordGenerator.generate(length=100)
        has_lower = any(char.islower() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_symbol = any(not char.isalnum() for char in password)
        assert has_lower and has_upper and has_digit and has_symbol, f"Expected all types, got {password}"
        print_progress(current=7, max=12)

        # Test no types specified (should default to all)
        password = PasswordGenerator.generate(length=100, use_uppercase=False, use_lowercase=False, use_numbers=False, use_symbols=False)
        has_lower = any(char.islower() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_symbol = any(not char.isalnum() for char in password)
        assert has_lower and has_upper and has_digit and has_symbol, f"Expected default to all types, got {password}"
        print_progress(current=8, max=12)

        # Test invalid length
        try:
            PasswordGenerator.generate(length=0)
            assert False, "Should raise ValueError for length 0"
        except ValueError:
            pass  # Expected
        print_progress(current=9, max=12)

        # Test uniqueness (basic check)
        password1 = PasswordGenerator.generate(length=20)
        password2 = PasswordGenerator.generate(length=20)
        assert password1 != password2, "Passwords should be unique"
        print_progress(current=10, max=12)

        # Test generate_with_requirements
        reqs = {'uppercase': True, 'lowercase': False, 'numbers': False, 'symbols': False}
        password = PasswordGenerator.generate_with_requirements(length=100, requirements=reqs)
        assert all(char.isupper() for char in password), f"Expected uppercase only with requirements, got {password}"
        print_progress(current=11, max=12)

        # Test default requirements
        password = PasswordGenerator.generate_with_requirements(length=100)
        has_lower = any(char.islower() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_symbol = any(not char.isalnum() for char in password)
        assert has_lower and has_upper and has_digit and has_symbol, f"Expected all types with default requirements, got {password}"
        print_progress(current=12, max=12)

        print("✓ Password generator tests passed")
        return True
    except Exception as e:
        print(f"✗ Password generator test error: {e}")
        return False

def test_salt_handling():
    """Test salt generation and persistence."""
    try:
        import os
        import json
        from config_service import ConfigService
        from auth_service import AuthService
        
        # Clean up any existing test files
        test_salt_file = "test_salt.json"
        if os.path.exists(test_salt_file):
            os.remove(test_salt_file)

        # Create a test config and auth service with custom salt file
        config = ConfigService()
        auth = AuthService(config)
        auth.salt_file = test_salt_file  # Use test file

        # Manually call salt loading (since __init__ already did it)
        auth._load_or_create_salt()

        # Check that salt file was created
        assert os.path.exists(test_salt_file), "Salt file should be created"
        print_progress(current=1, max=5)

        # Check file contents
        with open(test_salt_file, 'r') as f:
            salt_data = json.load(f)

        assert 'salt' in salt_data, "Salt data should contain 'salt' key"
        print_progress(current=2, max=5)
        assert 'created_date' in salt_data, "Salt data should contain 'created_date' key"
        print_progress(current=3, max=5)
        assert 'version' in salt_data, "Salt data should contain 'version' key"
        print_progress(current=4, max=5)

        # Create another auth service and verify it loads the same salt
        auth2 = AuthService(config)
        auth2.salt_file = test_salt_file
        auth2._load_or_create_salt()

        assert auth.salt == auth2.salt, "Both auth services should have the same salt"
        print_progress(current=5, max=5)

        # Clean up
        if os.path.exists(test_salt_file):
            os.remove(test_salt_file)

        print("✓ Salt handling tests passed")
        return True
    except Exception as e:
        print(f"✗ Salt handling test error: {e}")
        return False

def run_tests():
    print("Testing Password Manager v2.0 Components")
    print("=" * 40)

    tests = [
        ("Imports", test_imports),
        ("Services", test_services),
        ("Validation", test_validation),
        ("Password Generator", test_password_generator),
        ("Salt Handling", test_salt_handling),
    ]

    passed = 0
    total = len(tests)

    for name, test_func in tests:
        print(f"\nTesting {name}...")
        if test_func():
            passed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! The refactored application should work correctly.")
    else:
        print("⚠️  Some tests failed. Please check the implementation.")

if __name__ == "__main__":
    run_tests()