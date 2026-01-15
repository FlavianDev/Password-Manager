from auth_service import AuthService
from storage_service import StorageService
from validation_service import ValidationService
from config_service import ConfigService
from logger_service import LoggerService
from ui_components import LoginWindow
from main_app import PasswordManagerApp


def main():
    """Main application entry point."""
    # Initialize services
    logger_service = LoggerService()
    config_service = ConfigService()
    validation_service = ValidationService(logger_service)
    auth_service = AuthService(config_service)
    storage_service = StorageService(auth_service, logger_service)

    # Show login dialog
    login = LoginWindow(auth_service, validation_service, logger_service)
    login.mainloop()

    if login.result:
        # Load user data
        storage_service.load_credentials()

        # Start main application
        app = PasswordManagerApp(
            auth_service=auth_service,
            storage_service=storage_service,
            validation_service=validation_service,
            config_service=config_service,
            logger_service=logger_service
        )
        app.mainloop()
    else:
        logger_service.log_system_event("Application startup cancelled by user")


if __name__ == "__main__":
    main()