# This file is automatically generated by pyo3_stub_gen
# ruff: noqa: E501, F401

import builtins
import typing

class LicenseClient:
    r"""
    A client for validating licenses against the Chipa License Server.
    
    This client provides a Python interface for license validation operations. It handles
    communication with the license server, validation of license keys, and proper error
    handling with custom exceptions.
    
    # Features
    - Async license validation
    - Custom error handling with LicenseValidationError
    - Configurable server URL
    - Support for multiple applications
    
    # Example
    ```python
    from chipa_license_validator import LicenseClient
    
    # Create a new client
    client = LicenseClient("https://license.example.com")
    
    # Validate a license
    try:
        token = await client.validate_license(
            "550e8400-e29b-41d4-a716-446655440000",
            "my-application"
        )
        print(f"License validated successfully. Token: {token}")
    except LicenseValidationError as e:
        print(f"License validation failed: {str(e)}")
    ```
    """
    def __new__(cls,base_url:builtins.str): ...
    def set_url(self, url:builtins.str) -> LicenseClient:
        r"""
        Updates the base URL of the license client.
        
        Creates a new client instance with an updated base URL while maintaining
        other configurations.
        
        Args:
            url (str): The new base URL for the license server
        
        Returns:
            LicenseClient: A new instance with the updated URL configuration
        
        Example:
            ```python
            new_client = client.set_url("https://new-license.example.com")
            ```
        """
        ...

    def validate_license(self, license:builtins.str, application:builtins.str) -> typing.Any:
        r"""
        Validates a license against the server.
        
        Performs an asynchronous validation of the provided license key for the
        specified application.
        
        Args:
            license (str): The license UUID to validate (must be a valid UUID string)
            application (str): The application identifier requesting validation
        
        Returns:
            str: A validation token that can be used to verify the license status
        
        Raises:
            LicenseValidationError: If validation fails for any reason:
                - Invalid license UUID format
                - Network connectivity issues
                - Server-side validation failures
                - Expired licenses
                - Unauthorized applications
        
        Example:
            ```python
            try:
                token = await client.validate_license(
                    "550e8400-e29b-41d4-a716-446655440000",
                    "my-app"
                )
                print(f"Validation successful: {token}")
            except LicenseValidationError as e:
                print(f"Validation failed: {str(e)}")
            ```
        """
        ...


class LicenseValidationError(Exception): ...

