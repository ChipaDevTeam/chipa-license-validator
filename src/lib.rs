mod client;
mod encryption;

#[cfg(not(any(feature = "js", feature = "py")))]
pub use client::{SecureResponse as Response, TClient as LicenseClient, TError as Error};
#[cfg(not(any(feature = "js", feature = "py")))]
pub use encryption::{ChipaError, ChipaFile};

#[cfg(feature = "js")]
pub use js::LicenseClient;

#[cfg(feature = "js")]
mod js {

    use crate::client::{TClient, TError};
    use napi_derive::napi;
    use uuid::Uuid;

    impl From<TError> for napi::Error {
        fn from(e: TError) -> Self {
            napi::Error::from_reason(e.to_string())
        }
    }

    /// A client for validating licenses against the Chipa License Server.
    ///
    /// This client provides methods to validate license keys for specific applications
    /// against a license server. It handles all the necessary communication and
    /// validation protocols securely.
    ///
    /// # Example
    /// ```typescript
    /// const client = new LicenseClient("https://license.example.com");
    ///
    /// try {
    ///     const token = await client.validateLicense(
    ///         "550e8400-e29b-41d4-a716-446655440000",
    ///         "my-app"
    ///     );
    ///     console.log("License validated successfully:", token);
    /// } catch (error) {
    ///     console.error("License validation failed:", error.message);
    /// }
    /// ```
    #[napi]
    pub struct LicenseClient {
        client: TClient,
    }

    #[napi]
    impl LicenseClient {
        /// Creates a new instance of the license client.
        ///
        /// # Arguments
        /// * `baseUrl` - The base URL of the license server (e.g., "https://license.example.com")
        ///
        /// # Returns
        /// A new `LicenseClient` instance configured with the specified base URL.
        #[napi(constructor)]
        pub fn new(base_url: String) -> Self {
            Self {
                client: TClient::new(base_url),
            }
        }

        /// Updates the base URL of the license server.
        ///
        /// # Arguments
        /// * `url` - The new base URL to use for subsequent license validations
        ///
        /// # Returns
        /// A new `LicenseClient` instance with the updated URL configuration.
        #[napi(factory)]
        pub fn set_url(&self, url: String) -> Self {
            Self {
                client: self.client.clone().set_url(url),
            }
        }

        /// Validates a license key for a specific application.
        ///
        /// # Arguments
        /// * `license` - The UUID of the license to validate
        /// * `application` - The identifier of the application requesting validation
        ///
        /// # Returns
        /// A Promise that resolves to a validation token string if successful.
        ///
        /// # Throws
        /// Throws an error if:
        /// - The license UUID is invalid
        /// - The server cannot be reached
        /// - The license is invalid or expired
        /// - The application is not authorized
        #[napi]
        pub async fn validate_license(
            &self,
            license: String,
            application: String,
        ) -> napi::Result<String> {
            self.client
                .validate_license(
                    Uuid::parse_str(&license).map_err(TError::from)?,
                    application,
                )
                .await
                .map_err(|e| e.into())
        }
    }
}

#[cfg(feature = "py")]
pub mod py {
    use crate::client::{TClient, TError};
    use pyo3::{exceptions::PyException, prelude::*};
    use pyo3_stub_gen::{
        create_exception, define_stub_info_gatherer,
        derive::{gen_stub_pyclass, gen_stub_pymethods},
    };
    // use pythonize::pythonize;
    // use serde_json::Value;
    use uuid::Uuid;

    pub struct ValidationError {
        msg: String,
    }

    impl ValidationError {
        fn new(msg: String) -> Self {
            Self { msg }
        }
    }

    impl From<ValidationError> for PyErr {
        fn from(e: ValidationError) -> Self {
            PyErr::new::<LicenseValidationError, _>(e.msg)
        }
    }

    // / Exception raised when license validation fails.
    // /
    // / This exception is raised when there are issues validating a license, which can
    // / include:
    // /
    // / - Invalid license UUID format
    // / - Network connectivity issues
    // / - Server-side validation failures
    // / - Expired licenses
    // / - Unauthorized applications
    // /
    // / # Example
    // / ```python
    // / from chipa_license_validator import LicenseClient, LicenseValidationError
    // /
    // / try:
    // /     client = LicenseClient("https://license.example.com")
    // /     token = await client.validate_license(
    // /         "550e8400-e29b-41d4-a716-446655440000",
    // /         "my-app"
    // /     )
    // / except LicenseValidationError as e:
    // /     print(f"Validation failed: {str(e)}")
    // /     # Handle specific validation errors
    // / ```
    create_exception!(chipa_license_validator, LicenseValidationError, PyException);

    /// A client for validating licenses against the Chipa License Server.
    ///
    /// This client provides a Python interface for license validation operations. It handles
    /// communication with the license server, validation of license keys, and proper error
    /// handling with custom exceptions.
    ///
    /// # Features
    /// - Async license validation
    /// - Custom error handling with LicenseValidationError
    /// - Configurable server URL
    /// - Support for multiple applications
    ///
    /// # Example
    /// ```python
    /// from chipa_license_validator import LicenseClient
    ///
    /// # Create a new client
    /// client = LicenseClient("https://license.example.com")
    ///
    /// # Validate a license
    /// try:
    ///     token = await client.validate_license(
    ///         "550e8400-e29b-41d4-a716-446655440000",
    ///         "my-application"
    ///     )
    ///     print(f"License validated successfully. Token: {token}")
    /// except LicenseValidationError as e:
    ///     print(f"License validation failed: {str(e)}")
    /// ```
    #[pyclass]
    #[gen_stub_pyclass]
    pub struct LicenseClient {
        client: TClient,
        application: String,
    }

    #[gen_stub_pymethods]
    #[pymethods]
    impl LicenseClient {
        /// Creates a new LicenseClient instance.
        ///
        /// Initializes a new client that can be used to validate licenses against
        /// the specified license server.
        ///
        /// Args:
        ///     base_url (str): The base URL of the license server (e.g., "https://license.example.com")
        ///
        /// Returns:
        ///     LicenseClient: A new instance of the license client configured with the specified URL
        ///
        /// Example:
        ///     ```python
        ///     client = LicenseClient("https://license.example.com")
        ///     ```
        #[new]
        pub fn new(base_url: String, application: String) -> Self {
            Self {
                client: TClient::new(base_url),
                application,
            }
        }

        /// Updates the base URL of the license client.
        ///
        /// Creates a new client instance with an updated base URL while maintaining
        /// other configurations.
        ///
        /// Args:
        ///     url (str): The new base URL for the license server
        ///
        /// Returns:
        ///     LicenseClient: A new instance with the updated URL configuration
        ///
        /// Example:
        ///     ```python
        ///     new_client = client.set_url("https://new-license.example.com")
        ///     ```
        pub fn set_url(&self, url: String) -> Self {
            Self {
                client: self.client.clone().set_url(url),
                application: self.application.clone(),
            }
        }

        /// Validates a license against the server.
        ///
        /// Performs an asynchronous validation of the provided license key for the
        /// specified application.
        ///
        /// Args:
        ///     license (str): The license UUID to validate (must be a valid UUID string)
        ///     application (str): The application identifier requesting validation
        ///
        /// Returns:
        ///     str: A validation token that can be used to verify the license status
        ///
        /// Raises:
        ///     LicenseValidationError: If validation fails for any reason:
        ///         - Invalid license UUID format
        ///         - Network connectivity issues
        ///         - Server-side validation failures
        ///         - Expired licenses
        ///         - Unauthorized applications
        ///
        /// Example:
        ///     ```python
        ///     try:
        ///         token = await client.validate_license(
        ///             "550e8400-e29b-41d4-a716-446655440000",
        ///             "my-app"
        ///         )
        ///         print(f"Validation successful: {token}")
        ///     except LicenseValidationError as e:
        ///         print(f"Validation failed: {str(e)}")
        ///     ```
        pub fn validate_license<'py>(
            &self,
            py: Python<'py>,
            license: String,
        ) -> PyResult<Bound<'py, PyAny>> {
            let client = self.client.clone();
            let app = self.application.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                Ok(client
                    .validate_license(
                        Uuid::parse_str(&license)
                            .map_err(TError::from)
                            .map_err(|e| ValidationError::new(e.to_string()))?,
                        app,
                    )
                    .await
                    .map_err(|e| ValidationError::new(e.to_string()))?)
            })
        }

        // pub fn load<'py>(&self, py: Python<'py>, path: String, license: String) -> PyResult<Bound<'static, PyAny>> {
        //     let client = self.client.clone();
        //     let app = self.application.clone();
        //     pyo3_async_runtimes::tokio::future_into_py(py, async move {
        //         let license = client.validate_license(Uuid::parse_str(&license)
        //         .map_err(TError::from)
        //         .map_err(|e| ValidationError::new(e.to_string()))?, app)
        //         .await
        //         .map_err(|e| ValidationError::new(e.to_string()))?;
        //         Python::with_gil(|py: Python<'static>| {
        //         let file = ChipaFile::load(&path, &license)
        //             .map_err(TError::from)
        //             .map_err(|e| ValidationError::new(e.to_string()))?;
        //             let data: Value = file.read()
        //                 .map_err(TError::from)
        //                 .map_err(|e| ValidationError::new(e.to_string()))?;

        //             pythonize(py, &data).map_err(move |e| PyErr::from(e))
                    
        //         })
        //     })
        // }
    }
    #[pymodule]
    #[pyo3(name = "chipa_license_validator")]
    fn chipa(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_class::<LicenseClient>()?;
        m.add(
            "LicenseValidationError",
            py.get_type::<LicenseValidationError>(),
        )?;

        Ok(())
    }

    define_stub_info_gatherer!(stub_info); // Register the custom exception
}

