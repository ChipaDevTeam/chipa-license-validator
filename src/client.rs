use core::fmt;

use reqwest_wasm::{
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client, Method, StatusCode,
};
use serde::{
    de::{DeserializeOwned, Error},
    Deserialize, Serialize,
};
use tenacity_utils::security::{headers::VERSION as VERSION_STR, TenacityMiddleware, Version};
use uuid::Uuid;

const VERSION: Version = Version::V1;

#[derive(thiserror::Error, Debug)]
pub enum TError {
    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Parsing error: {0}")]
    Parsing(#[from] serde_json::Error),
    #[error("Request error: {0}")]
    Request(#[from] reqwest_wasm::Error),
    #[error("Response error: {0}")]
    Response(#[from] ApiError),
    #[error("UUID Parsing error: {0}")]
    UuidParsing(#[from] uuid::Error),
}

#[derive(Deserialize, Debug)]
pub struct ApiError {
    pub error: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for ApiError {}

pub type SecureResult<T> = Result<T, TError>;
#[derive(Clone)]
pub struct SecureResponse {
    pub status: StatusCode,
    body: Option<String>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ValidateResponse {
    #[serde(rename = "success")]
    _success: String,
    token: String,
}

#[derive(Clone)]
pub struct TClient {
    inner: Client,
    base_url: String,
}

impl TClient {
    pub fn new(base: String) -> Self {
        Self {
            inner: Client::new(),
            base_url: base,
        }
    }

    pub fn set_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    async fn _send_secure<T: Serialize>(
        &self,
        url: String,
        body: Option<T>,
        method: Method,
        id: Uuid,
    ) -> SecureResult<SecureResponse> {
        let encryptor = VERSION.encryptor();
        let id_header = encryptor.encrypt_header(id).await?;
        let request = self
            .inner
            .request(method, url.to_string())
            .header(AUTHORIZATION, id_header)
            .header(VERSION_STR, "v1");
        // .header("Agents", json!(agents).to_string());

        let req = match body {
            Some(body) => request
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(
                    encryptor
                        .encrypt(id, &serde_json::to_string(&body)?)
                        .await?,
                ),
            None => request,
        };

        let response = self.inner.execute(req.build()?).await?;
        let status = response.status();
        let body = response.text().await?;
        match body.is_empty() {
            true => Ok(SecureResponse { status, body: None }),
            false => {
                let decrypted_body = encryptor.decrypt(id, &body).await?.clone();
                Ok(SecureResponse {
                    status,
                    body: Some(decrypted_body),
                })
            }
        }
    }

    pub async fn validate_license(
        &self,
        license: Uuid,
        application: String,
    ) -> SecureResult<String> {
        let url = format!(
            "{}/subscriptions/validateapp/{}/{}",
            self.base_url, license, application
        );
        let req = self
            ._send_secure::<()>(url, None, Method::GET, license)
            .await?;
        if req.status.is_success() {
            let body = req.json::<ValidateResponse>()?.token;
            Ok(body)
        } else {
            let body = req.json::<ApiError>()?;
            Err(TError::from(body))
        }
    }


}

impl SecureResponse {
    pub fn json<T>(&self) -> SecureResult<T>
    where
        T: Send + DeserializeOwned,
    {
        match &self.body {
            Some(body) => Ok(serde_json::from_str(body)?),
            None => Err(TError::from(serde_json::Error::custom(
                "Expected body to be some found none",
            ))),
        }
    }
}
