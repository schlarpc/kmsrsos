//! The KMS activation payloads: the request a client sends, the response a
//! host returns, and the vocabulary both are made of.
//!
//! The DCE/RPC framing that carries them lives in [`crate::wire`]; this module
//! is about what is inside the stub.

pub mod epid;
pub mod framing;
pub mod hresult;
pub mod layout;
pub mod request;
pub mod response;
pub mod status;
pub mod validate;
pub mod version;

pub use epid::EPid;
pub use framing::{Ciphers, DecodedRequest, ResponsePlan};
pub use hresult::HResult;
pub use request::{Request, RequestError};
pub use status::LicenseStatus;
pub use version::{ProtocolVersion, Version};
