//! The KMS activation payloads: the request a client sends, the response a
//! host returns, and the vocabulary both are made of.
//!
//! The DCE/RPC framing that carries them lives in [`crate::wire`]; this module
//! is about what is inside the stub.

pub mod hresult;
pub mod status;
pub mod version;

pub use hresult::HResult;
pub use status::LicenseStatus;
pub use version::{ProtocolVersion, Version};
