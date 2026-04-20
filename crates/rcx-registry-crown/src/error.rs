use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CrownError {
    #[error("decode: {0}")]
    Decode(String),
    #[error("bad signature")]
    BadSignature,
    #[error("public key must be 32 bytes, got {0}")]
    PublicKeyLength(usize),
}
