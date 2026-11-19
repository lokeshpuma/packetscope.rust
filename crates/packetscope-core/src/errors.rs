use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CaptureError {
    #[error("Invalid capture header: {0}")]
    InvalidHeader(String),

    #[error("Unsupported capture format: {0}")]
    UnsupportedFormat(String),

    #[error("Corrupted PCAPNG block at offset {offset}: {reason}")]
    CorruptedBlock { offset: usize, reason: String },

    #[error("Incomplete packet record: expected {expected} bytes, found {found}")]
    IncompleteRecord { expected: usize, found: usize },

    #[error("Unsupported link-layer type: {0}")]
    UnsupportedLinkType(u16),

    #[error("Capture contains no packets")]
    EmptyCapture,

    #[error("File exceeds maximum browser memory limit: {0} bytes")]
    FileTooLarge(u64),

    #[error("Parsing error: {0}")]
    ParseError(String),
}

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum FilterError {
    #[error("Syntax error at position {position}: {message}")]
    SyntaxError { position: usize, message: String },

    #[error("Unknown field: '{0}'")]
    UnknownField(String),

    #[error("Invalid operator '{op}' for field '{field}'")]
    InvalidOperator { field: String, op: String },

    #[error("Invalid value '{value}' for field '{field}': {reason}")]
    InvalidValue {
        field: String,
        value: String,
        reason: String,
    },

    #[error("Filter expression too long (max {0} characters)")]
    ExpressionTooLong(usize),

    #[error("Nesting depth exceeds maximum limit of {0}")]
    NestingTooDeep(usize),
}
