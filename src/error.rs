use crate::types::SGXQuoteVerifyResult;
use std::{error, fmt::Display};

#[derive(Debug)]
pub enum SGXError {
    DeviceOpenFailed(&'static str),
    BadQuoteLength {
        min: usize,
        actual: usize,
    },
    IoctlClientError {
        request_type: &'static str,
        ret: i32,
    },
    SGXMeasurementParseError(String),
    VerifyQuoteFailed(SGXQuoteVerifyResult),
}

impl Display for SGXError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SGXError::BadQuoteLength { min, actual } => {
                write!(f, "Bad report length (actual: {}, min: {})", actual, min)
            }
            SGXError::IoctlClientError { request_type, ret } => {
                write!(f, "Failed {} with code {}", request_type, ret)
            }
            SGXError::VerifyQuoteFailed(result) => {
                write!(f, "Quote verification failed: {:?}", result)
            }
            SGXError::DeviceOpenFailed(path) => {
                write!(f, "Failed to open {}", path)
            }
            SGXError::SGXMeasurementParseError(msg) => {
                write!(f, "Failed to parse SGX measurement: {}", msg)
            }
        }
    }
}

impl error::Error for SGXError {}
