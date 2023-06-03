use std::{error, fmt::Display};

use crate::types::SGXQuoteVerifyResult;

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
        }
    }
}

impl error::Error for SGXError {}
