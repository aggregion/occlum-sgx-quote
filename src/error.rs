use std::{error, fmt::Display};

#[derive(Debug)]
pub enum OcclumSgxError {
    BadQuoteLength { min: usize, actual: usize },
}

impl Display for OcclumSgxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OcclumSgxError::BadQuoteLength { min, actual } => {
                write!(f, "Bad report length (actual: {}, min: {})", actual, min)
            }
        }
    }
}

impl error::Error for OcclumSgxError {}
