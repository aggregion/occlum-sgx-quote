use std::{error, fmt::Display};

#[derive(Debug)]
pub enum SgxError {
    BadQuoteLength { min: usize, actual: usize },
}

impl Display for SgxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SgxError::BadQuoteLength { min, actual } => {
                write!(f, "Bad report length (actual: {}, min: {})", actual, min)
            }
        }
    }
}

impl error::Error for SgxError {}
