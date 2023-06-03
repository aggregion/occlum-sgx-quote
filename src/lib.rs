use std::fmt::Debug;
use std::mem::size_of;

#[macro_use]
extern crate lazy_static;

use error::SGXError;
use ioctl::IOCTL_CLIENT;
use types::{
    SGXConfigId, SGXExtProdId, SGXFamilyId, SGXMeasurement, SGXQuoteHeader, SGXQuoteVerifyResult,
    SGXReportBody, SGXReportData,
};

mod constants;
mod error;
mod ioctl;
mod types;

pub struct SGXQuoteBuilder {}

impl SGXQuoteBuilder {
    pub fn generate_bytes(data: &str) -> Result<Vec<u8>, SGXError> {
        let result = IOCTL_CLIENT
            .lock()
            .unwrap()
            .generate_quote(SGXReportData::from_str(data))?;
        Ok(result)
    }
}

pub struct SGXQuote<'a> {
    buf: &'a [u8],
    report_body: *const SGXReportBody,
}

impl<'a> TryFrom<&'a Vec<u8>> for SGXQuote<'a> {
    type Error = SGXError;
    fn try_from(value: &'a Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for SGXQuote<'a> {
    type Error = SGXError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let report_body_offset = size_of::<SGXQuoteHeader>();
        let report_body_size = size_of::<SGXReportBody>();

        if buf.len() < report_body_offset + report_body_size {
            return Err(SGXError::BadQuoteLength {
                min: buf.len(),
                actual: report_body_offset + report_body_size,
            });
        }

        Ok(Self {
            buf,
            report_body: (buf[report_body_offset..]).as_ptr() as _,
        })
    }
}

impl SGXQuote<'_> {
    pub fn as_slice(&self) -> &[u8] {
        self.buf
    }

    pub fn verify(&self) -> Result<bool, SGXError> {
        let result = IOCTL_CLIENT.lock().unwrap().verify_quote(self.buf)?;

        match result {
            SGXQuoteVerifyResult::Ok => Ok(true),
            SGXQuoteVerifyResult::ConfigNeeded
            | SGXQuoteVerifyResult::OutOfDate
            | SGXQuoteVerifyResult::OutOfDateConfigNeeded
            | SGXQuoteVerifyResult::SwHardeningNeeded
            | SGXQuoteVerifyResult::ConfigAndSwHardeningNeeded => {
                // TODO: add logging here
                Ok(true)
            }
            _ => Err(SGXError::VerifyQuoteFailed(result)),
        }
    }

    pub fn isv_family_id(&self) -> SGXFamilyId {
        unsafe { (*self.report_body).isv_family_id }
    }

    pub fn isv_ext_prod_id(&self) -> SGXExtProdId {
        unsafe { (*self.report_body).isv_ext_prod_id }
    }

    pub fn config_id(&self) -> SGXConfigId {
        unsafe { (*self.report_body).config_id }
    }

    pub fn mrenclave(&self) -> SGXMeasurement {
        unsafe { (*self.report_body).mr_enclave }
    }

    pub fn mrsigner(&self) -> SGXMeasurement {
        unsafe { (*self.report_body).mr_signer }
    }

    pub fn product_id(&self) -> u16 {
        unsafe { (*self.report_body).isv_prod_id }
    }

    pub fn version(&self) -> u16 {
        unsafe { (*self.report_body).isv_svn }
    }

    pub fn report_data(&self) -> SGXReportData {
        unsafe { (*self.report_body).report_data }
    }
}

impl Debug for SGXQuote<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SGXQuote")
            .field("mrenclave", &self.mrenclave())
            .field("mrsigner", &self.mrsigner())
            .field("report_body", &self.report_data())
            .field("product_id", &self.product_id())
            .field("version", &self.version())
            .field("family_id", &self.isv_family_id())
            .field("ext_prod_id", &self.isv_ext_prod_id())
            .field("config_id", &self.config_id())
            .finish()
    }
}
