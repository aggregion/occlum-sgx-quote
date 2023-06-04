#![doc(issue_tracker_base_url = "https://github.com/aggregion/occlum-sgx/issues")]
//! Generate and verify [`SGXQuote`] with [Occlum] DCAP
//!
//! RFC: <https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
//!
//! # Generate [`SGXQuote`]
//! ```rust ignore
//! use occlum_sgx::SGXQuote;
//! let quote: SGXQuote = [0u8; 64].try_into().unwrap();
//! // or
//! let quote = SGXQuote::from_report_data(&[0u8; 64]).unwrap();
//! // convert to &[u8] and send to remote for verification
//! let quote_buf = quote.as_slice();
//! ```
//!
//! # Verify [`SGXQuote`] on remote
//! ```rust ignore
//! use occlum_sgx::SGXQuote;
//! let quote_buf: &[u8] = ...;
//! let quote = SGXQuote::from_slice(quote_buf).unwrap();
//! // verify quote
//! quote.verify().unwrap();
//! // check report data
//! assert_eq!(quote.report_data(), &[0u8; 64]);
//! // and check measurement data if required
//! ```
//!
//! [Occlum]: https://github.com/occlum/occlum
use std::fmt::Debug;
use std::mem::size_of;
use std::ops::Deref;

#[macro_use]
extern crate lazy_static;

pub use error::SGXError;
use ioctl::IOCTL_CLIENT;
use log::warn;
pub use types::*;

mod constants;
mod error;
mod ioctl;
mod types;

/// SGX Quote
pub struct SGXQuote {
    buf: Vec<u8>,
    report_body: *const SGXReportBody,
}

impl TryFrom<Vec<u8>> for SGXQuote {
    type Error = SGXError;
    fn try_from(buf: Vec<u8>) -> Result<Self, Self::Error> {
        let report_body_offset = size_of::<SGXQuoteHeader>();
        let report_body_size = size_of::<SGXReportBody>();

        if buf.len() < report_body_offset + report_body_size {
            return Err(SGXError::BadQuoteLength {
                min: report_body_offset + report_body_size,
                actual: buf.len(),
            });
        }

        let report_body = buf.as_slice()[report_body_offset..].as_ptr() as *const SGXReportBody;

        Ok(Self { buf, report_body })
    }
}

impl TryFrom<&[u8]> for SGXQuote {
    type Error = SGXError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        buf.to_vec().try_into()
    }
}

impl TryFrom<ReportData> for SGXQuote {
    type Error = SGXError;

    fn try_from(value: ReportData) -> Result<Self, Self::Error> {
        Self::from_report_data(&value)
    }
}

impl Deref for SGXQuote {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buf.as_ref()
    }
}

impl SGXQuote {
    /// Create a new [SGXQuote] from [ReportData], it needs to be run on the SGX server in an [Occlum] instance, also requires [PCCS].
    ///
    /// # Example
    /// ```rust ignore
    /// let quote = SGXQuote::from_report_data(&value).unwrap();
    /// ```
    ///
    /// [Occlum]: https://github.com/occlum/occlum
    /// [PCCS]: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/pccs/README.md
    pub fn from_report_data(data: &ReportData) -> Result<Self, SGXError> {
        let result = IOCTL_CLIENT
            .lock()
            .unwrap()
            .generate_quote(SGXReportData::new(*data))?;
        result.try_into()
    }

    /// Restore SGXQuote from slice of bytes.
    /// # Example
    /// ```rust
    /// use occlum_sgx::SGXQuote;
    /// let quote_buf: &[u8] = &[0u8; 4356];
    /// let quote = SGXQuote::from_slice(quote_buf).unwrap();
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self, SGXError> {
        slice.try_into()
    }

    pub fn as_slice(&self) -> &[u8] {
        self
    }

    /// Verify [`SGXQuote`] and return [`SGXQuoteVerifyResult`]
    ///
    /// # Example
    /// ```rust ignore
    /// let status = quote.verify().unwrap();
    /// match status {
    ///     SGXQuoteVerifyResult::Ok => println!("SGX Quote verified"),
    ///     SGXQuoteVerifyResult::ConfigNeeded
    ///     | SGXQuoteVerifyResult::OutOfDate
    ///     | SGXQuoteVerifyResult::OutOfDateConfigNeeded
    ///     | SGXQuoteVerifyResult::SwHardeningNeeded
    ///     | SGXQuoteVerifyResult::ConfigAndSwHardeningNeeded => {
    ///         println!(
    ///             "SGX Quote Verification completed with non-terminal result: {:?}",
    ///             result
    ///         )
    ///     }
    ///     _ => println!("SGX Quote Verification failed"),
    /// }
    /// ```
    pub fn verify_result(&self) -> Result<SGXQuoteVerifyResult, SGXError> {
        IOCTL_CLIENT.lock().unwrap().verify_quote(self.buf.as_ref())
    }

    /// Verify [SGXQuote], if it is not valid, return error [`SGXError::VerifyQuoteFailed`]
    ///
    /// See also [`SGXQuote::verify_result`]
    pub fn verify(&self) -> Result<(), SGXError> {
        let result = self.verify_result()?;

        match result {
            SGXQuoteVerifyResult::Ok => Ok(()),
            SGXQuoteVerifyResult::ConfigNeeded
            | SGXQuoteVerifyResult::OutOfDate
            | SGXQuoteVerifyResult::OutOfDateConfigNeeded
            | SGXQuoteVerifyResult::SwHardeningNeeded
            | SGXQuoteVerifyResult::ConfigAndSwHardeningNeeded => {
                warn!(
                    "SGX Quote Verification completed with non-terminal result: {:?}",
                    result
                );
                Ok(())
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

impl Debug for SGXQuote {
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

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn create_from_vec() {
        let quote_buf = include_bytes!("../tests/fixtures/quote.raw");
        let quote = SGXQuote::from_slice(quote_buf.as_slice()).unwrap();

        insta::assert_yaml_snapshot!(format!("{:?}", quote));
    }
}
