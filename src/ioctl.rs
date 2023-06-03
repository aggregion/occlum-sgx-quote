use crate::types::{SGXReportData, SgxQuoteVerifyResult};

#[repr(C)]
#[derive(Debug)]
pub struct IoctlGenDCAPQuoteArg {
    pub report_data: *const SGXReportData, // Input
    pub quote_size: *mut u32,              // Input/output
    pub quote_buf: *mut u8,                // Output
}

#[repr(C)]
pub struct IoctlVerDCAPQuoteArg {
    pub quote_buf: *const u8,                                 // Input
    pub quote_size: u32,                                      // Input
    pub collateral_expiration_status: *mut u32,               // Output
    pub quote_verification_result: *mut SgxQuoteVerifyResult, // Output
    pub supplemental_data_size: u32,                          // Input (optional)
    pub supplemental_data: *mut u8,                           // Output (optional)
}
