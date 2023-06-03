use std::{ffi::CString, sync::Mutex};

use log::trace;

use crate::{
    constants::{
        IOCTL_GEN_DCAP_QUOTE, IOCTL_GET_DCAP_QUOTE_SIZE, IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE,
        IOCTL_VER_DCAP_QUOTE,
    },
    error::SGXError,
    types::{SGXQuoteVerifyResult, SGXReportData},
};

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
    pub quote_verification_result: *mut SGXQuoteVerifyResult, // Output
    pub supplemental_data_size: u32,                          // Input (optional)
    pub supplemental_data: *mut u8,                           // Output (optional)
}

lazy_static! {
    pub static ref IOCTL_CLIENT: Mutex<IoctlClient> = {
        let client = IoctlClient::new();
        Mutex::new(client)
    };
}

// Client which send ioctls to the Occlum LibOS
// @see https://github.com/occlum/occlum/blob/master/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
pub struct IoctlClient {
    fd: Option<i32>,
    quote_size: Option<u32>,
    supplemental_size: Option<u32>,
}

impl IoctlClient {
    fn new() -> Self {
        Self {
            fd: None,
            quote_size: None,
            supplemental_size: None,
        }
    }

    fn fd(&mut self) -> Result<i32, SGXError> {
        if self.fd.is_none() {
            let path = CString::new("/dev/sgx").expect("CString::new failed");
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };

            if fd <= 0 {
                return Err(SGXError::DeviceOpenFailed("/dev/sgx"));
            }

            self.fd = Some(fd);
            Ok(fd)
        } else {
            Ok(self.fd.as_ref().unwrap().clone())
        }
    }

    fn get_quote_size(&mut self) -> Result<u32, SGXError> {
        if self.quote_size.is_none() {
            let size: u32 = 0;
            trace!("ioctl(SGX_IOCTL_GET_DCAP_QUOTE_SIZE): Get DCAP Quote size");
            let ret = unsafe { libc::ioctl(self.fd()?, IOCTL_GET_DCAP_QUOTE_SIZE, &size) };

            if ret < 0 {
                return Err(SGXError::IoctlClientError {
                    request_type: "IOCTL_GET_DCAP_QUOTE_SIZE",
                    ret,
                });
            }

            self.quote_size = Some(size);
        }

        Ok(self.quote_size.as_ref().unwrap().clone())
    }

    pub fn generate_quote(&mut self, report_data: SGXReportData) -> Result<Vec<u8>, SGXError> {
        let mut quote_size = self.get_quote_size()?;
        let mut quote_buf: Vec<u8> = vec![0; quote_size as usize];

        let quote_arg: IoctlGenDCAPQuoteArg = IoctlGenDCAPQuoteArg {
            report_data: &report_data,
            quote_size: &mut quote_size,
            quote_buf: quote_buf.as_mut_ptr(),
        };

        trace!("ioctl(IOCTL_GEN_DCAP_QUOTE): Generate SGX DCAP Quote");
        let ret = unsafe { libc::ioctl(self.fd()?, IOCTL_GEN_DCAP_QUOTE, &quote_arg) };
        if ret < 0 {
            return Err(SGXError::IoctlClientError {
                request_type: "IOCTL_GEN_DCAP_QUOTE",
                ret,
            });
        }
        Ok(quote_buf)
    }

    fn get_supplemental_size(&mut self) -> Result<u32, SGXError> {
        if self.supplemental_size.is_none() {
            let size: u32 = 0;
            trace!("ioctl(IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE): Get Supplemental size");
            let ret = unsafe { libc::ioctl(self.fd()?, IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE, &size) };

            if ret < 0 {
                return Err(SGXError::IoctlClientError {
                    request_type: "IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE",
                    ret,
                });
            }

            self.supplemental_size = Some(size);
        }

        Ok(self.supplemental_size.as_ref().unwrap().clone())
    }

    pub fn verify_quote(&mut self, quote_buf: &[u8]) -> Result<SGXQuoteVerifyResult, SGXError> {
        let supplemental_data_size = self.get_supplemental_size()?;
        let mut result = SGXQuoteVerifyResult::Unspecified;
        let mut status = 1;
        let mut suppl_buf: Vec<u8> = vec![0; supplemental_data_size as usize];

        let verify_arg = IoctlVerDCAPQuoteArg {
            quote_buf: quote_buf.as_ptr(),
            quote_size: quote_buf.len() as u32,
            collateral_expiration_status: &mut status,
            quote_verification_result: &mut result,
            supplemental_data_size,
            supplemental_data: suppl_buf.as_mut_ptr(),
        };

        trace!("ioctl(IOCTL_VER_DCAP_QUOTE): Verify SGX DCAP Quote");
        let ret = unsafe { libc::ioctl(self.fd()?, IOCTL_VER_DCAP_QUOTE, &verify_arg) };
        if ret < 0 {
            return Err(SGXError::IoctlClientError {
                request_type: "IOCTL_VER_DCAP_QUOTE",
                ret,
            });
        }
        Ok(result)
    }
}

impl Drop for IoctlClient {
    fn drop(&mut self) {
        unsafe {
            if let Some(fd) = self.fd {
                libc::close(fd);
            }
        }
    }
}
