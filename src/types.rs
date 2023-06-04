use base64::{engine::general_purpose::STANDARD_NO_PAD as base64, Engine};
use std::fmt::{Debug, Display};
use std::ops::Deref;

use crate::constants::{
    SGX_CONFIGID_SIZE, SGX_CPUSVN_SIZE, SGX_HASH_SIZE, SGX_REPORT_BODY_RESERVED1_BYTES,
    SGX_REPORT_BODY_RESERVED2_BYTES, SGX_REPORT_BODY_RESERVED3_BYTES,
    SGX_REPORT_BODY_RESERVED4_BYTES, SGX_REPORT_DATA_SIZE,
};
use crate::error::SGXError;

pub type ReportData = [u8; SGX_REPORT_DATA_SIZE];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXReportData {
    data: ReportData,
}

impl SGXReportData {
    pub fn new(data: ReportData) -> Self {
        Self { data }
    }
}

impl Deref for SGXReportData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl Default for SGXReportData {
    fn default() -> Self {
        Self {
            data: [0u8; SGX_REPORT_DATA_SIZE],
        }
    }
}

impl Debug for SGXReportData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", base64.encode(self.data))
    }
}

#[repr(C)]
pub struct SGXQuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub att_key_data_0: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

#[repr(C)]
pub struct SGXCpuSvn {
    pub svn: [u8; SGX_CPUSVN_SIZE],
}

#[repr(C)]
pub struct SGXAttributes {
    pub flags: u64,
    pub xfrm: u64,
}

type SGXHash = [u8; SGX_HASH_SIZE];

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct SGXMeasurement {
    measurement: SGXHash,
}

impl SGXMeasurement {
    pub fn new(measurement: SGXHash) -> Self {
        Self { measurement }
    }

    pub fn from_hex(s: &str) -> Result<Self, SGXError> {
        let measurement: SGXHash = hex::decode(s)
            .map_err(|e| SGXError::SGXMeasurementParseError(e.to_string()))?
            .try_into()
            .map_err(|x: Vec<u8>| {
                SGXError::SGXMeasurementParseError(format!(
                    "Bad length, required 32 bytes, received: {}",
                    x.len()
                ))
            })?;
        Ok(Self { measurement })
    }
}

impl Deref for SGXMeasurement {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.measurement.as_ref()
    }
}

impl Display for SGXMeasurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.measurement))
    }
}

impl Debug for SGXMeasurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", hex::encode(self.measurement))
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXFamilyId(u64, u64);

impl Debug for SGXFamilyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FamilyId")
            .field("low", &format!("{:#x?}", self.0))
            .field("high", &format!("{:#x?}", self.1))
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXExtProdId(u64, u64);

impl Debug for SGXExtProdId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtProdId")
            .field("low", &format!("{:#x?}", self.0))
            .field("high", &format!("{:#x?}", self.1))
            .finish()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXConfigId([u8; SGX_CONFIGID_SIZE]);

impl Debug for SGXConfigId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", base64.encode(self.0.as_slice()))
    }
}

#[repr(C)]
pub struct SGXReportBody {
    pub cpu_svn: SGXCpuSvn,
    pub misc_select: u32,
    pub reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES],
    pub isv_ext_prod_id: SGXExtProdId,
    pub attributes: SGXAttributes,
    pub mr_enclave: SGXMeasurement,
    pub reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES],
    pub mr_signer: SGXMeasurement,
    pub reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES],
    pub config_id: SGXConfigId,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub config_svn: u16,
    pub reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES],
    pub isv_family_id: SGXFamilyId,
    pub report_data: SGXReportData,
}

#[derive(Debug)]
pub enum SGXQuoteVerifyResult {
    Ok = 0x0000_0000,
    ///#  Not terminal
    /// The SGX platform firmware and SW are at
    /// the latest security patching level but there are platform hardware configurations that
    /// may expose the enclave to vulnerabilities. These vulnerabilities can be mitigated with
    /// the appropriate platform configuration changes that will produce an
    /// [`SGXQuoteVerifyResult::Ok`] verification result.
    ConfigNeeded = 0x0000_A001,
    /// # Not terminal
    /// The SGX platform firmware and SW are not at
    /// the latest security patching level. The platform needs to be patched with firmware
    /// and/or software patches in order to produce an [`SGXQuoteVerifyResult::Ok`] verification
    /// result.
    OutOfDate = 0x0000_A002,
    /// # Not terminal
    /// The SGX platform firmware
    /// and SW are not at the latest security patching level. The platform needs to be patched
    /// with firmware and/or software patches. There are also platform hardware
    /// configurations that may expose the enclave to vulnerabilities. These configuration
    /// vulnerabilities can be mitigated with the appropriate platform configuration changes.
    /// Applying both the updated patches and the appropriate platform configuration changes
    /// will produce an SGX_QL_QV_RESULT_OK verification result.
    OutOfDateConfigNeeded = 0x0000_A003,
    /// # Terminal
    InvalidSignature = 0x0000_A004,
    /// # Terminal
    Revoked = 0x0000_A005,
    /// # Terminal
    Unspecified = 0x0000_A006,
    /// # Not terminal
    /// The SGX platform firmware and SW
    /// are at the latest security patching level but there are certain vulnerabilities that can only
    /// be mitigated with software mitigations implemented by the enclave. The enclave
    /// identity policy needs to indicate whether the enclave has implemented these
    /// mitigations.
    SwHardeningNeeded = 0x0000_A007,
    /// # Not terminal
    /// The SGX platform firmware and SW are at the latest security patching level but there are certain
    /// vulnerabilities that can only be mitigated with software mitigations implemented by the
    /// enclave. The enclave identity policy needs to indicate whether the enclave has
    /// implemented these mitigations. There are also platform hardware configurations that
    /// may expose the enclave to vulnerabilities. These configuration vulnerabilities can be
    /// mitigated with the appropriate platform configuration changes that will produce an
    /// [`SGXQuoteVerifyResult::SwHardeningNeeded`] verification result.
    ConfigAndSwHardeningNeeded = 0x0000_A008,
    Max = 0x0000_A0FF,
}
