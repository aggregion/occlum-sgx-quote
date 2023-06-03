use base64::{engine::general_purpose::STANDARD_NO_PAD as base64, Engine};
use std::fmt::Debug;
use std::fmt::Display;

use crate::constants::{
    SGX_CONFIGID_SIZE, SGX_CPUSVN_SIZE, SGX_HASH_SIZE, SGX_REPORT_BODY_RESERVED1_BYTES,
    SGX_REPORT_BODY_RESERVED2_BYTES, SGX_REPORT_BODY_RESERVED3_BYTES,
    SGX_REPORT_BODY_RESERVED4_BYTES, SGX_REPORT_DATA_SIZE,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXReportData {
    pub d: [u8; SGX_REPORT_DATA_SIZE],
}

impl SGXReportData {
    pub fn from_str(s: &str) -> Self {
        let mut report = Self::default();
        for (pos, val) in s.as_bytes().iter().enumerate() {
            report.d[pos] = *val;
        }
        report
    }
}

impl Default for SGXReportData {
    fn default() -> Self {
        Self {
            d: [0u8; SGX_REPORT_DATA_SIZE],
        }
    }
}

impl Debug for SGXReportData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", base64.encode(self.d))
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SGXMeasurement {
    pub m: [u8; SGX_HASH_SIZE],
}

impl Display for SGXMeasurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.m))
    }
}

impl Debug for SGXMeasurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", hex::encode(self.m))
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
pub enum SgxQuoteVerifyResult {
    Ok = 0x0000_0000,
    ConfigNeeded = 0x0000_A001,
    OutOfDate = 0x0000_A002,
    OutOfDateConfigNeeded = 0x0000_A003,
    InvalidSignature = 0x0000_A004,
    Revoked = 0x0000_A005,
    Unspecified = 0x0000_A006,
    SwHardeningNeeded = 0x0000_A007,
    ConfigAndSwHardeningNeeded = 0x0000_A008,
    Max = 0x0000_A0FF,
}
