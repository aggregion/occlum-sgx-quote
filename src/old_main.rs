use std::{ffi::CString, mem::size_of};

use libc::O_RDONLY;

const SGXIOC_GET_DCAP_QUOTE_SIZE: u64 = 0x80047307;
const SGXIOC_GEN_DCAP_QUOTE: u64 = 0xc0187308;
const SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE: u64 = 0x80047309;
const SGXIOC_VER_DCAP_QUOTE: u64 = 0xc030730a;

const SGX_REPORT_DATA_SIZE: usize = 64;
const SGX_CPUSVN_SIZE: usize = 16;
pub const SGX_CONFIGID_SIZE: usize = 64;

const SGX_REPORT_BODY_RESERVED1_BYTES: usize = 12;
const SGX_REPORT_BODY_RESERVED2_BYTES: usize = 32;
const SGX_REPORT_BODY_RESERVED3_BYTES: usize = 32;
const SGX_REPORT_BODY_RESERVED4_BYTES: usize = 42;

const SGX_ISVEXT_PROD_ID_SIZE: usize = 16;
const SGX_ISV_FAMILY_ID_SIZE: usize = 16;

const SGX_HASH_SIZE: usize = 32;

cfg_if::cfg_if! {
    if #[cfg(target_env = "musl")] {
        const IOCTL_GET_DCAP_QUOTE_SIZE: i32 = SGXIOC_GET_DCAP_QUOTE_SIZE as i32;
        const IOCTL_GEN_DCAP_QUOTE: i32 = SGXIOC_GEN_DCAP_QUOTE as i32;
        const IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE: i32 = SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE as i32;
        const IOCTL_VER_DCAP_QUOTE: i32 = SGXIOC_VER_DCAP_QUOTE as i32;
    } else {
        const IOCTL_GET_DCAP_QUOTE_SIZE: u64 = SGXIOC_GET_DCAP_QUOTE_SIZE;
        const IOCTL_GEN_DCAP_QUOTE: u64 = SGXIOC_GEN_DCAP_QUOTE;
        const IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE: u64 = SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE;
        const IOCTL_VER_DCAP_QUOTE: u64 = SGXIOC_VER_DCAP_QUOTE;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

#[repr(C)]
pub struct SgxQuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub att_key_data_0: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

#[repr(C)]
pub struct SgxCpuSvn {
    pub svn: [u8; SGX_CPUSVN_SIZE],
}

#[repr(C)]
pub struct SgxAttributes {
    pub flags: u64,
    pub xfrm: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SgxMeasurement {
    pub m: [u8; SGX_HASH_SIZE],
}

#[repr(C)]
pub struct SgxReportBody {
    pub cpu_svn: SgxCpuSvn,
    pub misc_select: u32,
    pub reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES],
    pub isv_ext_prod_id: [u8; SGX_ISVEXT_PROD_ID_SIZE],
    pub attributes: SgxAttributes,
    pub mr_enclave: SgxMeasurement,
    pub reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES],
    pub mr_signer: SgxMeasurement,
    pub reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES],
    pub config_id: [u8; SGX_CONFIGID_SIZE],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub config_svn: u16,
    pub reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES],
    pub isv_family_id: [u8; SGX_ISV_FAMILY_ID_SIZE],
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

fn main() {
    let path = CString::new("/dev/sgx").expect("CString::new failed");
    let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };

    if fd <= 0 {
        panic!("Open /dev/sgx failed");
    }

    let mut quote_size: u32 = 0;
    let ret = unsafe { libc::ioctl(fd, IOCTL_GET_DCAP_QUOTE_SIZE, &quote_size) };

    if ret < 0 {
        panic!("IOCTRL IOCTL_GET_DCAP_QUOTE_SIZE failed");
    }

    let mut report_data = SGXReportData::from_str("test data");

    println!("Report data: {:?}", report_data.d);
    let mut quote_buf: Vec<u8> = vec![0; quote_size as usize];

    let quote_arg: IoctlGenDCAPQuoteArg = IoctlGenDCAPQuoteArg {
        report_data: &mut report_data,
        quote_size: &mut quote_size,
        quote_buf: quote_buf.as_mut_ptr(),
    };

    let ret = unsafe { libc::ioctl(fd, IOCTL_GEN_DCAP_QUOTE, &quote_arg) };
    if ret < 0 {
        panic!("IOCTRL IOCTL_GEN_DCAP_QUOTE failed")
    }

    println!("SGX Quote: {:?}", quote_buf);

    let supplemental_size: u32 = 0;
    let ret = unsafe { libc::ioctl(fd, IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_size) };
    if ret < 0 {
        panic!("IOCTRL IOCTL_GET_DCAP_SUPPLEMENTAL_SIZE failed");
    }

    let mut quote_verification_result = SgxQuoteVerifyResult::Unspecified;
    let mut status = 1;
    let mut suppl_buf: Vec<u8> = vec![0; supplemental_size as usize];

    let verify_arg = IoctlVerDCAPQuoteArg {
        quote_buf: quote_buf.as_mut_ptr(),
        quote_size,
        collateral_expiration_status: &mut status,
        quote_verification_result: &mut quote_verification_result,
        supplemental_data_size: supplemental_size,
        supplemental_data: suppl_buf.as_mut_ptr(),
    };

    let ret = unsafe { libc::ioctl(fd, IOCTL_VER_DCAP_QUOTE, &verify_arg) };
    if ret < 0 {
        panic!("IOCTRL IOCTL_VER_DCAP_QUOTE failed")
    }

    match quote_verification_result {
        SgxQuoteVerifyResult::Ok => println!("Succeed to verify the quote!"),
        SgxQuoteVerifyResult::ConfigNeeded
        | SgxQuoteVerifyResult::OutOfDate
        | SgxQuoteVerifyResult::OutOfDateConfigNeeded
        | SgxQuoteVerifyResult::SwHardeningNeeded
        | SgxQuoteVerifyResult::ConfigAndSwHardeningNeeded => println!(
            "WARN: App: Verification completed with Non-terminal result: {:?}",
            quote_verification_result
        ),
        _ => println!(
            "Error: App: Verification completed with Terminal result: {:?}",
            quote_verification_result
        ),
    }

    let report_body_offset = size_of::<SgxQuoteHeader>();
    let report_body: *const SgxReportBody = (quote_buf[report_body_offset..]).as_ptr() as _;

    // Dump ISV FAMILY ID
    let family_id = unsafe { (*report_body).isv_family_id };
    let (fam_id_l, fam_id_h) = family_id.split_at(8);
    let fam_id_l = <&[u8; 8]>::try_from(fam_id_l).unwrap();
    let fam_id_l = u64::from_le_bytes(*fam_id_l);
    let fam_id_h = <&[u8; 8]>::try_from(fam_id_h).unwrap();
    let fam_id_h = u64::from_le_bytes(*fam_id_h);
    println!("\nSGX ISV Family ID:");
    println!("\t Low 8 bytes: 0x{:016x?}\t", fam_id_l);
    println!("\t high 8 bytes: 0x{:016x?}\t", fam_id_h);

    // Dump ISV EXT Product ID
    let prod_id = unsafe { (*report_body).isv_ext_prod_id };
    let (prod_id_l, prod_id_h) = prod_id.split_at(8);
    let prod_id_l = <&[u8; 8]>::try_from(prod_id_l).unwrap();
    let prod_id_l = u64::from_le_bytes(*prod_id_l);
    let prod_id_h = <&[u8; 8]>::try_from(prod_id_h).unwrap();
    let prod_id_h = u64::from_le_bytes(*prod_id_h);
    println!("\nSGX ISV EXT Product ID:");
    println!("\t Low 8 bytes: 0x{:016x?}\t", prod_id_l);
    println!("\t high 8 bytes: 0x{:016x?}\t", prod_id_h);

    // Dump CONFIG ID
    let conf_id = unsafe { (*report_body).config_id };
    println!("\nSGX CONFIG ID:");
    println!("\t{:02x?}", &conf_id[..16]);
    println!("\t{:02x?}", &conf_id[16..32]);
    println!("\t{:02x?}", &conf_id[32..48]);
    println!("\t{:02x?}", &conf_id[48..]);

    // Dump CONFIG SVN
    let conf_svn = unsafe { (*report_body).config_svn };
    println!("\nSGX CONFIG SVN:\t {:04x?}", conf_svn);

    let mrenclave = unsafe { (*report_body).mr_enclave };
    println!("\nMRENCLAVE:\t {}", hex::encode(mrenclave.m));

    let mrsigner = unsafe { (*report_body).mr_signer };
    println!("MRSIGNER:\t {}", hex::encode(mrsigner.m));

    let report_data = unsafe { (*report_body).report_data };
    println!("Report data:\t{:?}", report_data.d);

    let version = unsafe { (*report_body).isv_svn };
    println!("Version:\t {}", version);

    let val = unsafe { (*report_body).isv_prod_id };
    println!("Product Id:\t {:?}", val);
}
