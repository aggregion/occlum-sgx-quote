# Occlum SGX Lib
Implementation for generating and verifying SGX DCAP quotes for [Occlum](https://github.com/occlum/occlum)

Docs: https://docs.rs/occlum-sgx/

# Install

Run the following Cargo command in your project directory:

```bash
cargo add occlum-sgx
```
Or add the following line to your Cargo.toml:
```
occlum-sgx = "0.1.11"
```

# Requirements
- SGX Server
- [PCCS](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/pccs/README.md)
- The app should be run as an [occlum instance](https://occlum.readthedocs.io/en/latest/quickstart.html) in HW sgx mode
- Occlum's configuration should contain mount devfs.

# Usage

```rust
use occlum_sgx::SGXQuote;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate SGX Quote from report data
    let quote: SGXQuote = [0u8; 64].try_into()?;
    // Check the quote, it's just for reference
    quote.verify()?;

    let mrenclave = quote.mrenclave();
    let mrsigner = quote.mrsigner();
    let product_id = quote.product_id();
    let version = quote.version();

    println!("MrEnclave:\t{}", mrenclave);
    println!("MrSigner:\t{}", mrsigner);
    println!("ProdID:\t{}", product_id);
    println!("Version:\t{}", version);

    println!("\n{:#?}", quote);

    Ok(())
}
```