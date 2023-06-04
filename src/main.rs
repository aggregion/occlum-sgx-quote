use occlum_sgx::SGXQuote;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate SGX Quote from report data
    let quote: SGXQuote = [0u8; 64].try_into()?;

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
