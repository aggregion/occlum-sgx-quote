use occlum_sgx::{SGXQuote, SGXQuoteBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buf = SGXQuoteBuilder::generate_bytes("test data")?;
    let quote = SGXQuote::try_from(&buf)?;

    if quote.verify()? {
        println!("Quote is valid");
    } else {
        println!("Quote is invalid");
    }

    let _mrenclave = quote.mrenclave();
    let _mrsigner = quote.mrsigner();
    let _product_id = quote.product_id();
    let _version = quote.version();

    println!("{:#?}", quote);

    Ok(())
}
