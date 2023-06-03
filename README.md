# Occlum SGX lib

Implementation for generate and verify SGX Quote

# Usage:

```
use occlum_sgx::{SGXQuote, SGXQuoteBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buf = SGXQuoteBuilder::generate_bytes("test data")?;
    let quote = SGXQuote::try_from(&buf)?;

    println!("{:#?}", quote);

    if quote.verify()? {
        println!("Quote is valid");
    } else {
        println!("Quote is invalid");
    }

    Ok(())
}
```