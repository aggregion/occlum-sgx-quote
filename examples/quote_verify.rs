use occlum_sgx::{SGXMeasurement, SGXQuote};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let quote_buf = include_bytes!("../tests/fixtures/quote.raw");
    let quote = SGXQuote::from_slice(quote_buf)?;

    // Verify quote
    quote.verify()?;

    // Check mrenclave
    let mrenclave = SGXMeasurement::new([
        0x9C, 0x90, 0xFD, 0x81, 0xF6, 0xE9, 0xFE, 0x64, 0xB4, 0x6B, 0x14, 0xF0, 0x62, 0x35, 0x23,
        0xA5, 0x2D, 0x6A, 0x56, 0x78, 0x48, 0x29, 0x88, 0xC4, 0x8, 0xF6, 0xAD, 0xFF, 0xE6, 0x30,
        0x1E, 0x2C,
    ]);
    assert_eq!(quote.mrenclave(), mrenclave);

    // Check mrsigner
    let mrsigner = SGXMeasurement::from_hex(
        "6d5ead54bfbe9494e1cd9042bb7c25d74c597d4700e332b1b3168a60712c1e02",
    )?;
    assert_eq!(quote.mrsigner(), mrsigner);

    // Check product id
    assert_eq!(quote.product_id(), 4000);

    // Check version
    assert_eq!(quote.version(), 5000);

    // Check report data
    assert_eq!(*quote.report_data(), [0u8; 64]);

    Ok(())
}
