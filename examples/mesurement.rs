use occlum_sgx::SGXMeasurement;

fn main() {
    let measurement1 = SGXMeasurement::new([
        0x8A, 0x2F, 0x1B, 0x63, 0xE7, 0x8C, 0x93, 0xB7, 0x44, 0xDF, 0x1E, 0xE1, 0x0F, 0x23, 0xAB,
        0x09, 0x70, 0xC9, 0x1C, 0xD3, 0x99, 0xAE, 0x4B, 0x18, 0x6F, 0x53, 0x2A, 0xA7, 0x37, 0x81,
        0xD8, 0x12,
    ]);

    let measurement2 = SGXMeasurement::new([
        0x53, 0x8C, 0x41, 0x6A, 0x27, 0x9B, 0x18, 0xE5, 0x4F, 0x71, 0x9D, 0x63, 0x32, 0xAF, 0x1B,
        0xC9, 0x50, 0x82, 0xD4, 0xEF, 0x79, 0x15, 0x3F, 0xB8, 0xC6, 0xA3, 0x1E, 0xF7, 0x09, 0x57,
        0xD8, 0x2B,
    ]);

    assert_eq!(measurement1.eq(&measurement2), false);
}