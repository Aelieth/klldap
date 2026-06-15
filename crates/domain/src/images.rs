// crates/domain/src/images.rs
//
// Centralized avatar / image handling for KLLDAP 7.0+
//
// DESIGN PRINCIPLES:
// - Single source of truth for all avatar creation and validation.
// - Avatar struct ALWAYS contains valid JPEG bytes (≤512×512, ≤512 KiB).
// - process_avatar_input is the ONLY way to create a new Avatar from untrusted input.
// - validate_stored_avatar_bytes is defensive (accepts legacy data + current JPEGs).
// - All errors are clear and actionable.
// - PNG/BMP/JPEG input → always converted to optimized JPEG on write.

use base64::Engine;
use base64::engine::general_purpose;
use image::{ImageFormat, ImageReader, codecs::jpeg::JpegEncoder};
use std::io::Cursor;

pub const MAX_AVATAR_SIZE: u32 = 512;
pub const TARGET_AVATAR_SIZE: u32 = MAX_AVATAR_SIZE;
pub const JPEG_QUALITY: u8 = 82;
pub const MAX_AVATAR_JPEG_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarError {
    WrongDimensions { width: u32, height: u32 },
    UnsupportedFormat,
    TooLarge { size: usize },
    InvalidImage(String),
}

impl std::fmt::Display for AvatarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvatarError::WrongDimensions { width, height } => {
                write!(
                    f,
                    "Avatar must be at most {}x{} pixels (got {}x{})",
                    TARGET_AVATAR_SIZE, TARGET_AVATAR_SIZE, width, height
                )
            }
            AvatarError::UnsupportedFormat => {
                write!(
                    f,
                    "Unsupported image format. Only JPEG, PNG, or BMP allowed."
                )
            }
            AvatarError::TooLarge { size } => {
                write!(
                    f,
                    "Avatar too large ({} bytes > {} KiB limit)",
                    size,
                    MAX_AVATAR_JPEG_SIZE / 1024
                )
            }
            AvatarError::InvalidImage(msg) => write!(f, "Invalid or corrupted image data: {}", msg),
        }
    }
}

impl std::error::Error for AvatarError {}

/// THE single entry point for creating Avatars from user input (GraphQL, LDAP, etc.).
///
/// Guarantees:
/// - Output is always valid JPEG (even if input was PNG/BMP).
/// - Output respects size and dimension limits.
/// - Never stores raw PNG/BMP in the database.
pub fn process_avatar_input(input: &[u8]) -> Result<Vec<u8>, AvatarError> {
    if input.is_empty() {
        return Ok(vec![]);
    }

    let reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|e| {
            tracing::error!(target: "avatar_debug", "guessed_format FAILED: {}", e);
            AvatarError::InvalidImage(e.to_string())
        })?;

    let format = reader.format().ok_or_else(|| {
        tracing::error!(target: "avatar_debug", "format() returned None");
        AvatarError::UnsupportedFormat
    })?;

    if !matches!(
        format,
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::Bmp
    ) {
        tracing::error!(target: "avatar_debug", "Unsupported format: {:?}", format);
        return Err(AvatarError::UnsupportedFormat);
    }

    let max_input_size = if format == ImageFormat::Bmp {
        2 * 1024 * 1024
    } else {
        MAX_AVATAR_JPEG_SIZE // 512 KiB for JPEG, PNG
    };

    if input.len() > max_input_size {
        return Err(AvatarError::TooLarge { size: input.len() });
    }

    let img = reader
        .decode()
        .map_err(|e| AvatarError::InvalidImage(e.to_string()))?;

    if img.width() > TARGET_AVATAR_SIZE || img.height() > TARGET_AVATAR_SIZE {
        tracing::warn!(
            target: "avatar_debug",
            "REJECTED: image {}x{} exceeds {}x{} limit",
            img.width(),
            img.height(),
            TARGET_AVATAR_SIZE,
            TARGET_AVATAR_SIZE
        );
        return Err(AvatarError::WrongDimensions {
            width: img.width(),
            height: img.height(),
        });
    }

    let mut jpeg_bytes = Vec::with_capacity(128 * 1024);
    let mut encoder = JpegEncoder::new_with_quality(&mut jpeg_bytes, JPEG_QUALITY);
    encoder
        .encode_image(&img)
        .map_err(|e| AvatarError::InvalidImage(e.to_string()))?;

    if jpeg_bytes.len() > MAX_AVATAR_JPEG_SIZE {
        return Err(AvatarError::TooLarge {
            size: jpeg_bytes.len(),
        });
    }

    Ok(jpeg_bytes)
}

/// Converts stored avatar bytes (always JPEG) to GraphQL base64.
pub fn avatar_to_graphql_base64(jpeg_bytes: &[u8]) -> String {
    if jpeg_bytes.is_empty() {
        return String::new();
    }
    general_purpose::STANDARD.encode(jpeg_bytes)
}

/// Defense-in-depth validation for data coming FROM the database.
/// Accepts:
/// - Valid JPEG (current format)
/// - Valid input formats (for legacy data that may still be PNG/BMP)
/// - Never fails on legacy data — lets the read path re-process if needed.
pub fn validate_stored_avatar_bytes(bytes: &[u8]) -> Result<(), AvatarError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > MAX_AVATAR_JPEG_SIZE {
        return Err(AvatarError::TooLarge { size: bytes.len() });
    }

    // Accept current JPEGs
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return Ok(());
    }

    // Accept legacy PNG/BMP (will be re-processed on read if needed)
    if bytes.len() >= 4 {
        let is_png = bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]);
        let is_bmp = bytes.starts_with(&[0x42, 0x4D]);
        if is_png || is_bmp {
            return Ok(());
        }
    }

    Err(AvatarError::InvalidImage(
        "Stored avatar is not a valid JPEG, PNG, or BMP".to_string(),
    ))
}

pub fn is_valid_avatar_dimensions(width: u32, height: u32) -> bool {
    width <= TARGET_AVATAR_SIZE && height <= TARGET_AVATAR_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, RgbImage};

    fn make_test_jpeg(size: u32) -> Vec<u8> {
        let img: RgbImage = ImageBuffer::from_fn(size, size, |x, y| {
            if (x + y) % 2 == 0 {
                Rgb([0, 0, 0])
            } else {
                Rgb([255, 255, 255])
            }
        });
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
            .unwrap();
        buf
    }

    fn make_test_png(size: u32) -> Vec<u8> {
        let img: RgbImage = ImageBuffer::from_fn(size, size, |x, y| {
            Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        buf
    }

    #[test]
    fn test_valid_512_jpeg_passes() {
        let jpeg = make_test_jpeg(512);
        let result = process_avatar_input(&jpeg);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert!(!out.is_empty());
        assert!(out.len() < MAX_AVATAR_JPEG_SIZE);
        assert_eq!(&out[0..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn test_png_converts_to_jpeg() {
        let png = make_test_png(512);
        let result = process_avatar_input(&png);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert_eq!(&out[0..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn test_oversized_image_rejected() {
        let jpeg = make_test_jpeg(600); // > 512 limit
        let err = process_avatar_input(&jpeg).unwrap_err();
        match err {
            AvatarError::WrongDimensions { width, height } => {
                assert_eq!(width, 600);
                assert_eq!(height, 600);
            }
            _ => panic!("Expected WrongDimensions, got {:?}", err),
        }
    }

    #[test]
    fn test_unsupported_format_rejected() {
        let gif = vec![
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x21,
            0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x02, 0x02, 0x4C, 0x01, 0x00, 0x3B,
        ];
        let err = process_avatar_input(&gif).unwrap_err();
        assert!(matches!(err, AvatarError::UnsupportedFormat));
    }

    #[test]
    fn test_empty_input_returns_empty() {
        let result = process_avatar_input(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_validate_stored_accepts_jpeg_and_png() {
        let jpeg = make_test_jpeg(512);
        assert!(validate_stored_avatar_bytes(&jpeg).is_ok());

        let png = make_test_png(512);
        assert!(validate_stored_avatar_bytes(&png).is_ok());
    }

    #[test]
    fn test_processed_output_is_always_valid_for_validate() {
        let png = make_test_png(400);
        let processed = process_avatar_input(&png).unwrap();
        assert!(validate_stored_avatar_bytes(&processed).is_ok());
    }
}

/// Single source of truth for test avatar data.
/// Use this everywhere instead of duplicating JPEG bytes.
pub fn make_test_jpeg_bytes() -> Vec<u8> {
    vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06,
        0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B,
        0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31,
        0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF,
        0xC0, 0x00, 0x11, 0x08, 0x00, 0x40, 0x00, 0x40, 0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01,
        0x03, 0x11, 0x01, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
        0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D, 0x01, 0x02, 0x03,
        0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71,
        0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24,
        0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86,
        0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
        0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
        0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1,
        0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01,
        0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0xF9, 0xFE, 0x8A, 0x28, 0xA0, 0x0F, 0xFF,
        0xD9,
    ]
}

/// Ready-to-use avatar attribute value for tests.
/// Uses `crate::` because we're inside lldap_domain.
pub fn make_test_avatar_value() -> crate::types::AttributeValue {
    use crate::types::{AttributeValue, Avatar, Cardinality};
    AttributeValue::Avatar(Cardinality::Singleton(Avatar(make_test_jpeg_bytes())))
}
