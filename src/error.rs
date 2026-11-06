//! Parse errors.

use std::fmt;

/// Why a byte buffer could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the fixed part of the structure needs.
    TooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
    /// The frame is not a Control|24 frame (PROTOCOL.md §1).
    WrongEtherType(u16),
    /// The header `length` field is below the 16-byte header size (§2).
    LengthBelowHeader(u16),
    /// The header `length` field claims more payload than the frame carries (§2).
    LengthExceedsFrame {
        /// Payload length declared by the header.
        declared: usize,
        /// Payload bytes actually present.
        available: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(f, "buffer too short: need {needed} bytes, got {got}")
            }
            Self::WrongEtherType(t) => write!(f, "unexpected EtherType {t:#06x}"),
            Self::LengthBelowHeader(l) => {
                write!(f, "header length {l} is smaller than the 16-byte header")
            }
            Self::LengthExceedsFrame {
                declared,
                available,
            } => write!(
                f,
                "header declares {declared} payload bytes but only {available} are present"
            ),
        }
    }
}

impl std::error::Error for ParseError {}
