//! Messages carried in data-packet payloads (PROTOCOL.md §5).
//!
//! The format looks MIDI-like: a status byte with the high bit set, 7-bit
//! data bytes, and `F0 … F7` system messages. Anything the parser cannot size
//! is returned as [`DeskMessage::Unknown`] instead of being guessed.

mod desk;
mod host;

use std::fmt;

pub use desk::{AutomationMode, CounterMode, DeskMessage, Messages, parse_messages};
pub use host::{HostMessage, MeterLeds, RingLeds, seven_segment};

/// Number of channel strips on the desk.
pub const TRACKS: u8 = 24;

/// A channel strip index, 0–23.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Track(u8);

impl Track {
    /// Every strip, left to right.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..TRACKS).map(Self)
    }

    /// The zero-based strip index.
    #[must_use]
    pub fn index(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Track {
    type Error = MessageError;

    fn try_from(index: u8) -> Result<Self, Self::Error> {
        if index < TRACKS {
            Ok(Self(index))
        } else {
            Err(MessageError::TrackOutOfRange(index))
        }
    }
}

/// A 10-bit fader position, 0–1023 (PROTOCOL.md §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FaderPosition(u16);

impl FaderPosition {
    /// Highest position.
    pub const MAX: Self = Self(0x3FF);

    /// The raw 10-bit value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }

    /// Splits into the two wire bytes: high 7 bits, then low 3 bits shifted
    /// into bits 4–6.
    fn to_wire(self) -> (u8, u8) {
        let high = u8::try_from(self.0 >> 3).unwrap_or(0x7F) & 0x7F;
        let low = u8::try_from(self.0 & 0x07).unwrap_or(0) << 4;
        (high, low)
    }

    fn from_wire(high: u8, low: u8) -> Self {
        Self((u16::from(high & 0x7F) << 3) | u16::from((low >> 4) & 0x07))
    }
}

impl TryFrom<u16> for FaderPosition {
    type Error = MessageError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(MessageError::FaderOutOfRange(value))
        }
    }
}

/// Identifies a button and its LED: the two data bytes of a `90` message
/// with the state bit (`0x40` of the second byte) cleared (§5.3).
///
/// The bytes are `[index, group]`: groups `0x00`–`0x17` are the channel
/// strips, `0x18`–`0x1D` the centre sections; [`crate::buttons`] names them.
/// The desk accepts the same ID to switch the button's LED [OBS].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ButtonId(pub [u8; 2]);

impl ButtonId {
    /// Bit of the second data byte that carries pressed / lit.
    pub(crate) const STATE_BIT: u8 = 0x40;
}

/// Bytes as space-separated hex, as written in the specification.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let text: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    text.join(" ")
}

/// Why a message could not be decoded or encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The payload ended in the middle of a message.
    Truncated {
        /// Status byte of the incomplete message.
        status: u8,
        /// Bytes the message needs.
        needed: usize,
        /// Bytes left in the payload.
        got: usize,
    },
    /// Track index outside 0–23.
    TrackOutOfRange(u8),
    /// Fader value above 1023.
    FaderOutOfRange(u16),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                status,
                needed,
                got,
            } => write!(
                f,
                "message {status:#04x} needs {needed} bytes but only {got} remain"
            ),
            Self::TrackOutOfRange(t) => write!(f, "track {t} is outside 0-{}", TRACKS - 1),
            Self::FaderOutOfRange(v) => write!(f, "fader value {v} is above 1023"),
        }
    }
}

impl std::error::Error for MessageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fader_position_round_trips_every_value() {
        for v in 0..=FaderPosition::MAX.value() {
            let pos = FaderPosition::try_from(v).unwrap();
            let (high, low) = pos.to_wire();
            assert!(high <= 0x7F && low <= 0x7F, "7-bit data bytes");
            assert_eq!(FaderPosition::from_wire(high, low), pos);
        }
        assert_eq!(
            FaderPosition::try_from(1024),
            Err(MessageError::FaderOutOfRange(1024))
        );
    }

    #[test]
    fn track_range() {
        assert_eq!(Track::try_from(23).map(Track::index), Ok(23));
        assert_eq!(Track::try_from(24), Err(MessageError::TrackOutOfRange(24)));
    }
}
