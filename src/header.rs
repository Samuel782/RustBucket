//! The 16-byte C24 header that follows the Ethernet header (PROTOCOL.md §2).

use crate::error::ParseError;

/// Packet type carried in the header's `command` byte (PROTOCOL.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0x00`: payload holds `n_messages` messages.
    Data,
    /// `0xA0`: acknowledges the peer's `send_counter`; no payload.
    Ack,
    /// `0xE0`: broadcast by a desk looking for a host (at power-up, or after
    /// losing its host); payload is an [`crate::Announce`] (§4.1).
    Announce,
    /// `0xE1`: broadcast every ~6 s by a desk bound to a host, whose MAC is
    /// in the [`crate::Announce`] payload (§4.1).
    Beacon,
    /// `0xE2`: host brings the desk online; no payload.
    Online,
    /// Any other value, kept verbatim (PROTOCOL.md §3).
    Unknown(u8),
}

impl From<u8> for Command {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Self::Data,
            0xA0 => Self::Ack,
            0xE0 => Self::Announce,
            0xE1 => Self::Beacon,
            0xE2 => Self::Online,
            other => Self::Unknown(other),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Data => 0x00,
            Command::Ack => 0xA0,
            Command::Announce => 0xE0,
            Command::Beacon => 0xE1,
            Command::Online => 0xE2,
            Command::Unknown(b) => b,
        }
    }
}

/// Header checksum of a payload: the sum of its bytes, modulo 2¹⁶ (§2).
///
/// Holds for every packet in the recorded sessions, in both directions.
#[must_use]
pub fn checksum(payload: &[u8]) -> u16 {
    payload
        .iter()
        .fold(0u16, |sum, &b| sum.wrapping_add(u16::from(b)))
}

/// Decoded C24 header. All multi-byte fields are big-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Header size plus payload size (offset 14).
    pub length: u16,
    /// Sum of the payload bytes, modulo 2¹⁶ (offset 16, §2); see [`checksum`].
    pub checksum: u16,
    /// Sender's counter, advanced by the number of messages sent (offset 18, §4.3).
    pub send_counter: u32,
    /// Counter value being acknowledged (offset 22, §4.3).
    pub ack_counter: u32,
    /// Non-zero when the sender is retransmitting (offset 26, §4.4).
    pub retry: u16,
    /// Packet type (offset 28, §3).
    pub command: Command,
    /// Number of messages in the payload (offset 29).
    pub n_messages: u8,
}

impl Header {
    /// Encoded size in bytes.
    pub const SIZE: usize = 16;

    /// Header with zero counters. `length` and `checksum` are filled in by
    /// [`crate::Frame::new`].
    #[must_use]
    pub fn new(command: Command, n_messages: u8) -> Self {
        Self {
            length: 16,
            checksum: 0,
            send_counter: 0,
            ack_counter: 0,
            retry: 0,
            command,
            n_messages,
        }
    }

    /// Payload length implied by `length`.
    ///
    /// # Errors
    /// [`ParseError::LengthBelowHeader`] when `length` is under 16.
    pub fn payload_len(&self) -> Result<usize, ParseError> {
        usize::from(self.length)
            .checked_sub(Self::SIZE)
            .ok_or(ParseError::LengthBelowHeader(self.length))
    }

    /// True when the sender flags this packet as a retransmission (§4.4).
    #[must_use]
    pub fn is_retry(&self) -> bool {
        self.retry != 0
    }

    /// Decodes the first 16 bytes of `bytes`.
    ///
    /// # Errors
    /// [`ParseError::TooShort`] when fewer than 16 bytes are given.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let b: &[u8; Self::SIZE] = bytes
            .get(..Self::SIZE)
            .and_then(|s| s.try_into().ok())
            .ok_or(ParseError::TooShort {
                needed: Self::SIZE,
                got: bytes.len(),
            })?;
        Ok(Self {
            length: u16::from_be_bytes([b[0], b[1]]),
            checksum: u16::from_be_bytes([b[2], b[3]]),
            send_counter: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ack_counter: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            retry: u16::from_be_bytes([b[12], b[13]]),
            command: Command::from(b[14]),
            n_messages: b[15],
        })
    }

    /// Encodes the header into its 16-byte wire form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..2].copy_from_slice(&self.length.to_be_bytes());
        out[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        out[4..8].copy_from_slice(&self.send_counter.to_be_bytes());
        out[8..12].copy_from_slice(&self.ack_counter.to_be_bytes());
        out[12..14].copy_from_slice(&self.retry.to_be_bytes());
        out[14] = self.command.into();
        out[15] = self.n_messages;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_big_endian_fields() {
        let bytes = [
            0x00, 0x13, // length = 19 -> 3 payload bytes
            0x00, 0xE8, // checksum = 0x90 + 0x18 + 0x40
            0x00, 0x00, 0x01, 0x02, // send_counter = 258
            0x00, 0x00, 0x00, 0x07, // ack_counter = 7
            0x00, 0x01, // retry = 1
            0x00, // Data
            0x01, // one message
        ];
        let h = Header::parse(&bytes).unwrap();
        assert_eq!(h.length, 19);
        assert_eq!(h.payload_len(), Ok(3));
        assert_eq!(h.checksum, checksum(&[0x90, 0x18, 0x40]));
        assert_eq!(h.send_counter, 258);
        assert_eq!(h.ack_counter, 7);
        assert!(h.is_retry());
        assert_eq!(h.command, Command::Data);
        assert_eq!(h.n_messages, 1);
        assert_eq!(h.to_bytes(), bytes);
    }

    #[test]
    fn checksum_matches_recorded_packets() {
        // Handshake clock reset: the `02 44` once thought to be flags.
        let clock_reset = [
            0xF0, 0x13, 0x01, 0x30, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF7,
        ];
        assert_eq!(checksum(&clock_reset), 0x0244);
        assert_eq!(checksum(&[0x90, 0x05, 0x41]), 0x00D6);
        assert_eq!(checksum(&[]), 0);
        assert_eq!(checksum(&[0xFF; 300]), 0x2AD4);
    }

    #[test]
    fn keeps_unknown_commands() {
        assert_eq!(Command::from(0x42), Command::Unknown(0x42));
        assert_eq!(u8::from(Command::Unknown(0x42)), 0x42);
        for byte in [0x00, 0xA0, 0xE0, 0xE1, 0xE2, 0x42] {
            assert_eq!(u8::from(Command::from(byte)), byte);
        }
    }

    #[test]
    fn rejects_short_input_and_bad_length() {
        assert_eq!(
            Header::parse(&[0; 15]),
            Err(ParseError::TooShort {
                needed: 16,
                got: 15
            })
        );
        let mut h = Header::new(Command::Ack, 0);
        h.length = 15;
        assert_eq!(h.payload_len(), Err(ParseError::LengthBelowHeader(15)));
    }
}
