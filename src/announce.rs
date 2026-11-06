//! The desk's broadcast announcement and beacon (PROTOCOL.md §4.1).

use crate::header::Command;
use crate::{Frame, MacAddress, ParseError};

/// Fields decoded from an announcement (`0xE0`) or beacon (`0xE1`) payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    /// The host the desk is bound to; `None` after power-up.
    pub host: Option<MacAddress>,
    /// Firmware version, e.g. `v1.08`.
    pub firmware: String,
    /// Device name, e.g. `CNTRL|24`.
    pub device: String,
}

impl Announce {
    /// Payload size: host MAC, 8 unknown bytes, two 10-byte text fields.
    pub const SIZE: usize = 34;

    /// Decodes an announcement from a broadcast frame's payload.
    ///
    /// # Errors
    /// [`ParseError::TooShort`] when the payload is under 34 bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, ParseError> {
        let b = payload.get(..Self::SIZE).ok_or(ParseError::TooShort {
            needed: Self::SIZE,
            got: payload.len(),
        })?;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&b[..6]);
        Ok(Self {
            host: (mac != [0; 6]).then_some(MacAddress(mac)),
            firmware: ascii_field(&b[14..24]),
            device: ascii_field(&b[24..34]),
        })
    }

    /// Decodes `frame` if it is an announcement or beacon broadcast from a
    /// Digidesign address.
    #[must_use]
    pub fn from_frame(frame: &Frame) -> Option<Self> {
        let kind = matches!(frame.header.command, Command::Announce | Command::Beacon);
        (kind && frame.is_broadcast() && frame.src.is_digidesign())
            .then(|| Self::parse(&frame.payload).ok())
            .flatten()
    }
}

/// NUL-terminated text field; non-ASCII bytes become U+FFFD.
fn ascii_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Header;

    /// As recorded from a desk with firmware 1.08.
    fn payload(host: [u8; 6]) -> Vec<u8> {
        let mut p = host.to_vec();
        p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 6]);
        p.extend_from_slice(b"v1.08\0\0\0\0\0");
        p.extend_from_slice(b"CNTRL|24\0\0");
        p
    }

    #[test]
    fn parses_fields() {
        let a = Announce::parse(&payload([0xAA; 6])).unwrap();
        assert_eq!(a.host, Some(MacAddress([0xAA; 6])));
        assert_eq!(a.firmware, "v1.08");
        assert_eq!(a.device, "CNTRL|24");
        assert_eq!(Announce::parse(&payload([0; 6])).unwrap().host, None);
    }

    #[test]
    fn only_accepts_digidesign_broadcasts() {
        let desk = MacAddress([0x00, 0xA0, 0x7E, 1, 2, 3]);
        let other = MacAddress([0x02, 0, 0, 0, 0, 9]);
        let header = Header::new(Command::Beacon, 1);
        let p = payload([0; 6]);

        let data = Frame::new(
            MacAddress::BROADCAST,
            desk,
            Header::new(Command::Data, 0),
            p.clone(),
        );
        assert!(Announce::from_frame(&data).is_none());

        let bcast = Frame::new(MacAddress::BROADCAST, desk, header, p.clone());
        assert!(Announce::from_frame(&bcast).is_some());

        let foreign = Frame::new(MacAddress::BROADCAST, other, header, p.clone());
        assert!(Announce::from_frame(&foreign).is_none());

        let unicast = Frame::new(other, desk, header, p);
        assert!(Announce::from_frame(&unicast).is_none());
    }

    #[test]
    fn rejects_short_payload() {
        assert_eq!(
            Announce::parse(&[0; 20]),
            Err(ParseError::TooShort {
                needed: 34,
                got: 20
            })
        );
    }
}
