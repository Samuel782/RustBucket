//! Complete Ethernet frames: MAC header, `EtherType`, C24 header and payload
//! (PROTOCOL.md §2).

use crate::header::{Command, Header, checksum};
use crate::{ETHERTYPE, MacAddress, ParseError};

/// Size of the Ethernet header (two MACs and the `EtherType`).
const ETH_HEADER_SIZE: usize = 14;

/// A decoded Control|24 frame. The payload is kept as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Destination MAC (offset 0).
    pub dst: MacAddress,
    /// Source MAC (offset 6).
    pub src: MacAddress,
    /// C24 header (offset 14).
    pub header: Header,
    /// Payload (offset 30), exactly `header.length - 16` bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Ethernet header plus C24 header (§2).
    pub const MIN_SIZE: usize = ETH_HEADER_SIZE + Header::SIZE;

    /// Decodes a raw Ethernet frame as captured from the wire.
    ///
    /// Bytes past `header.length` are ignored, since Ethernet pads short
    /// frames to 60 bytes (§1).
    ///
    /// # Errors
    /// [`ParseError`] when the buffer is too short, the `EtherType` is not
    /// `0x885F`, or the header length is inconsistent with the frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(ParseError::TooShort {
                needed: Self::MIN_SIZE,
                got: bytes.len(),
            });
        }
        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        if ethertype != ETHERTYPE {
            return Err(ParseError::WrongEtherType(ethertype));
        }
        let header = Header::parse(&bytes[ETH_HEADER_SIZE..])?;
        let declared = header.payload_len()?;
        let rest = &bytes[Self::MIN_SIZE..];
        let payload = rest.get(..declared).ok_or(ParseError::LengthExceedsFrame {
            declared,
            available: rest.len(),
        })?;
        Ok(Self {
            dst: MacAddress(mac_at(bytes, 0)),
            src: MacAddress(mac_at(bytes, 6)),
            header,
            payload: payload.to_vec(),
        })
    }

    /// Builds a frame, filling `header.length` and `header.checksum` from
    /// the payload.
    ///
    /// # Panics
    /// If the payload does not fit the 16-bit `length` field.
    #[must_use]
    pub fn new(dst: MacAddress, src: MacAddress, mut header: Header, payload: Vec<u8>) -> Self {
        header.length = u16::try_from(Header::SIZE + payload.len())
            .expect("payload too large for the 16-bit length field");
        header.checksum = checksum(&payload);
        Self {
            dst,
            src,
            header,
            payload,
        }
    }

    /// Host → desk `online` packet that starts a session (§4.2).
    #[must_use]
    pub fn online(desk: MacAddress, host: MacAddress) -> Self {
        Self::new(desk, host, Header::new(Command::Online, 0), Vec::new())
    }

    /// Acknowledges the peer's `send_counter` (§4.3).
    #[must_use]
    pub fn ack(dst: MacAddress, src: MacAddress, peer_send_counter: u32) -> Self {
        let mut header = Header::new(Command::Ack, 0);
        header.ack_counter = peer_send_counter;
        Self::new(dst, src, header, Vec::new())
    }

    /// True when `header.checksum` matches the payload (§2).
    #[must_use]
    pub fn checksum_ok(&self) -> bool {
        self.header.checksum == checksum(&self.payload)
    }

    /// True when sent to the broadcast address, as the announcement is (§4.1).
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.dst.is_broadcast()
    }

    /// Encodes the frame without Ethernet padding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::MIN_SIZE + self.payload.len());
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&ETHERTYPE.to_be_bytes());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

fn mac_at(bytes: &[u8], offset: usize) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes[offset..offset + 6]);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESK: MacAddress = MacAddress([0x00, 0xA0, 0x7E, 0x01, 0x02, 0x03]);
    const HOST: MacAddress = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    /// Hand-built from PROTOCOL.md §2: a data frame carrying one 3-byte message.
    fn data_frame_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&HOST.0);
        b.extend_from_slice(&DESK.0);
        b.extend_from_slice(&[0x88, 0x5F]);
        b.extend_from_slice(&[0x00, 0x13, 0x00, 0xE8]); // length 19, checksum
        b.extend_from_slice(&[0, 0, 0, 5, 0, 0, 0, 0]); // send 5, ack 0
        b.extend_from_slice(&[0, 0, 0x00, 1]); // retry 0, Data, 1 message
        b.extend_from_slice(&[0x90, 0x18, 0x40]); // payload (button press shape, §5.3)
        b
    }

    #[test]
    fn parses_and_round_trips_a_data_frame() {
        let bytes = data_frame_bytes();
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(frame.dst, HOST);
        assert_eq!(frame.src, DESK);
        assert!(frame.src.is_digidesign());
        assert_eq!(frame.header.command, Command::Data);
        assert_eq!(frame.header.send_counter, 5);
        assert_eq!(frame.payload, [0x90, 0x18, 0x40]);
        assert_eq!(frame.to_bytes(), bytes);
    }

    #[test]
    fn ignores_ethernet_padding() {
        let mut bytes = data_frame_bytes();
        bytes.resize(60, 0);
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(frame.payload.len(), 3);
    }

    #[test]
    fn rejects_foreign_and_truncated_frames() {
        let mut bytes = data_frame_bytes();
        bytes[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(
            Frame::parse(&bytes),
            Err(ParseError::WrongEtherType(0x0800))
        );

        let bytes = data_frame_bytes();
        assert_eq!(
            Frame::parse(&bytes[..31]),
            Err(ParseError::LengthExceedsFrame {
                declared: 3,
                available: 1
            })
        );
        assert_eq!(
            Frame::parse(&bytes[..20]),
            Err(ParseError::TooShort {
                needed: 30,
                got: 20
            })
        );
    }

    #[test]
    fn builds_session_packets() {
        let online = Frame::online(DESK, HOST);
        assert_eq!(online.header.command, Command::Online);
        assert_eq!(online.header.length, 16);
        assert_eq!(online.to_bytes().len(), Frame::MIN_SIZE);

        let ack = Frame::ack(DESK, HOST, 42);
        let parsed = Frame::parse(&ack.to_bytes()).unwrap();
        assert_eq!(parsed.header.command, Command::Ack);
        assert_eq!(parsed.header.ack_counter, 42);
        assert_eq!(parsed.payload, [] as [u8; 0]);
    }
}
