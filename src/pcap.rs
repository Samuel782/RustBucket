//! Classic pcap files: recording a live session and reading it back.
//!
//! Only the original libpcap format with Ethernet link type is handled,
//! which is what [`Recorder`] writes and what Wireshark offers as
//! "Wireshark/tcpdump - pcap". The newer pcapng format is detected and
//! rejected with a clear error.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use crate::ETHERTYPE;
use crate::driver::Link;

/// Magic number for microsecond timestamps.
const MAGIC_MICROS: u32 = 0xA1B2_C3D4;
/// Magic number for nanosecond timestamps.
const MAGIC_NANOS: u32 = 0xA1B2_3C4D;
/// First four bytes of a pcapng file (section header block type).
const PCAPNG_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
/// `LINKTYPE_ETHERNET`.
const LINKTYPE_ETHERNET: u32 = 1;
const SNAPLEN: u32 = 65_535;
const FILE_HEADER_SIZE: usize = 24;
const RECORD_HEADER_SIZE: usize = 16;

/// One captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Capture time since the Unix epoch.
    pub timestamp: Duration,
    /// The Ethernet frame as captured.
    pub data: Vec<u8>,
}

/// Why a capture file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// The file does not start with a pcap magic number.
    NotPcap,
    /// The file is pcapng, which is not supported.
    PcapNg,
    /// The capture is not of Ethernet frames.
    LinkType(u32),
    /// The file ends inside a header or a packet.
    Truncated {
        /// Offset of the incomplete part.
        offset: usize,
    },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPcap => write!(f, "not a pcap file"),
            Self::PcapNg => write!(
                f,
                "pcapng is not supported; in Wireshark use File > Save As > \"Wireshark/tcpdump - pcap\""
            ),
            Self::LinkType(t) => write!(f, "link type {t} is not Ethernet"),
            Self::Truncated { offset } => write!(f, "file is truncated at byte {offset}"),
        }
    }
}

impl std::error::Error for PcapError {}

/// Reads every packet of a pcap file held in memory.
///
/// # Errors
/// [`PcapError`] if the file is not a classic Ethernet pcap or is cut short.
/// A capture that stopped in the middle of its last packet (e.g. the program
/// was killed) is reported as [`PcapError::Truncated`].
pub fn read(bytes: &[u8]) -> Result<Vec<Packet>, PcapError> {
    if bytes.starts_with(&PCAPNG_MAGIC) {
        return Err(PcapError::PcapNg);
    }
    let header = bytes
        .get(..FILE_HEADER_SIZE)
        .ok_or(PcapError::Truncated { offset: 0 })?;
    let little = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let big = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let (big_endian, nanos) = match (little, big) {
        (MAGIC_MICROS, _) => (false, false),
        (MAGIC_NANOS, _) => (false, true),
        (_, MAGIC_MICROS) => (true, false),
        (_, MAGIC_NANOS) => (true, true),
        _ => return Err(PcapError::NotPcap),
    };
    let word = |b: &[u8], at: usize| {
        let w = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if big_endian {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        }
    };
    let link_type = word(header, 20);
    if link_type != LINKTYPE_ETHERNET {
        return Err(PcapError::LinkType(link_type));
    }

    let mut packets = Vec::new();
    let mut offset = FILE_HEADER_SIZE;
    while offset < bytes.len() {
        let record = bytes
            .get(offset..offset + RECORD_HEADER_SIZE)
            .ok_or(PcapError::Truncated { offset })?;
        let seconds = word(record, 0);
        let fraction = word(record, 4);
        let captured = word(record, 8) as usize;
        let start = offset + RECORD_HEADER_SIZE;
        let data = bytes
            .get(start..start + captured)
            .ok_or(PcapError::Truncated { offset })?;
        let fraction = if nanos {
            Duration::from_nanos(u64::from(fraction))
        } else {
            Duration::from_micros(u64::from(fraction))
        };
        packets.push(Packet {
            timestamp: Duration::from_secs(u64::from(seconds)) + fraction,
            data: data.to_vec(),
        });
        offset = start + captured;
    }
    Ok(packets)
}

/// Writes a pcap file (little-endian, microsecond timestamps).
#[derive(Debug)]
pub struct Writer<W> {
    out: W,
}

impl<W: Write> Writer<W> {
    /// Starts a file by writing its header.
    ///
    /// # Errors
    /// Any write error.
    pub fn new(mut out: W) -> io::Result<Self> {
        let mut header = Vec::with_capacity(FILE_HEADER_SIZE);
        header.extend_from_slice(&MAGIC_MICROS.to_le_bytes());
        header.extend_from_slice(&2u16.to_le_bytes());
        header.extend_from_slice(&4u16.to_le_bytes());
        header.extend_from_slice(&0i32.to_le_bytes()); // time zone
        header.extend_from_slice(&0u32.to_le_bytes()); // accuracy
        header.extend_from_slice(&SNAPLEN.to_le_bytes());
        header.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        out.write_all(&header)?;
        out.flush()?;
        Ok(Self { out })
    }

    /// Appends one frame. Each record goes out in a single write and is
    /// flushed, so the file stays readable if the program is killed.
    ///
    /// # Errors
    /// Any write error.
    pub fn write(&mut self, timestamp: Duration, frame: &[u8]) -> io::Result<()> {
        let frame = &frame[..frame.len().min(SNAPLEN as usize)];
        let len = u32::try_from(frame.len()).unwrap_or(SNAPLEN);
        // pcap stores 32-bit seconds; that lasts until 2106.
        let seconds = u32::try_from(timestamp.as_secs()).unwrap_or(u32::MAX);
        let mut record = Vec::with_capacity(RECORD_HEADER_SIZE + frame.len());
        record.extend_from_slice(&seconds.to_le_bytes());
        record.extend_from_slice(&timestamp.subsec_micros().to_le_bytes());
        record.extend_from_slice(&len.to_le_bytes());
        record.extend_from_slice(&len.to_le_bytes());
        record.extend_from_slice(frame);
        self.out.write_all(&record)?;
        self.out.flush()
    }

    /// The underlying writer.
    pub fn into_inner(self) -> W {
        self.out
    }
}

/// A [`Link`] that records every Control|24 frame it receives or sends.
///
/// Other traffic on the interface (IP, ARP, …) is passed through but not
/// written, so a recording made on a shared network holds only desk traffic.
#[derive(Debug)]
pub struct Recorder<L, W> {
    link: L,
    writer: Writer<W>,
}

impl<L: Link, W: Write> Recorder<L, W> {
    /// Records the traffic of `link` into `writer`.
    pub fn new(link: L, writer: Writer<W>) -> Self {
        Self { link, writer }
    }

    /// The wrapped link and the writer.
    pub fn into_parts(self) -> (L, Writer<W>) {
        (self.link, self.writer)
    }

    fn record(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.get(12..14) != Some(&ETHERTYPE.to_be_bytes()[..]) {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        self.writer.write(now, frame)
    }
}

impl<L: Link, W: Write> Link for Recorder<L, W> {
    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let frame = self.link.recv()?;
        if let Some(bytes) = &frame {
            self.record(bytes)?;
        }
        Ok(frame)
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.link.send(frame)?;
        self.record(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_packets() {
        let mut writer = Writer::new(Vec::new()).unwrap();
        let t = Duration::new(1_700_000_000, 123_456_000);
        writer.write(t, &[1, 2, 3]).unwrap();
        writer.write(t + Duration::from_millis(5), &[]).unwrap();
        let bytes = writer.into_inner();

        let packets = read(&bytes).unwrap();
        assert_eq!(
            packets,
            [
                Packet {
                    timestamp: t,
                    data: vec![1, 2, 3]
                },
                Packet {
                    timestamp: t + Duration::from_millis(5),
                    data: vec![]
                },
            ]
        );
    }

    #[test]
    fn reads_big_endian_nanosecond_files() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC_NANOS.to_be_bytes());
        bytes.extend_from_slice(&[0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&SNAPLEN.to_be_bytes());
        bytes.extend_from_slice(&LINKTYPE_ETHERNET.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB]);

        let packets = read(&bytes).unwrap();
        assert_eq!(packets[0].timestamp, Duration::new(10, 7));
        assert_eq!(packets[0].data, [0xAA, 0xBB]);
    }

    #[test]
    fn rejects_other_formats() {
        assert_eq!(
            read(&[0x0A, 0x0D, 0x0D, 0x0A, 0, 0]),
            Err(PcapError::PcapNg)
        );
        assert_eq!(read(&[0; 24]), Err(PcapError::NotPcap));
        assert_eq!(read(&[0xD4]), Err(PcapError::Truncated { offset: 0 }));

        let mut wifi = Writer::new(Vec::new()).unwrap().into_inner();
        wifi[20] = 105; // LINKTYPE_IEEE802_11
        assert_eq!(read(&wifi), Err(PcapError::LinkType(105)));
    }

    #[test]
    fn reports_a_cut_off_last_packet() {
        let mut writer = Writer::new(Vec::new()).unwrap();
        writer.write(Duration::ZERO, &[1, 2, 3, 4]).unwrap();
        let mut bytes = writer.into_inner();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            read(&bytes),
            Err(PcapError::Truncated {
                offset: FILE_HEADER_SIZE
            })
        );
    }

    #[test]
    fn recorder_keeps_only_desk_traffic() {
        struct Loopback(Vec<Vec<u8>>);
        impl Link for Loopback {
            fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
                Ok(self.0.pop())
            }
            fn send(&mut self, _: &[u8]) -> io::Result<()> {
                Ok(())
            }
        }
        let mut c24 = vec![0; 12];
        c24.extend_from_slice(&ETHERTYPE.to_be_bytes());
        let mut ipv4 = vec![0; 12];
        ipv4.extend_from_slice(&[0x08, 0x00]);

        let link = Loopback(vec![ipv4.clone(), c24.clone()]);
        let mut recorder = Recorder::new(link, Writer::new(Vec::new()).unwrap());
        assert_eq!(recorder.recv().unwrap(), Some(c24.clone()));
        assert_eq!(recorder.recv().unwrap(), Some(ipv4.clone()));
        recorder.send(&ipv4).unwrap();
        recorder.send(&c24).unwrap();

        let (_, writer) = recorder.into_parts();
        let packets = read(&writer.into_inner()).unwrap();
        let data: Vec<_> = packets.into_iter().map(|p| p.data).collect();
        assert_eq!(data, [c24.clone(), c24]);
    }
}
