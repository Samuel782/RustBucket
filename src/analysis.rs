//! Checks recorded traffic against the specification.
//!
//! Feed the packets of a capture to [`Analyzer::add`] in order. Each call
//! returns a readable description of the frame, with `!` lines for anything
//! that contradicts PROTOCOL.md; [`Analyzer::summary`] collects the evidence
//! about the protocol (message lengths, counter rule, ACK contents, button IDs).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::time::Duration;

use crate::buttons::lookup;
use crate::debounce::Debouncer;
use crate::header::checksum;
use crate::message::{ButtonId, hex};
use crate::pcap::Packet;
use crate::{Announce, Command, DeskMessage, ETHERTYPE, Frame, MacAddress, parse_messages};

/// Which way a frame travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Sent by the desk (source MAC has the Digidesign OUI).
    FromDesk,
    /// Sent by the host.
    ToDesk,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Self::FromDesk => 0,
            Self::ToDesk => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::FromDesk => Self::ToDesk,
            Self::ToDesk => Self::FromDesk,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FromDesk => "desk->host",
            Self::ToDesk => "host->desk",
        })
    }
}

/// Evidence collected from a whole capture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Control|24 frames seen.
    pub frames: usize,
    /// Frames with the Control|24 `EtherType` that did not decode.
    pub malformed: usize,
    /// Frames of other protocols (skipped).
    pub other_traffic: usize,
    /// Packets by direction and raw `command` byte.
    pub packets: BTreeMap<(Direction, u8), usize>,
    /// Announcements by "device firmware".
    pub announcements: BTreeMap<String, usize>,
    /// Host frames recorded twice within 2 ms: BPF hands the program its own
    /// sent frames back, and recordings made before this was filtered hold
    /// both copies. The second copy is skipped.
    pub echoes: usize,
    /// Frames whose header checksum does not match the payload (§2).
    pub bad_checksums: usize,
    /// Data packets with a non-zero `retry` field, by direction.
    pub retries: BTreeMap<Direction, usize>,
    /// Consecutive data packets whose `send_counter` grew by the message
    /// count of the newer packet (the rule this driver uses, §4.3).
    pub counter_after: usize,
    /// ...grew by the message count of the older packet.
    pub counter_before: usize,
    /// ...grew by neither.
    pub counter_other: usize,
    /// ACKs whose `ack_counter` equals the last data `send_counter` of the
    /// other side.
    pub ack_matches: usize,
    /// ACKs that echo something else.
    pub ack_mismatches: usize,
    /// Data packets whose header message count differs from what the parser
    /// found: evidence of a wrong length in §5.
    pub count_mismatches: usize,
    /// Payloads the parser rejected.
    pub parse_errors: usize,
    /// Unparsed message bytes and how often each appeared.
    pub unknown_messages: BTreeMap<Vec<u8>, usize>,
    /// Desk buttons and how often each was pressed, after debouncing.
    pub buttons: BTreeMap<ButtonId, usize>,
    /// Button messages dropped as contact bounce ([`Debouncer`]).
    pub bounces: usize,
    /// Track indexes of faders moved on the desk.
    pub faders: BTreeSet<u8>,
    /// Track indexes of V-Pots turned on the desk.
    pub vpots: BTreeSet<u8>,
    /// Indexes of other encoders turned (28 = jog wheel).
    pub encoders: BTreeSet<u8>,
    /// System messages from the desk, by their first four bytes.
    pub desk_sysex: BTreeMap<Vec<u8>, usize>,
}

/// Walks a capture frame by frame.
#[derive(Debug, Default)]
pub struct Analyzer {
    start: Option<Duration>,
    /// Last data packet per direction: `(send_counter, n_messages)`.
    last_data: [Option<(u32, u8)>; 2],
    /// Per direction: an `online` packet is waiting for its ACK (`ack_counter` 0).
    online_pending: [bool; 2],
    /// Last host frame, to spot BPF echoes.
    last_host_frame: Option<(Duration, Vec<u8>)>,
    debouncer: Debouncer,
    summary: Summary,
}

impl Analyzer {
    /// Empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evidence collected so far.
    #[must_use]
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Analyses the next packet of the capture. Returns its description, or
    /// `None` for traffic of other protocols.
    pub fn add(&mut self, packet: &Packet) -> Option<String> {
        let start = *self.start.get_or_insert(packet.timestamp);
        let time = packet.timestamp.saturating_sub(start).as_secs_f64();
        if packet.data.get(12..14) != Some(&ETHERTYPE.to_be_bytes()[..]) {
            self.summary.other_traffic += 1;
            return None;
        }
        if frame_is_echo(&mut self.last_host_frame, packet) {
            self.summary.echoes += 1;
            return None;
        }
        let frame = match Frame::parse(&packet.data) {
            Ok(frame) => frame,
            Err(e) => {
                self.summary.malformed += 1;
                return Some(format!("{time:10.6}  malformed frame: {e}"));
            }
        };
        self.summary.frames += 1;

        let direction = if frame.src.is_digidesign() {
            Direction::FromDesk
        } else {
            Direction::ToDesk
        };
        let h = frame.header;
        let command = u8::from(h.command);
        *self
            .summary
            .packets
            .entry((direction, command))
            .or_default() += 1;

        let mut out = format!(
            "{time:10.6}  {direction}  {:<8} send {:<6} ack {:<6} retry {:<2} sum {:04x}  {} msg",
            command_name(h.command),
            h.send_counter,
            h.ack_counter,
            h.retry,
            h.checksum,
            h.n_messages,
        );
        if !frame.checksum_ok() {
            self.summary.bad_checksums += 1;
            let _ = write!(
                out,
                "\n    ! checksum, payload sums to {:04x}",
                checksum(&frame.payload)
            );
        }

        if let Some(announce) = Announce::from_frame(&frame) {
            self.on_announce(&announce, &mut out);
            return Some(out);
        }
        let at = packet.timestamp;
        match h.command {
            Command::Data if h.n_messages > 0 => self.on_data(direction, &frame, at, &mut out),
            Command::Ack => self.on_ack(direction, h.ack_counter, &mut out),
            Command::Online => {
                // The sender's counter restarts with the handshake (§4.2).
                self.last_data[direction.index()] = None;
                self.online_pending[direction.index()] = true;
            }
            _ => {}
        }
        Some(out)
    }

    fn on_announce(&mut self, announce: &Announce, out: &mut String) {
        let name = format!("{} firmware {}", announce.device, announce.firmware);
        let host = announce
            .host
            .map_or_else(|| "no host".to_string(), |h| format!("bound to {h}"));
        let _ = write!(out, "\n    {name}, {host}");
        *self.summary.announcements.entry(name).or_default() += 1;
    }

    fn on_data(&mut self, direction: Direction, frame: &Frame, at: Duration, out: &mut String) {
        let h = frame.header;
        let retry = h.is_retry();
        if retry {
            *self.summary.retries.entry(direction).or_default() += 1;
            let _ = write!(out, "\n    ! retransmission");
        } else {
            self.check_counter(direction, h.send_counter, h.n_messages, out);
        }

        let mut parsed = 0usize;
        for message in parse_messages(&frame.payload) {
            parsed += 1;
            match message {
                Ok(m) => {
                    let _ = write!(out, "\n    {m}");
                    // A retransmission repeats messages already counted.
                    if !retry && !self.record_message(direction, m, at) {
                        let _ = write!(out, " (bounce, dropped)");
                    }
                }
                Err(e) => {
                    self.summary.parse_errors += 1;
                    let _ = write!(out, "\n    ! parse error: {e}");
                }
            }
        }
        if parsed != usize::from(h.n_messages) {
            self.summary.count_mismatches += 1;
            let _ = write!(
                out,
                "\n    ! header declares {} messages, parser found {parsed}",
                h.n_messages
            );
        }
    }

    fn check_counter(&mut self, direction: Direction, counter: u32, n: u8, out: &mut String) {
        let slot = &mut self.last_data[direction.index()];
        if let Some((previous, previous_n)) = slot.replace((counter, n)) {
            let delta = counter.wrapping_sub(previous);
            if delta == u32::from(n) {
                self.summary.counter_after += 1;
            } else if delta == u32::from(previous_n) {
                self.summary.counter_before += 1;
            } else {
                self.summary.counter_other += 1;
                let _ = write!(
                    out,
                    "\n    ! send_counter moved by {delta} (previous packet had {previous_n} messages, this one {n})"
                );
            }
        }
    }

    fn on_ack(&mut self, direction: Direction, ack_counter: u32, out: &mut String) {
        let peer = direction.other().index();
        if ack_counter == 0 && std::mem::take(&mut self.online_pending[peer]) {
            self.summary.ack_matches += 1;
            return;
        }
        let Some((acked, _)) = self.last_data[peer] else {
            return;
        };
        if ack_counter == acked {
            self.summary.ack_matches += 1;
        } else {
            self.summary.ack_mismatches += 1;
            let _ = write!(
                out,
                "\n    ! ack_counter {ack_counter}, last data packet had send_counter {acked}"
            );
        }
    }

    /// Counts one message; false if it was dropped as a bounce.
    fn record_message(&mut self, direction: Direction, message: DeskMessage, at: Duration) -> bool {
        let s = &mut self.summary;
        match message {
            DeskMessage::Unknown(bytes) => {
                *s.unknown_messages.entry(bytes).or_default() += 1;
            }
            _ if direction == Direction::ToDesk => {}
            DeskMessage::Button { id, pressed } => {
                if !self.debouncer.accept(id, pressed, at) {
                    s.bounces += 1;
                    return false;
                }
                let presses = s.buttons.entry(id).or_default();
                *presses += usize::from(pressed);
            }
            DeskMessage::Encoder { index, .. } => {
                s.encoders.insert(index);
            }
            DeskMessage::Fader { track, .. } => {
                s.faders.insert(track.index());
            }
            DeskMessage::VPot { track, .. } => {
                s.vpots.insert(track.index());
            }
            DeskMessage::SysEx(bytes) => {
                let kind = bytes[..bytes.len().min(4)].to_vec();
                *s.desk_sysex.entry(kind).or_default() += 1;
            }
            _ => {}
        }
        true
    }
}

/// True for the second copy of a host frame recorded twice (see [`Summary::echoes`]).
fn frame_is_echo(last: &mut Option<(Duration, Vec<u8>)>, packet: &Packet) -> bool {
    let from_host = packet
        .data
        .get(6..9)
        .is_some_and(|oui| oui != MacAddress::DIGIDESIGN_OUI);
    if !from_host {
        return false;
    }
    let echo = last.as_ref().is_some_and(|(t, data)| {
        *data == packet.data && packet.timestamp.saturating_sub(*t) < Duration::from_millis(2)
    });
    *last = (!echo).then(|| (packet.timestamp, packet.data.clone()));
    echo
}

fn command_name(command: Command) -> String {
    match command {
        Command::Unknown(byte) => format!("{byte:#04x}?"),
        known => format!("{known:?}"),
    }
}

fn tracks(set: &BTreeSet<u8>) -> String {
    if set.is_empty() {
        return "none".into();
    }
    set.iter().map(u8::to_string).collect::<Vec<_>>().join(" ")
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Control|24 frames: {} ({} malformed, {} frames of other protocols skipped)",
            self.frames, self.malformed, self.other_traffic
        )?;
        if self.echoes > 0 {
            writeln!(
                f,
                "host frames recorded twice (BPF echo, skipped): {}",
                self.echoes
            )?;
        }
        writeln!(f, "bad checksums: {}", self.bad_checksums)?;
        writeln!(f, "packets:")?;
        for ((direction, command), count) in &self.packets {
            let name = command_name(Command::from(*command));
            writeln!(f, "  {direction}  {command:#04x} {name:<12} {count}")?;
        }
        for (name, count) in &self.announcements {
            writeln!(f, "announcement: {name} ({count}x)")?;
        }
        for (direction, count) in &self.retries {
            writeln!(f, "retransmissions {direction}: {count}")?;
        }
        writeln!(
            f,
            "send_counter growth (§4.3): by this packet's count {}, by the previous packet's count {}, neither {}",
            self.counter_after, self.counter_before, self.counter_other
        )?;
        writeln!(
            f,
            "ACKs echoing the peer's last send_counter: {} of {}",
            self.ack_matches,
            self.ack_matches + self.ack_mismatches
        )?;
        writeln!(
            f,
            "message count mismatches (§5 lengths): {}",
            self.count_mismatches
        )?;
        writeln!(f, "parse errors: {}", self.parse_errors)?;
        if !self.unknown_messages.is_empty() {
            writeln!(f, "unknown messages:")?;
            for (bytes, count) in &self.unknown_messages {
                writeln!(f, "  {count:>5}x  {}", hex(bytes))?;
            }
        }
        writeln!(f, "faders moved (track index): {}", tracks(&self.faders))?;
        writeln!(f, "V-Pots turned (track index): {}", tracks(&self.vpots))?;
        writeln!(f, "other encoders (28 = jog): {}", tracks(&self.encoders))?;
        if !self.desk_sysex.is_empty() {
            writeln!(f, "system messages from the desk (first bytes):")?;
            for (kind, count) in &self.desk_sysex {
                writeln!(f, "  {count:>5}x  {} ...", hex(kind))?;
            }
        }
        writeln!(f, "button bounces dropped: {}", self.bounces)?;
        writeln!(f, "buttons ({} distinct, id: presses):", self.buttons.len())?;
        for (&id, presses) in &self.buttons {
            let name = lookup(id).map_or_else(|| "?".to_string(), |b| b.to_string());
            writeln!(f, "  {}  {presses:>3}  {name}", hex(&id.0))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;
    use crate::{MacAddress, message::Track};

    const DESK: MacAddress = MacAddress([0x00, 0xA0, 0x7E, 1, 2, 3]);
    const HOST: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    fn packet(ms: u64, frame: &Frame) -> Packet {
        Packet {
            timestamp: Duration::from_millis(ms),
            data: frame.to_bytes(),
        }
    }

    fn data(src: MacAddress, dst: MacAddress, counter: u32, n: u8, payload: &[u8]) -> Frame {
        let mut header = Header::new(Command::Data, n);
        header.send_counter = counter;
        Frame::new(dst, src, header, payload.to_vec())
    }

    fn announce() -> Frame {
        let mut payload = vec![0; 14];
        payload.extend_from_slice(b"1.0\0\0\0\0\0\0\0");
        payload.extend_from_slice(b"C24\0\0\0\0\0\0\0");
        Frame::new(
            MacAddress::BROADCAST,
            DESK,
            Header::new(Command::Announce, 1),
            payload,
        )
    }

    #[test]
    fn collects_evidence_from_a_session() {
        let mut a = Analyzer::new();
        let frames = [
            announce(),
            Frame::online(DESK, HOST),
            data(DESK, HOST, 1, 1, &[0x90, 0x18, 0x40]),
            Frame::ack(DESK, HOST, 1),
            data(DESK, HOST, 2, 1, &[0x90, 0x18, 0x00]),
            data(
                DESK,
                HOST,
                4,
                2,
                &[0x90, 0x18, 0x40, 0xB0, 0x02, 0x40, 0x22, 0x00],
            ),
            Frame::ack(DESK, HOST, 99),
            // Header says 2, but the unknown status byte swallows the rest.
            data(DESK, HOST, 6, 2, &[0xC0, 0x01, 0x02]),
        ];
        let lines: Vec<_> = frames
            .iter()
            .enumerate()
            .map(|(i, f)| a.add(&packet(i as u64, f)).unwrap())
            .collect();
        assert!(lines[0].contains("C24 firmware 1.0, no host"));
        assert!(lines[6].contains("! ack_counter 99"));
        assert!(lines[7].contains("! header declares 2 messages, parser found 1"));

        let s = a.summary();
        assert_eq!(s.frames, 8);
        assert_eq!(s.counter_after, 3);
        assert_eq!(s.counter_other, 0);
        assert_eq!((s.ack_matches, s.ack_mismatches), (1, 1));
        assert_eq!(s.count_mismatches, 1);
        // The second press comes 1 ms after the release: a bounce.
        assert_eq!(s.buttons, BTreeMap::from([(ButtonId([0x18, 0x00]), 1)]));
        assert_eq!(s.bounces, 1);
        assert!(lines[5].contains("(bounce, dropped)"));
        assert_eq!(
            s.faders,
            BTreeSet::from([Track::try_from(2).unwrap().index()])
        );
        assert_eq!(s.unknown_messages[&vec![0xC0, 0x01, 0x02]], 1);
        assert!(s.to_string().contains("buttons (1 distinct"));
    }

    #[test]
    fn spots_counter_jumps_and_skips_other_traffic() {
        let mut a = Analyzer::new();
        a.add(&packet(0, &data(DESK, HOST, 1, 1, &[0x00])));
        let line = a.add(&packet(1, &data(DESK, HOST, 5, 1, &[0x00]))).unwrap();
        assert!(line.contains("! send_counter moved by 4"));

        let mut ipv4 = data(DESK, HOST, 1, 1, &[0x00]).to_bytes();
        ipv4[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(
            a.add(&Packet {
                timestamp: Duration::ZERO,
                data: ipv4
            }),
            None
        );
        assert_eq!(a.summary().other_traffic, 1);
        assert_eq!(a.summary().counter_other, 1);
    }
}
