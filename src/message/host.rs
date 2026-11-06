//! Messages sent by the host to the desk (PROTOCOL.md §5).

use super::{ButtonId, FaderPosition, Track};

/// Header shared by display, LED and meter system messages (§5.4).
const DISPLAY_PREFIX: [u8; 3] = [0xF0, 0x13, 0x01];
const SYSEX_END: u8 = 0xF7;

/// One message for the desk. [`HostMessage::encode`] produces its wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMessage {
    /// `00`: keepalive (§4.5).
    Keepalive,
    /// `B0 t hi 20+t lo`: drive a motorised fader (§5.1).
    FaderMove {
        /// Channel strip.
        track: Track,
        /// Target position.
        position: FaderPosition,
    },
    /// `90 a b`: switch a button LED (§5.3).
    Led {
        /// Which button.
        id: ButtonId,
        /// Lit or dark.
        on: bool,
    },
    /// `F0 13 01 40 t 00 c0 c1 c2 c3 F7`: four-character scribble strip (§5.4).
    ScribbleStrip {
        /// Channel strip.
        track: Track,
        /// Characters as 7-bit codes; see [`HostMessage::scribble`].
        text: [u8; 4],
    },
    /// `F0 13 01 30 19 dots d0…d7 F7`: transport (clock / counter) display,
    /// eight 7-segment digits (§5.4) [OBS]. [`HostMessage::clock_text`]
    /// builds it from text.
    Clock {
        /// Decimal points: bit `k` is the point of `segments[7 - k]`, so bit 0
        /// is the leftmost digit's and bit 6 the second digit from the right's;
        /// the rightmost digit has none.
        dots: u8,
        /// Segment masks, `segments[0]` = rightmost digit; see [`seven_segment`].
        segments: [u8; 8],
    },
    /// `F0 13 01 10 (32·side+t) l0 l1 F7`: channel meter (§5.4) [OBS].
    /// [`MeterLeds::level`] builds the level bytes.
    Meter {
        /// Channel strip.
        track: Track,
        /// Meter side: 0 = left, 1 = right [OBS]; masked to the low bit.
        side: u8,
        /// The two level bytes: LED bit masks, not a value.
        level: [u8; 2],
    },
    /// `F0 13 01 10 (32·side+24+pair) l0 l1 F7`: output bus meter (§5.4)
    /// [OBS]. Pair 0 side 0 is bus 1, pair 0 side 1 bus 2, …, pair 2 side 1
    /// bus 6.
    BusMeter {
        /// Stereo pair 0–2; other values are clamped to 2.
        pair: u8,
        /// Side 0 or 1; masked to the low bit.
        side: u8,
        /// The two level bytes, as for [`HostMessage::Meter`].
        level: [u8; 2],
    },
    /// `F0 13 01 00 (p0|t) p1 p2 F7`: V-Pot LED ring (§5.4). The first
    /// pattern byte shares its byte with the track index, so only its top
    /// bit (`0x40`) is kept. [`HostMessage::ring`] builds the pattern from
    /// LED positions.
    VPotRing {
        /// Channel strip.
        track: Track,
        /// LED pattern.
        pattern: [u8; 3],
    },
}

/// The 15 LEDs of a V-Pot ring by position: bit 0 is the leftmost LED,
/// bit 7 the centre one, bit 14 the rightmost (§5.4) [OBS].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RingLeds(u16);

impl RingLeds {
    /// Number of LEDs on a ring.
    pub const COUNT: u8 = 15;
    /// Position of the centre LED.
    pub const CENTER: u8 = 7;

    /// LEDs from a bit mask; bits above 14 are ignored.
    #[must_use]
    pub fn from_mask(mask: u16) -> Self {
        Self(mask & 0x7FFF)
    }

    /// The bit mask, bit 0 = leftmost LED.
    #[must_use]
    pub fn mask(self) -> u16 {
        self.0
    }

    /// A single LED at the position of `value` (0–127, left to right).
    #[must_use]
    pub fn dot(value: u8) -> Self {
        Self(1 << position(value))
    }

    /// LEDs from the left up to the position of `value`, as for a level.
    #[must_use]
    pub fn fill(value: u8) -> Self {
        Self((2 << position(value)) - 1)
    }

    /// LEDs from the centre to the position of `value`, as for pan or
    /// boost/cut.
    #[must_use]
    pub fn spread(value: u8) -> Self {
        let (low, high) = {
            let p = position(value);
            (p.min(Self::CENTER), p.max(Self::CENTER))
        };
        Self(((2u16 << high) - 1) & !((1u16 << low) - 1))
    }

    /// The three pattern bytes of the ring message. The wiring was mapped
    /// on the desk with `rustbucketd --ring-test`: the first byte's `0x40`
    /// is the leftmost LED, the second byte's bits `0x40`…`0x01` the LEDs
    /// from second to centre, the third byte's bits `0x40`…`0x01` the LEDs
    /// right of the centre up to the rightmost.
    #[must_use]
    pub fn pattern(self) -> [u8; 3] {
        let mut out = [0u8; 3];
        for led in (0..Self::COUNT).filter(|&i| self.0 & (1 << i) != 0) {
            match led {
                0 => out[0] |= 0x40,
                1..=7 => out[1] |= 1 << (7 - led),
                _ => out[2] |= 1 << (14 - led),
            }
        }
        out
    }
}

/// Segment mask for one character on the transport display, or `None` if
/// it cannot be drawn on seven segments.
///
/// Bits (§5.4) [OBS]: `40` top (a), `20` upper right (b), `10` lower right
/// (c), `08` bottom (d), `04` lower left (e), `02` upper left (f), `01`
/// middle (g). Letters use the usual 7-segment shapes, upper or lower case
/// as they read best.
#[must_use]
pub fn seven_segment(ch: char) -> Option<u8> {
    const A: u8 = 0x40;
    const B: u8 = 0x20;
    const C: u8 = 0x10;
    const D: u8 = 0x08;
    const E: u8 = 0x04;
    const F: u8 = 0x02;
    const G: u8 = 0x01;
    Some(match ch.to_ascii_uppercase() {
        ' ' => 0,
        '0' | 'O' if ch == '0' || ch == 'O' => A | B | C | D | E | F,
        '1' => B | C,
        '2' => A | B | D | E | G,
        '3' => A | B | C | D | G,
        '4' => B | C | F | G,
        '5' | 'S' => A | C | D | F | G,
        '6' => A | C | D | E | F | G,
        '7' => A | B | C,
        '8' => A | B | C | D | E | F | G,
        '9' => A | B | C | D | F | G,
        'A' => A | B | C | E | F | G,
        'B' => C | D | E | F | G,
        'C' if ch == 'c' => D | E | G,
        'C' => A | D | E | F,
        'D' => B | C | D | E | G,
        'E' => A | D | E | F | G,
        'F' => A | E | F | G,
        'G' => A | C | D | E | F,
        'H' if ch == 'h' => C | E | F | G,
        'H' => B | C | E | F | G,
        'I' => E | F,
        'J' => B | C | D | E,
        'L' => D | E | F,
        'N' => C | E | G,
        'O' => C | D | E | G,
        'P' => A | B | E | F | G,
        'Q' => A | B | C | F | G,
        'R' => E | G,
        'T' => D | E | F | G,
        'U' if ch == 'u' => C | D | E,
        'U' => B | C | D | E | F,
        'Y' => B | C | D | F | G,
        '-' => G,
        '_' => D,
        '=' => D | G,
        '\'' => F,
        '"' => B | F,
        _ => return None,
    })
}

/// The 14 LEDs of a meter, bit 0 = the bottom one (−50 dB), bit 13 the top
/// one (0 dB), §5.4 [OBS].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MeterLeds(u16);

impl MeterLeds {
    /// Printed scale of each LED, bottom to top.
    pub const SCALE_DB: [i8; 14] = [
        -50, -40, -35, -30, -26, -22, -18, -14, -10, -8, -6, -4, -2, 0,
    ];

    /// LEDs from a bit mask; bits above 13 are ignored.
    #[must_use]
    pub fn from_mask(mask: u16) -> Self {
        Self(mask & 0x3FFF)
    }

    /// The bit mask, bit 0 = bottom LED.
    #[must_use]
    pub fn mask(self) -> u16 {
        self.0
    }

    /// Bar lighting every LED whose mark is at or below `db`.
    #[must_use]
    pub fn from_db(db: f32) -> Self {
        let lit = Self::SCALE_DB
            .iter()
            .filter(|&&mark| f32::from(mark) <= db)
            .count();
        Self((1u16 << lit) - 1)
    }

    /// The two level bytes of the meter message. Mapped on the desk with
    /// `rustbucketd --meter-test`: the first byte's bits `0x40`…`0x08` are
    /// 0, −2, −4, −6 dB and the second byte's `0x40`…`0x08` −18, −22, −26,
    /// −30 dB. The three low bits of each byte light −8/−10/−14 and
    /// −35/−40/−50 dB; which bit is which follows the same order [INF].
    #[must_use]
    pub fn level(self) -> [u8; 2] {
        let low = u8::try_from(self.0 & 0x7F).unwrap_or(0);
        let high = u8::try_from((self.0 >> 7) & 0x7F).unwrap_or(0);
        [high, low]
    }
}

/// LED position 0–14 for a value 0–127, rounded to the nearest.
fn position(value: u8) -> u8 {
    let value = u16::from(value.min(127));
    u8::try_from((value * 14 + 63) / 127).unwrap_or(RingLeds::COUNT - 1)
}

impl HostMessage {
    /// Scribble-strip message from text: padded with spaces or cut to four
    /// characters; non-ASCII characters become `?`.
    #[must_use]
    pub fn scribble(track: Track, text: &str) -> Self {
        let mut out = [b' '; 4];
        for (slot, ch) in out.iter_mut().zip(text.chars()) {
            *slot = if ch.is_ascii() { ch as u8 } else { b'?' };
        }
        Self::ScribbleStrip { track, text: out }
    }

    /// Transport display showing `text`, right-aligned on the eight digits.
    ///
    /// A `.` lights the point of the character before it; characters
    /// [`seven_segment`] cannot draw show as blank. Text longer than eight
    /// digits keeps its last eight.
    #[must_use]
    pub fn clock_text(text: &str) -> Self {
        // (segments, point) left to right.
        let mut cells: Vec<(u8, bool)> = Vec::new();
        for ch in text.chars() {
            match (ch, cells.last_mut()) {
                ('.', Some((_, point))) if !*point => *point = true,
                ('.', _) => cells.push((0, true)),
                _ => cells.push((seven_segment(ch).unwrap_or(0), false)),
            }
        }
        let mut segments = [0u8; 8];
        let mut dots = 0u8;
        for (position, &(mask, point)) in cells.iter().rev().take(8).enumerate() {
            segments[position] = mask;
            if point && position > 0 {
                dots |= 1 << (7 - position);
            }
        }
        Self::Clock { dots, segments }
    }

    /// V-Pot ring message lighting `leds`.
    #[must_use]
    pub fn ring(track: Track, leds: RingLeds) -> Self {
        Self::VPotRing {
            track,
            pattern: leds.pattern(),
        }
    }

    /// Wire bytes of this message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match *self {
            Self::Keepalive => vec![0x00],
            Self::FaderMove { track, position } => {
                let t = track.index();
                let (high, low) = position.to_wire();
                vec![0xB0, t, high, 0x20 + t, low]
            }
            Self::Led {
                id: ButtonId([a, b]),
                on,
            } => {
                let state = if on { ButtonId::STATE_BIT } else { 0 };
                vec![0x90, data(a), (data(b) & !ButtonId::STATE_BIT) | state]
            }
            Self::ScribbleStrip { track, text } => {
                display(0x40, &[&[track.index(), 0x00], &text.map(data)])
            }
            Self::Clock { dots, segments } => {
                display(0x30, &[&[0x19, data(dots)], &segments.map(data)])
            }
            Self::Meter { track, side, level } => {
                let address = 32 * (side & 1) + track.index();
                display(0x10, &[&[address], &level.map(data)])
            }
            Self::BusMeter { pair, side, level } => {
                let address = 32 * (side & 1) + 24 + pair.min(2);
                display(0x10, &[&[address], &level.map(data)])
            }
            Self::VPotRing {
                track,
                pattern: [p0, p1, p2],
            } => {
                let first = (p0 & 0x40) | (track.index() & 0x3F);
                display(0x00, &[&[first, data(p1), data(p2)]])
            }
        }
    }
}

/// Keeps a value within the 7 bits allowed for data bytes.
fn data(byte: u8) -> u8 {
    byte & 0x7F
}

/// Builds `F0 13 01 <kind> <parts…> F7`.
fn display(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = DISPLAY_PREFIX.to_vec();
    out.push(kind);
    for part in parts {
        out.extend_from_slice(part);
    }
    out.push(SYSEX_END);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{DeskMessage, parse_messages};

    fn track(i: u8) -> Track {
        Track::try_from(i).unwrap()
    }

    #[test]
    fn fader_move_matches_the_desk_format() {
        let msg = HostMessage::FaderMove {
            track: track(3),
            position: FaderPosition::try_from(517).unwrap(),
        };
        let bytes = msg.encode();
        assert_eq!(bytes, [0xB0, 0x03, 0x40, 0x23, 0x50]);
        // Same layout in both directions (§5.1), so the desk parser reads it back.
        let parsed: Vec<_> = parse_messages(&bytes).collect();
        assert_eq!(
            parsed,
            [Ok(DeskMessage::Fader {
                track: track(3),
                position: FaderPosition::try_from(517).unwrap()
            })]
        );
    }

    #[test]
    fn led_sets_only_the_state_bit() {
        let id = ButtonId([0x18, 0x02]);
        assert_eq!(
            HostMessage::Led { id, on: true }.encode(),
            [0x90, 0x18, 0x42]
        );
        assert_eq!(
            HostMessage::Led { id, on: false }.encode(),
            [0x90, 0x18, 0x02]
        );
    }

    #[test]
    fn scribble_strip_pads_and_replaces() {
        assert_eq!(
            HostMessage::scribble(track(2), "Vox").encode(),
            [
                0xF0, 0x13, 0x01, 0x40, 0x02, 0x00, b'V', b'o', b'x', b' ', 0xF7
            ]
        );
        assert_eq!(
            HostMessage::scribble(track(0), "Bässe"),
            HostMessage::ScribbleStrip {
                track: track(0),
                text: *b"B?ss"
            }
        );
    }

    #[test]
    fn clock_layout() {
        let msg = HostMessage::Clock {
            dots: 0b001_0101,
            segments: [1, 2, 3, 4, 5, 6, 7, 0xFF],
        };
        assert_eq!(
            msg.encode(),
            [
                0xF0, 0x13, 0x01, 0x30, 0x19, 0x15, 1, 2, 3, 4, 5, 6, 7, 0x7F, 0xF7
            ]
        );
    }

    #[test]
    fn seven_segment_bits_match_the_desk() {
        // Observed with --clock-test: one bit on every digit.
        assert_eq!(seven_segment('-'), Some(0x01)); // middle
        assert_eq!(seven_segment('_'), Some(0x08)); // bottom
        assert_eq!(seven_segment('8'), Some(0x7F)); // all segments, as 7F showed
        assert_eq!(seven_segment('1'), Some(0x30)); // both right segments
        assert_eq!(seven_segment('L'), Some(0x0E));
        assert_eq!(seven_segment('o'), Some(0x1D));
        assert_eq!(seven_segment('0'), Some(0x7E));
        assert_eq!(seven_segment('%'), None);
    }

    #[test]
    fn clock_text_is_right_aligned_with_points() {
        let HostMessage::Clock { dots, segments } = HostMessage::clock_text("12.5") else {
            panic!("expected a clock message");
        };
        let s = |c| seven_segment(c).unwrap();
        assert_eq!(segments, [s('5'), s('2'), s('1'), 0, 0, 0, 0, 0]);
        // The point after "2" belongs to the second digit from the right.
        assert_eq!(dots, 1 << 6);

        let HostMessage::Clock { segments, .. } = HostMessage::clock_text("123456789") else {
            panic!("expected a clock message");
        };
        assert_eq!(segments[7], s('2'), "keeps the last eight");

        // No point exists on the rightmost digit.
        let HostMessage::Clock { dots, .. } = HostMessage::clock_text("1.") else {
            panic!("expected a clock message");
        };
        assert_eq!(dots, 0);
    }

    #[test]
    fn meter_and_vpot_ring_layouts() {
        let meter = HostMessage::Meter {
            track: track(4),
            side: 1,
            level: [0x7F, 0x10],
        };
        assert_eq!(
            meter.encode(),
            [0xF0, 0x13, 0x01, 0x10, 36, 0x7F, 0x10, 0xF7]
        );

        let ring = HostMessage::VPotRing {
            track: track(5),
            pattern: [0x7F, 0x01, 0x40],
        };
        assert_eq!(
            ring.encode(),
            [0xF0, 0x13, 0x01, 0x00, 0x45, 0x01, 0x40, 0xF7]
        );
    }

    #[test]
    fn ring_pattern_matches_the_desk_wiring() {
        // Observed with --ring-test: which LED (1 = leftmost) each single
        // pattern bit lit. Bit 0 = byte 1's 0x40, bits 1-7 = byte 2's
        // 0x01-0x40, bits 8-14 = byte 3's 0x01-0x40.
        let observed: [(usize, u8); 15] = [
            (0, 1),
            (1, 8),
            (2, 7),
            (3, 6),
            (4, 5),
            (5, 4),
            (6, 3),
            (7, 2),
            (8, 15),
            (9, 14),
            (10, 13),
            (11, 12),
            (12, 11),
            (13, 10),
            (14, 9),
        ];
        for (bit, led) in observed {
            let mut pattern = [0u8; 3];
            match bit {
                0 => pattern[0] = 0x40,
                1..=7 => pattern[1] = 1 << (bit - 1),
                _ => pattern[2] = 1 << (bit - 8),
            }
            let leds = RingLeds::from_mask(1 << (led - 1));
            assert_eq!(leds.pattern(), pattern, "bit {bit} should light LED {led}");
        }
        assert_eq!(RingLeds::from_mask(0x7FFF).pattern(), [0x40, 0x7F, 0x7F]);
    }

    #[test]
    fn ring_shapes_follow_the_value() {
        assert_eq!(RingLeds::dot(0).mask(), 1);
        assert_eq!(RingLeds::dot(64).mask(), 1 << RingLeds::CENTER);
        assert_eq!(RingLeds::dot(127).mask(), 1 << 14);
        assert_eq!(RingLeds::fill(0).mask(), 1);
        assert_eq!(RingLeds::fill(127).mask(), 0x7FFF);
        assert_eq!(RingLeds::spread(64).mask(), 1 << 7);
        assert_eq!(RingLeds::spread(127).mask(), 0x7F80);
        assert_eq!(RingLeds::spread(0).mask(), 0x00FF);
        assert_eq!(
            HostMessage::ring(track(0), RingLeds::dot(64)).encode(),
            [0xF0, 0x13, 0x01, 0x00, 0x00, 0x01, 0x00, 0xF7]
        );
    }

    #[test]
    fn meter_bits_match_the_desk_scale() {
        // Observed with --meter-test: single bits and the dB mark they lit.
        let observed: [([u8; 2], i8); 8] = [
            ([0x08, 0], -6),
            ([0x10, 0], -4),
            ([0x20, 0], -2),
            ([0x40, 0], 0),
            ([0, 0x08], -30),
            ([0, 0x10], -26),
            ([0, 0x20], -22),
            ([0, 0x40], -18),
        ];
        for (level, db) in observed {
            let led = MeterLeds::SCALE_DB.iter().position(|&m| m == db).unwrap();
            assert_eq!(MeterLeds::from_mask(1 << led).level(), level, "{db} dB");
        }
        assert_eq!(MeterLeds::from_db(0.0).level(), [0x7F, 0x7F]);
        assert_eq!(MeterLeds::from_db(-60.0).level(), [0, 0]);
        // -20 dB: everything up to the -22 mark.
        assert_eq!(MeterLeds::from_db(-20.0).mask(), 0b11_1111);
    }

    #[test]
    fn bus_meters_sit_after_the_channels() {
        let bus = |pair, side| {
            HostMessage::BusMeter {
                pair,
                side,
                level: [1, 2],
            }
            .encode()[4]
        };
        // Bus 1, 3, 5 at 24-26 and bus 2, 4, 6 at 56-58, as observed.
        assert_eq!([bus(0, 0), bus(1, 0), bus(2, 0)], [24, 25, 26]);
        assert_eq!([bus(0, 1), bus(1, 1), bus(2, 1)], [56, 57, 58]);
        assert_eq!(bus(9, 0), 26);
    }

    #[test]
    fn every_data_byte_stays_seven_bit() {
        let msgs = [
            HostMessage::Clock {
                dots: 0xFF,
                segments: [0xFF; 8],
            },
            HostMessage::ScribbleStrip {
                track: track(23),
                text: [0xFF; 4],
            },
            HostMessage::Meter {
                track: track(23),
                side: 0xFF,
                level: [0xFF; 2],
            },
            HostMessage::VPotRing {
                track: track(23),
                pattern: [0xFF; 3],
            },
        ];
        for msg in msgs {
            let bytes = msg.encode();
            let inner = &bytes[1..bytes.len() - 1];
            assert!(inner.iter().all(|&b| b < 0x80), "{msg:?} -> {bytes:02x?}");
        }
    }
}
