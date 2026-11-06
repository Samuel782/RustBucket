//! Messages sent by the desk (PROTOCOL.md §5).

use std::fmt;

use super::{ButtonId, FaderPosition, MessageError, Track, hex};
use crate::buttons;

/// Automation-mode LED reported by the desk (`FF FE xx`, §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomationMode {
    /// `F0`
    Read,
    /// `F1`
    Trim,
    /// `F2`
    Latch,
    /// `F3`
    Touch,
    /// `F4`
    Write,
    /// `F5`
    Off,
    /// Any other value.
    Other(u8),
}

impl From<u8> for AutomationMode {
    fn from(byte: u8) -> Self {
        match byte {
            0xF0 => Self::Read,
            0xF1 => Self::Trim,
            0xF2 => Self::Latch,
            0xF3 => Self::Touch,
            0xF4 => Self::Write,
            0xF5 => Self::Off,
            other => Self::Other(other),
        }
    }
}

/// Counter-mode LED reported by the desk (`FF FF xx`, §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterMode {
    /// `F0`: hours / milliseconds.
    HoursMs,
    /// `F1`: hours / frames.
    HoursFrames,
    /// `F2`: feet / frames.
    FeetFrames,
    /// `F3`: bars / beats.
    BarsBeats,
    /// `F4`
    Off,
    /// Any other value.
    Other(u8),
}

impl From<u8> for CounterMode {
    fn from(byte: u8) -> Self {
        match byte {
            0xF0 => Self::HoursMs,
            0xF1 => Self::HoursFrames,
            0xF2 => Self::FeetFrames,
            0xF3 => Self::BarsBeats,
            0xF4 => Self::Off,
            other => Self::Other(other),
        }
    }
}

/// One decoded message from the desk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeskMessage {
    /// `00`: one-byte keepalive [INF].
    Keepalive,
    /// `B0 t hi 20+t lo`: fader moved (§5.1).
    Fader {
        /// Channel strip.
        track: Track,
        /// New position.
        position: FaderPosition,
    },
    /// `B0 40|t d`: V-Pot turned (§5.2) [OBS].
    VPot {
        /// Channel strip.
        track: Track,
        /// Signed steps: `d - 0x40`; ±1 per detent, larger when turned fast.
        delta: i8,
    },
    /// `B0 40|i d` with `i` ≥ 24: another rotary control. `i` = 28 (`0x5C`)
    /// is the jog/shuttle wheel (§5.2) [OBS].
    Encoder {
        /// Encoder index, `i`.
        index: u8,
        /// Signed steps: `d - 0x40`.
        delta: i8,
    },
    /// `90 a b`: button pressed or released; also fader touch (§5.3).
    Button {
        /// Which button.
        id: ButtonId,
        /// True on press, false on release.
        pressed: bool,
    },
    /// `FF FE xx` (§5.5).
    AutomationMode(AutomationMode),
    /// `FF FF xx` (§5.5).
    CounterMode(CounterMode),
    /// `F0 … F7` system message, kept whole.
    SysEx(Vec<u8>),
    /// Bytes the parser does not understand, kept verbatim. For an unknown
    /// status byte this is the whole rest of the payload, since its length
    /// cannot be known (§5).
    Unknown(Vec<u8>),
}

impl fmt::Display for DeskMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keepalive => f.write_str("keepalive"),
            Self::Fader { track, position } => {
                write!(f, "fader {} {}", track.index() + 1, position.value())
            }
            Self::VPot { track, delta } => write!(f, "V-Pot {} {delta:+}", track.index() + 1),
            Self::Encoder { index: 28, delta } => write!(f, "jog {delta:+}"),
            Self::Encoder { index, delta } => write!(f, "encoder {index} {delta:+}"),
            Self::Button { id, pressed } => {
                let state = if *pressed { "pressed" } else { "released" };
                write!(f, "button {} ", hex(&id.0))?;
                match buttons::lookup(*id) {
                    Some(button) => write!(f, "{button} {state}"),
                    None => write!(f, "? {state}"),
                }
            }
            Self::AutomationMode(mode) => write!(f, "automation mode {mode:?}"),
            Self::CounterMode(mode) => write!(f, "counter mode {mode:?}"),
            Self::SysEx(bytes) => write!(f, "sysex {}", hex(bytes)),
            Self::Unknown(bytes) => write!(f, "unknown {}", hex(bytes)),
        }
    }
}

/// Iterates over the messages in a data-packet payload.
///
/// Stops after the first error or after an [`DeskMessage::Unknown`] tail.
#[must_use]
pub fn parse_messages(payload: &[u8]) -> Messages<'_> {
    Messages { rest: payload }
}

/// Iterator returned by [`parse_messages`].
#[derive(Debug, Clone)]
pub struct Messages<'a> {
    rest: &'a [u8],
}

impl Iterator for Messages<'_> {
    type Item = Result<DeskMessage, MessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let &status = self.rest.first()?;
        let Some(len) = message_len(self.rest) else {
            // Unknown status byte: its length is unknown too, so the rest of the payload goes with it.
            let tail = std::mem::take(&mut self.rest);
            return Some(Ok(DeskMessage::Unknown(tail.to_vec())));
        };
        let len = match len {
            Ok(len) => len,
            Err(e) => {
                self.rest = &[];
                return Some(Err(e));
            }
        };
        let (bytes, rest) = self.rest.split_at(len);
        self.rest = rest;
        debug_assert_eq!(bytes[0], status);
        Some(Ok(decode(bytes)))
    }
}

/// Length of the message at the start of `bytes`: `None` for an unknown
/// status byte, an error when the payload is too short.
fn message_len(bytes: &[u8]) -> Option<Result<usize, MessageError>> {
    let status = bytes[0];
    let needed = match status {
        0x00 => 1,
        0x90 | 0xFF => 3,
        // Encoders set bit 0x40 of the first data byte; it may be missing if truncated.
        0xB0 => match bytes.get(1) {
            Some(b) if b & 0x40 != 0 => 3,
            Some(_) => 5,
            None => 2,
        },
        0xF0 => match bytes.iter().position(|&b| b == 0xF7) {
            Some(end) => end + 1,
            None => bytes.len() + 1,
        },
        _ => return None,
    };
    Some(if bytes.len() >= needed {
        Ok(needed)
    } else {
        Err(MessageError::Truncated {
            status,
            needed,
            got: bytes.len(),
        })
    })
}

/// Decodes one complete message whose length `message_len` has checked.
fn decode(bytes: &[u8]) -> DeskMessage {
    let unknown = || DeskMessage::Unknown(bytes.to_vec());
    match *bytes {
        [0x00] => DeskMessage::Keepalive,
        [0x90, a, b] => DeskMessage::Button {
            id: ButtonId([a, b & !ButtonId::STATE_BIT]),
            pressed: b & ButtonId::STATE_BIT != 0,
        },
        [0xB0, i, d] => {
            let index = i & 0x3F;
            let delta = i8::try_from(i16::from(d) - 0x40).unwrap_or(0);
            match Track::try_from(index) {
                Ok(track) => DeskMessage::VPot { track, delta },
                Err(_) => DeskMessage::Encoder { index, delta },
            }
        }
        [0xB0, t, high, _, low] => match Track::try_from(t & 0x1F) {
            Ok(track) => DeskMessage::Fader {
                track,
                position: FaderPosition::from_wire(high, low),
            },
            Err(_) => unknown(),
        },
        [0xFF, 0xFE, mode] => DeskMessage::AutomationMode(mode.into()),
        [0xFF, 0xFF, mode] => DeskMessage::CounterMode(mode.into()),
        [0xF0, ..] => DeskMessage::SysEx(bytes.to_vec()),
        _ => unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(i: u8) -> Track {
        Track::try_from(i).unwrap()
    }

    fn all(payload: &[u8]) -> Vec<Result<DeskMessage, MessageError>> {
        parse_messages(payload).collect()
    }

    #[test]
    fn parses_a_mixed_payload() {
        let payload = [
            0xB0, 0x03, 0x40, 0x23, 0x50, // fader 3 -> (0x40 << 3) | 5 = 517
            0xB0, 0x45, 0x41, // V-Pot 5, +1
            0x90, 0x18, 0x40, // button pressed
            0x90, 0x18, 0x00, // button released
            0xFF, 0xFE, 0xF3, // automation: touch
            0xFF, 0xFF, 0xF1, // counter: hours/frames
            0x00, // keepalive
        ];
        let id = ButtonId([0x18, 0x00]);
        assert_eq!(
            all(&payload),
            [
                Ok(DeskMessage::Fader {
                    track: track(3),
                    position: FaderPosition::try_from(517).unwrap()
                }),
                Ok(DeskMessage::VPot {
                    track: track(5),
                    delta: 1,
                }),
                Ok(DeskMessage::Button { id, pressed: true }),
                Ok(DeskMessage::Button { id, pressed: false }),
                Ok(DeskMessage::AutomationMode(AutomationMode::Touch)),
                Ok(DeskMessage::CounterMode(CounterMode::HoursFrames)),
                Ok(DeskMessage::Keepalive),
            ]
        );
    }

    #[test]
    fn displays_with_names() {
        let mute = DeskMessage::Button {
            id: ButtonId([0x08, 0x02]),
            pressed: true,
        };
        assert_eq!(mute.to_string(), "button 08 02 Ch3 Mute pressed");
        let jog = DeskMessage::Encoder {
            index: 28,
            delta: -1,
        };
        assert_eq!(jog.to_string(), "jog -1");
    }

    #[test]
    fn vpot_turning_left_is_negative() {
        assert_eq!(
            all(&[0xB0, 0x40, 0x3D]),
            [Ok(DeskMessage::VPot {
                track: track(0),
                delta: -3,
            })]
        );
    }

    #[test]
    fn keeps_sysex_whole_and_continues_after_it() {
        let payload = [0xF0, 0x13, 0x01, 0x40, 0x00, 0x00, 0x41, 0xF7, 0x00];
        assert_eq!(
            all(&payload),
            [
                Ok(DeskMessage::SysEx(payload[..8].to_vec())),
                Ok(DeskMessage::Keepalive)
            ]
        );
    }

    #[test]
    fn unknown_status_swallows_the_rest() {
        assert_eq!(
            all(&[0x00, 0xD0, 0x01, 0x90, 0x18, 0x40]),
            [
                Ok(DeskMessage::Keepalive),
                Ok(DeskMessage::Unknown(vec![0xD0, 0x01, 0x90, 0x18, 0x40])),
            ]
        );
    }

    #[test]
    fn reports_truncation_and_stops() {
        assert_eq!(
            all(&[0x90, 0x18]),
            [Err(MessageError::Truncated {
                status: 0x90,
                needed: 3,
                got: 2
            })]
        );
        assert_eq!(
            all(&[0xB0, 0x02, 0x10]),
            [Err(MessageError::Truncated {
                status: 0xB0,
                needed: 5,
                got: 3
            })]
        );
        assert_eq!(
            all(&[0xB0]),
            [Err(MessageError::Truncated {
                status: 0xB0,
                needed: 2,
                got: 1
            })]
        );
        assert_eq!(
            all(&[0xF0, 0x13, 0x01]),
            [Err(MessageError::Truncated {
                status: 0xF0,
                needed: 4,
                got: 3
            })]
        );
    }

    #[test]
    fn decodes_recorded_v_pot_and_jog_messages() {
        // As recorded from the desk.
        assert_eq!(
            all(&[0xB0, 0x57, 0x3F, 0xB0, 0x5C, 0x42]),
            [
                Ok(DeskMessage::VPot {
                    track: track(23),
                    delta: -1
                }),
                Ok(DeskMessage::Encoder {
                    index: 28,
                    delta: 2
                }),
            ]
        );
    }

    #[test]
    fn unknown_mode_values_are_preserved() {
        assert_eq!(
            all(&[0xFF, 0xFE, 0x99, 0xFF, 0x01, 0x02]),
            [
                Ok(DeskMessage::AutomationMode(AutomationMode::Other(0x99))),
                Ok(DeskMessage::Unknown(vec![0xFF, 0x01, 0x02])),
            ]
        );
    }
}
