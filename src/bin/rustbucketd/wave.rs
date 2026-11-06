//! `--wave-test`: one sine wave runs across the 24 strips and drives every
//! output at once, so faders, V-Pot rings, meters and Select LEDs move
//! together.

use std::f32::consts::TAU;
use std::time::{Duration, Instant};

use rustbucket::HostMessage;
use rustbucket::message::{ButtonId, FaderPosition, MeterLeds, RingLeds, TRACKS, Track};

use crate::exercises::Exercise;

/// Lights are refreshed 20 times a second.
const FRAME: Duration = Duration::from_millis(50);
/// Faders get every second frame, so the motors are not flooded.
const FADER_EVERY: u32 = 2;
/// Seconds for one wave to travel across the desk.
const PERIOD: f32 = 4.0;
/// Fader travel used by the wave, leaving room at both ends.
const FADER_LOW: f32 = 80.0;
const FADER_HIGH: f32 = 940.0;
/// Select button of each strip, lit at the crest of the wave.
const SELECT: u8 = 0x06;

#[derive(Debug, Default)]
pub struct WaveTest {
    start: Option<Instant>,
    next: Option<Instant>,
    frame: u32,
    /// What each strip's ring and LED last showed: both stay lit by
    /// themselves, so they are only sent when they change.
    shown: [Option<(RingLeds, bool)>; TRACKS as usize],
}

impl Exercise for WaveTest {
    fn on_connect(&mut self, now: Instant) -> Vec<HostMessage> {
        *self = Self {
            start: Some(now),
            next: Some(now),
            ..Self::default()
        };
        println!("wave test: running; stop with Ctrl+C");
        Vec::new()
    }

    fn tick(&mut self, now: Instant) -> Vec<HostMessage> {
        let Some(start) = self.start else {
            return Vec::new();
        };
        if self.next.is_some_and(|due| now < due) {
            return Vec::new();
        }
        self.next = Some(now + FRAME);
        let with_faders = self.frame.is_multiple_of(FADER_EVERY);
        self.frame = self.frame.wrapping_add(1);

        let t = now.duration_since(start).as_secs_f32();
        let mut out = Vec::new();
        for track in Track::all() {
            let height = height(t, track.index());
            if with_faders {
                out.push(HostMessage::FaderMove {
                    track,
                    position: fader(height),
                });
            }
            let level = MeterLeds::from_db(-50.0 + 50.0 * height).level();
            for side in 0..2 {
                out.push(HostMessage::Meter { track, side, level });
            }

            let ring = RingLeds::fill(to_7bit(height));
            let lit = height > 0.85;
            let shown = &mut self.shown[usize::from(track.index())];
            let previous = shown.replace((ring, lit));
            if previous.map(|(r, _)| r) != Some(ring) {
                out.push(HostMessage::ring(track, ring));
            }
            if previous.map(|(_, l)| l) != Some(lit) {
                out.push(HostMessage::Led {
                    id: ButtonId([SELECT, track.index()]),
                    on: lit,
                });
            }
        }
        out
    }
}

/// Wave height 0.0–1.0 for strip `index` at time `t`: strips further right
/// lag behind, so the crest travels left to right.
fn height(t: f32, index: u8) -> f32 {
    let phase = t / PERIOD - f32::from(index) / f32::from(TRACKS);
    0.5 + 0.5 * (TAU * phase).sin()
}

fn to_7bit(height: f32) -> u8 {
    // Clamped to 0–127 first, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let value = (height.clamp(0.0, 1.0) * 127.0).round() as u8;
    value
}

fn fader(height: f32) -> FaderPosition {
    let span = FADER_HIGH - FADER_LOW;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let value = (FADER_LOW + span * height.clamp(0.0, 1.0)).round() as u16;
    FaderPosition::try_from(value).unwrap_or(FaderPosition::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crest_travels_left_to_right() {
        // At t = 1 s (a quarter period) strip 0 is at the crest.
        assert!((height(1.0, 0) - 1.0).abs() < 1e-4);
        // A quarter of the desk later (6 strips) the crest arrives at strip 6.
        assert!((height(2.0, 6) - 1.0).abs() < 1e-4);
        assert!(height(1.0, 12) < 0.01, "half a desk away is the trough");
    }

    #[test]
    fn sends_faders_every_other_frame_and_lights_only_when_they_change() {
        let mut wave = WaveTest::default();
        let t0 = Instant::now();
        assert_eq!(wave.tick(t0), [], "idle until the desk is found");
        wave.on_connect(t0);

        let is_fader = |m: &&HostMessage| matches!(m, HostMessage::FaderMove { .. });
        let is_meter = |m: &&HostMessage| matches!(m, HostMessage::Meter { .. });
        let strips = usize::from(TRACKS);

        // First frame: everything, for every strip.
        let first = wave.tick(t0);
        assert_eq!(first.len(), strips * 5);
        assert_eq!(wave.tick(t0), [], "one frame per period");

        // Second frame: no faders, meters always, few rings, few LEDs.
        let second = wave.tick(t0 + FRAME);
        assert_eq!(second.iter().filter(is_fader).count(), 0);
        assert_eq!(second.iter().filter(is_meter).count(), 2 * strips);
        assert!(second.len() < first.len() - strips);

        let positions: Vec<u16> = first
            .iter()
            .filter_map(|m| match m {
                HostMessage::FaderMove { position, .. } => Some(position.value()),
                _ => None,
            })
            .collect();
        assert!(positions.iter().all(|&p| (80..=940).contains(&p)));
        assert!(
            positions.windows(2).any(|w| w[0] != w[1]),
            "faders differ along the wave"
        );
    }
}
