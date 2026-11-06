//! Optional host → desk exercises: `--demo` and the step-by-step checks of
//! the rings, meters and transport display.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rustbucket::message::{ButtonId, FaderPosition, MeterLeds, RingLeds, Track};
use rustbucket::{DeskMessage, HostMessage};

/// Something that drives the desk while the driver runs.
pub trait Exercise {
    /// The desk has just connected.
    fn on_connect(&mut self, now: Instant) -> Vec<HostMessage>;

    /// A (debounced) message arrived from the desk.
    fn on_message(&mut self, _message: &DeskMessage) -> Vec<HostMessage> {
        Vec::new()
    }

    /// Called on every turn of the driver loop.
    fn tick(&mut self, _now: Instant) -> Vec<HostMessage> {
        Vec::new()
    }

    /// A line was typed in the terminal.
    fn on_line(&mut self, _line: &str) {}

    /// Whether [`Exercise::on_line`] is used.
    fn reads_terminal(&self) -> bool {
        false
    }
}

/// `--demo`: names the scribble strips and centres the rings, writes on the
/// transport display and moves fader 1. Then each button press toggles its
/// LED, and each V-Pot turn shows a value 0–127 on its scribble strip and as
/// a dot on its ring (centre = 64).
#[derive(Debug, Default)]
pub struct Demo {
    leds: HashMap<ButtonId, bool>,
    vpots: HashMap<Track, i16>,
}

impl Exercise for Demo {
    fn on_connect(&mut self, _now: Instant) -> Vec<HostMessage> {
        self.leds.clear();
        self.vpots.clear();
        let mut out: Vec<_> = Track::all()
            .map(|t| HostMessage::scribble(t, &format!("Ch{:02}", t.index() + 1)))
            .collect();
        out.extend(Track::all().map(|t| HostMessage::ring(t, RingLeds::dot(64))));
        out.push(HostMessage::clock_text("CntrL 24"));
        if let (Some(track), Ok(position)) = (Track::all().next(), FaderPosition::try_from(768)) {
            out.push(HostMessage::FaderMove { track, position });
        }
        out
    }

    fn on_message(&mut self, message: &DeskMessage) -> Vec<HostMessage> {
        match *message {
            DeskMessage::Button { id, pressed: true } => {
                let lit = self.leds.entry(id).or_default();
                *lit = !*lit;
                vec![HostMessage::Led { id, on: *lit }]
            }
            DeskMessage::VPot { track, delta } => {
                let value = self.vpots.entry(track).or_insert(64);
                *value = (*value + i16::from(delta)).clamp(0, 127);
                let ring = RingLeds::dot(u8::try_from(*value).unwrap_or(64));
                vec![
                    HostMessage::scribble(track, &format!("V{:>3}", *value)),
                    HostMessage::ring(track, ring),
                ]
            }
            _ => Vec::new(),
        }
    }
}

/// One step of a [`StepTest`]: its label for the scribble strips, and the
/// messages that set the desk to it.
#[derive(Debug)]
struct Step {
    label: String,
    messages: Vec<HostMessage>,
}

/// A check that walks through steps at the user's pace: Enter goes to the
/// next one, `b` + Enter back. The current step is named on every scribble
/// strip and in the terminal.
#[derive(Debug)]
pub struct StepTest {
    name: &'static str,
    steps: Vec<Step>,
    current: usize,
    /// Whether the desk has connected.
    started: bool,
    /// The current step has not been sent yet.
    pending: bool,
    /// Re-send the current step this often, if set.
    refresh: Option<Duration>,
    next_refresh: Option<Instant>,
}

impl StepTest {
    fn new(name: &'static str, steps: Vec<Step>) -> Self {
        Self {
            name,
            steps,
            current: 0,
            started: false,
            pending: false,
            refresh: None,
            next_refresh: None,
        }
    }

    fn go_to(&mut self, step: usize) {
        self.current = step;
        self.pending = true;
        println!(
            "{} {}/{}: {}",
            self.name,
            step + 1,
            self.steps.len(),
            self.steps[step].label
        );
    }
}

impl Exercise for StepTest {
    fn on_connect(&mut self, _now: Instant) -> Vec<HostMessage> {
        self.started = true;
        println!(
            "{}: press Enter for the next step, b + Enter to go back",
            self.name
        );
        self.go_to(0);
        Vec::new()
    }

    fn on_line(&mut self, line: &str) {
        if self.started {
            let n = self.steps.len();
            let back = line.trim().eq_ignore_ascii_case("b");
            self.go_to((self.current + if back { n - 1 } else { 1 }) % n);
        }
    }

    fn reads_terminal(&self) -> bool {
        true
    }

    fn tick(&mut self, now: Instant) -> Vec<HostMessage> {
        let step = &self.steps[self.current];
        let mut out = Vec::new();
        let due = self.next_refresh.is_some_and(|at| now >= at);
        if self.pending {
            out.extend(Track::all().map(|t| HostMessage::scribble(t, &step.label)));
        }
        if self.pending || due {
            self.pending = false;
            self.next_refresh = self.refresh.map(|every| now + every);
            out.extend(step.messages.iter().cloned());
        }
        out
    }
}

/// `--ring-test`: lights each LED of all the V-Pot rings, left to right.
pub fn ring_test() -> StepTest {
    let step = |label: String, mask| Step {
        label,
        messages: Track::all()
            .map(|t| HostMessage::ring(t, RingLeds::from_mask(mask)))
            .collect(),
    };
    let mut steps: Vec<_> = (0..RingLeds::COUNT)
        .map(|led| step(format!("L{:>2}", led + 1), 1 << led))
        .collect();
    steps.push(step("all".into(), 0x7FFF));
    steps.push(step("none".into(), 0));
    StepTest::new("ring test", steps)
}

/// `--meter-test`: lights each LED of the left channel meters, bottom to
/// top, then the right channel meters, then each bus meter.
///
/// Every step sets all the meters and is re-sent four times a second, in
/// case the desk lets meters fall back without updates.
pub fn meter_test() -> StepTest {
    let full = MeterLeds::from_mask(0x3FFF);
    let off = MeterLeds::default();
    let mut steps: Vec<_> = MeterLeds::SCALE_DB
        .iter()
        .enumerate()
        .map(|(led, db)| Step {
            label: format!("{db:>4}"),
            messages: meters(MeterLeds::from_mask(1 << led), off, None),
        })
        .collect();
    steps.push(Step {
        label: "rght".into(),
        messages: meters(off, full, None),
    });
    steps.extend((0..6).map(|bus| Step {
        label: format!("bus{}", bus + 1),
        messages: meters(off, off, Some(bus)),
    }));
    steps.push(Step {
        label: "off".into(),
        messages: meters(off, off, None),
    });
    let mut test = StepTest::new("meter test", steps);
    test.refresh = Some(Duration::from_millis(250));
    test
}

/// Sets every meter: the channels to `left` and `right`, and the bus with
/// index `lit_bus` (0–5) to full, the other buses to nothing.
fn meters(left: MeterLeds, right: MeterLeds, lit_bus: Option<u8>) -> Vec<HostMessage> {
    let mut out = Vec::new();
    for track in Track::all() {
        for (side, leds) in [(0, left), (1, right)] {
            let level = leds.level();
            out.push(HostMessage::Meter { track, side, level });
        }
    }
    for bus in 0..6 {
        let leds = if lit_bus == Some(bus) {
            MeterLeds::from_mask(0x3FFF)
        } else {
            MeterLeds::default()
        };
        out.push(HostMessage::BusMeter {
            pair: bus / 2,
            side: bus % 2,
            level: leds.level(),
        });
    }
    out
}

/// `--clock-test`: lights each digit of the transport display, right to
/// left, then each segment and decimal point, then a sample text.
pub fn clock_test() -> StepTest {
    let step = |label: String, dots, segments| Step {
        label,
        messages: vec![HostMessage::Clock { dots, segments }],
    };
    let mut steps = vec![step("blnk".into(), 0, [0; 8])];
    for digit in 0..8 {
        let mut segments = [0; 8];
        segments[digit] = 0x7F;
        steps.push(step(format!("dg {}", digit + 1), 0, segments));
    }
    for (bit, name) in ['g', 'f', 'e', 'd', 'c', 'b', 'a'].iter().enumerate() {
        steps.push(step(format!("sg {name}"), 0, [1 << bit; 8]));
    }
    for bit in 0..7 {
        // Bit 0 is the point of digit 8, the leftmost.
        steps.push(step(format!("dot{}", 8 - bit), 1 << bit, [0; 8]));
    }
    steps.push(Step {
        label: "text".into(),
        messages: vec![HostMessage::clock_text("12.34.56.78")],
    });
    StepTest::new("clock test", steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbucket::parse_messages;

    #[test]
    fn demo_names_strips_and_toggles_leds() {
        let mut demo = Demo::default();
        let track = |i| Track::try_from(i).unwrap();
        let out = demo.on_connect(Instant::now());
        assert_eq!(out.len(), 2 * Track::all().count() + 2);
        assert_eq!(out[0], HostMessage::scribble(track(0), "Ch01"));

        let id = ButtonId([0x18, 0x00]);
        let press = DeskMessage::Button { id, pressed: true };
        let release = DeskMessage::Button { id, pressed: false };
        let led = |on| vec![HostMessage::Led { id, on }];
        assert_eq!(demo.on_message(&press), led(true));
        assert_eq!(demo.on_message(&release), []);
        assert_eq!(demo.on_message(&press), led(false));

        // Recorded V-Pot message: B0 42 45 is V-Pot 3, +5.
        let turn = parse_messages(&[0xB0, 0x42, 0x45]).next().unwrap().unwrap();
        assert_eq!(
            demo.on_message(&turn),
            [
                HostMessage::scribble(track(2), "V 69"),
                HostMessage::ring(track(2), RingLeds::dot(69)),
            ]
        );
    }

    #[test]
    fn step_test_moves_on_enter_and_sends_once() {
        let mut test = clock_test();
        let t0 = Instant::now();
        test.on_line("");
        assert_eq!(test.current, 0, "ignores input until the desk is found");
        assert_eq!(test.tick(t0), []);

        test.on_connect(t0);
        let strips = Track::all().count();
        assert_eq!(test.tick(t0).len(), strips + 1);
        assert_eq!(test.tick(t0), [], "sent once per step");

        test.on_line("");
        let out = test.tick(t0);
        let HostMessage::Clock { segments, .. } = out[strips] else {
            panic!("expected the clock message after the labels");
        };
        assert_eq!(segments, [0x7F, 0, 0, 0, 0, 0, 0, 0]);

        test.on_line("b");
        test.on_line("B");
        assert_eq!(test.current, test.steps.len() - 1, "back wraps around");
    }

    #[test]
    fn meter_test_refreshes_its_step() {
        let mut test = meter_test();
        let t0 = Instant::now();
        test.on_connect(t0);
        let every_meter = 2 * Track::all().count() + 6;
        assert_eq!(test.tick(t0).len(), Track::all().count() + every_meter);
        assert_eq!(test.tick(t0), []);
        let later = test.tick(t0 + Duration::from_millis(250));
        assert_eq!(later.len(), every_meter, "levels only, no labels");
    }

    #[test]
    fn labels_fit_the_scribble_strips() {
        for test in [ring_test(), meter_test(), clock_test()] {
            assert!(test.steps.iter().all(|s| s.label.len() <= 4));
        }
    }

    #[test]
    fn meter_test_reaches_each_bus_once() {
        let test = meter_test();
        let step = test.steps.iter().find(|s| s.label == "bus4").unwrap();
        let lit: Vec<_> = step
            .messages
            .iter()
            .filter(|m| m.encode()[5..7] != [0, 0])
            .collect();
        // Bus 4 is pair 1, side 1: address 32 + 24 + 1.
        assert_eq!(lit.len(), 1);
        assert_eq!(lit[0].encode()[4], 57);
    }
}
