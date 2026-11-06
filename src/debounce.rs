//! Filters contact bounce from button messages (PROTOCOL.md §5.3).
//!
//! The recorded desk often reports a single press as press, release, press,
//! release, with the bounce release→press gap under 50 ms (worn switches);
//! deliberate presses were at least 100 ms apart. A press that follows the
//! release of the same button within [`Debouncer::DEFAULT_WINDOW`] is
//! dropped, and so is any message that does not change the button's state.
//! The surviving release is the first one, so it may come a few
//! milliseconds early; no timer is needed.

use std::collections::HashMap;
use std::time::Duration;

use crate::message::ButtonId;

/// Per-button bounce filter.
#[derive(Debug, Clone)]
pub struct Debouncer {
    window: Duration,
    /// Last accepted state of each button, and when its last release arrived.
    buttons: HashMap<ButtonId, (bool, Option<Duration>)>,
}

impl Default for Debouncer {
    fn default() -> Self {
        Self::new(Self::DEFAULT_WINDOW)
    }
}

impl Debouncer {
    /// Bounces in the recordings ended within 47 ms.
    pub const DEFAULT_WINDOW: Duration = Duration::from_millis(60);

    /// Filter that drops re-presses within `window` of a release.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            buttons: HashMap::new(),
        }
    }

    /// Whether a button message received at `at` (any monotonic clock)
    /// should be passed on.
    pub fn accept(&mut self, id: ButtonId, pressed: bool, at: Duration) -> bool {
        let (state, released_at) = self.buttons.entry(id).or_insert((false, None));
        if pressed {
            let bounce = released_at.is_some_and(|r| at.saturating_sub(r) < self.window);
            // The bounce's own release then finds the state already released
            // and is dropped as well.
            if bounce || *state {
                return false;
            }
            *state = true;
            true
        } else {
            *released_at = Some(at);
            let changed = *state;
            *state = false;
            changed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: ButtonId = ButtonId([0x05, 0x01]);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn swallows_a_recorded_bounce() {
        // Times from a recording, button 05 01.
        let mut d = Debouncer::default();
        let events = [(true, 8_975), (false, 8_995), (true, 9_007), (false, 9_207)];
        let passed: Vec<_> = events
            .iter()
            .map(|&(pressed, t)| d.accept(ID, pressed, ms(t)))
            .collect();
        assert_eq!(passed, [true, true, false, false]);
    }

    #[test]
    fn keeps_deliberate_double_presses() {
        let mut d = Debouncer::default();
        assert!(d.accept(ID, true, ms(0)));
        assert!(d.accept(ID, false, ms(150)));
        assert!(d.accept(ID, true, ms(260)));
        assert!(d.accept(ID, false, ms(400)));
    }

    #[test]
    fn buttons_are_independent_and_repeats_are_dropped() {
        let mut d = Debouncer::default();
        let other = ButtonId([0x06, 0x01]);
        assert!(d.accept(ID, true, ms(0)));
        assert!(!d.accept(ID, true, ms(5)), "already pressed");
        assert!(d.accept(other, true, ms(5)));
        assert!(d.accept(other, false, ms(6)));
        assert!(
            !d.accept(ButtonId([0, 0]), false, ms(0)),
            "release without press"
        );
    }
}
