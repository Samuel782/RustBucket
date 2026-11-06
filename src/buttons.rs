//! Names of the desk's buttons (PROTOCOL.md §5.3).
//!
//! A [`ButtonId`] is `[index, group]`: groups `0x00`–`0x17` are the 24
//! channel strips, `0x18`–`0x1D` the centre sections. The table comes from
//! recorded sessions: one section per file, with the buttons pressed in a
//! noted order.
//!
//! The control-room monitor section sends nothing over Ethernet.

use std::fmt;

use crate::message::{ButtonId, TRACKS, Track};

/// Buttons of each channel strip, by index. `0x09` is the fader's touch sensor.
pub const STRIP: [(u8, &str); 11] = [
    (0x00, "Rec Arm"),
    (0x01, "Pan/Send"),
    (0x02, "EQ"),
    (0x03, "Dyn"),
    (0x04, "Switch Active"),
    (0x05, "Auto"),
    (0x06, "Select"),
    (0x07, "Solo"),
    (0x08, "Mute"),
    (0x09, "Fader Touch"),
    (0x0A, "Insert"),
];

/// Centre-section buttons: `(index, group, name)`.
pub const SECTIONS: &[(u8, u8, &str)] = &[
    // 0x18: function keys, meter select, automation, Pro Tools modifiers.
    (0x00, 0x18, "F1"),
    (0x02, 0x18, "F2"),
    (0x04, 0x18, "F3"),
    (0x06, 0x18, "F4"),
    (0x08, 0x18, "F5"),
    (0x32, 0x18, "F6"),
    (0x33, 0x18, "F7"),
    (0x34, 0x18, "F8"),
    (0x35, 0x18, "F9"),
    (0x36, 0x18, "F10"),
    (0x0F, 0x18, "Rec Safe"),
    (0x01, 0x18, "Master Rec"),
    (0x10, 0x18, "Show Values"),
    (0x12, 0x18, "Show Channel Names"),
    (0x16, 0x18, "Vel Sens Encoders"),
    (0x11, 0x18, "Show Group"),
    (0x13, 0x18, "Show Info"),
    (0x27, 0x18, "Auto/Select"),
    (0x28, 0x18, "Pre/Post"),
    (0x0D, 0x18, "Send Mute"),
    (0x2B, 0x18, "Copy Settings From Channel"),
    (0x2C, 0x18, "Specify Settings"),
    (0x2D, 0x18, "Paste Settings To Channel"),
    (0x29, 0x18, "Apply To All Channels"),
    (0x2A, 0x18, "Apply To Selected Channels"),
    (0x07, 0x18, "Default"),
    (0x05, 0x18, "Edit/Byp"),
    (0x03, 0x18, "Ins/Byp"),
    (0x0E, 0x18, "Clear Peaks"),
    (0x09, 0x18, "Meter Channel"),
    (0x0C, 0x18, "Post Fader"),
    (0x0B, 0x18, "Pre Fader"),
    (0x0A, 0x18, "Meter Input"),
    (0x2E, 0x18, "Solo Safe"),
    (0x14, 0x18, "Solo Clear"),
    (0x17, 0x18, "Write"),
    (0x19, 0x18, "Touch"),
    (0x1B, 0x18, "Latch"),
    (0x1D, 0x18, "Trim"),
    (0x1F, 0x18, "Read"),
    (0x21, 0x18, "Off"),
    (0x18, 0x18, "Auto Fader"),
    (0x1A, 0x18, "Auto Pan"),
    (0x1C, 0x18, "Auto Mute"),
    (0x1E, 0x18, "Auto Send Level"),
    (0x20, 0x18, "Auto Send Mute"),
    (0x22, 0x18, "Auto Plug-in"),
    (0x15, 0x18, "Auto Suspend"),
    (0x2F, 0x18, "Write Automation Start"),
    (0x30, 0x18, "Write Automation All"),
    (0x31, 0x18, "Write Automation End"),
    (0x23, 0x18, "Shift/Add"),
    (0x25, 0x18, "Ctrl/Clutch"),
    (0x24, 0x18, "Opt/All"),
    (0x26, 0x18, "Ctrl"),
    // 0x19: windows, zoom presets, navigation, counter.
    (0x00, 0x19, "Mix"),
    (0x01, 0x19, "Edit Window"),
    (0x02, 0x19, "Status"),
    (0x03, 0x19, "Transport Window"),
    (0x04, 0x19, "Pan Window"),
    (0x05, 0x19, "Alt"),
    (0x06, 0x19, "Plug-in Window"),
    (0x07, 0x19, "Mem Loc"),
    (0x08, 0x19, "Zoom Preset 1"),
    (0x09, 0x19, "Zoom Preset 2"),
    (0x0A, 0x19, "Zoom Preset 3"),
    (0x0B, 0x19, "Zoom Preset 4"),
    (0x14, 0x19, "Zoom Preset 5"),
    (0x0C, 0x19, "Nav"),
    (0x0D, 0x19, "Zoom"),
    (0x0E, 0x19, "Sel Adj"),
    (0x0F, 0x19, "Up"),
    (0x10, 0x19, "Previous"),
    (0x11, 0x19, "Next"),
    (0x12, 0x19, "Down"),
    (0x13, 0x19, "Counter Mode"),
    // 0x1A: numeric keypad.
    (0x00, 0x1A, "Keypad 0"),
    (0x01, 0x1A, "Keypad 1"),
    (0x02, 0x1A, "Keypad 2"),
    (0x03, 0x1A, "Keypad 3"),
    (0x04, 0x1A, "Keypad 4"),
    (0x05, 0x1A, "Keypad 5"),
    (0x06, 0x1A, "Keypad 6"),
    (0x07, 0x1A, "Keypad 7"),
    (0x08, 0x1A, "Keypad 8"),
    (0x09, 0x1A, "Keypad 9"),
    (0x0A, 0x1A, "Keypad Clr"),
    (0x0B, 0x1A, "Keypad ="),
    (0x0C, 0x1A, "Keypad /"),
    (0x0D, 0x1A, "Keypad *"),
    (0x0E, 0x1A, "Keypad -"),
    (0x0F, 0x1A, "Keypad +"),
    (0x10, 0x1A, "Keypad ."),
    (0x11, 0x1A, "Keypad Enter"),
    // 0x1B: edit modes, edit functions, edit tools, groups, banks.
    (0x00, 0x1B, "Shuffle"),
    (0x01, 0x1B, "Slip"),
    (0x02, 0x1B, "Spot"),
    (0x03, 0x1B, "Grid"),
    (0x04, 0x1B, "Cut"),
    (0x05, 0x1B, "Copy"),
    (0x06, 0x1B, "Paste"),
    (0x07, 0x1B, "Delete"),
    (0x08, 0x1B, "Separate"),
    (0x09, 0x1B, "Capture"),
    (0x1C, 0x1B, "Duplicate"),
    (0x1D, 0x1B, "Repeat"),
    (0x0A, 0x1B, "Bank Left"),
    (0x0B, 0x1B, "Nudge"),
    (0x0C, 0x1B, "Bank Right"),
    (0x0D, 0x1B, "Trim Tool"),
    (0x0E, 0x1B, "Select Tool"),
    (0x0F, 0x1B, "Grab Tool"),
    (0x10, 0x1B, "Pencil Tool"),
    (0x11, 0x1B, "MIDI Tools"),
    (0x12, 0x1B, "Smart Quantize"),
    (0x1E, 0x1B, "Link Edit/TL"),
    (0x1F, 0x1B, "Auto To Cur / Event List"),
    (0x20, 0x1B, "Auto To All / All Notes Off"),
    (0x13, 0x1B, "Master Faders"),
    (0x14, 0x1B, "Undo"),
    (0x15, 0x1B, "Safe"),
    (0x21, 0x1B, "Esc/Cancel (Nav)"),
    (0x17, 0x1B, "Group Create"),
    (0x18, 0x1B, "Group Enable"),
    (0x19, 0x1B, "Group Edit"),
    (0x1A, 0x1B, "Group Delete"),
    (0x1B, 0x1B, "Group Suspend"),
    // 0x1C: transport.
    (0x00, 0x1C, "Audition"),
    (0x01, 0x1C, "Pre-roll"),
    (0x02, 0x1C, "In"),
    (0x03, 0x1C, "Out"),
    (0x04, 0x1C, "Post-roll"),
    (0x05, 0x1C, "Go To Start"),
    (0x06, 0x1C, "Go To End"),
    (0x07, 0x1C, "Online"),
    (0x08, 0x1C, "Ext Trans"),
    (0x09, 0x1C, "Loop Play"),
    (0x0A, 0x1C, "Loop Rec"),
    (0x0B, 0x1C, "Quick Punch"),
    (0x0C, 0x1C, "Talkback"),
    (0x0D, 0x1C, "Rewind"),
    (0x0E, 0x1C, "Fast Forward"),
    (0x0F, 0x1C, "Stop"),
    (0x10, 0x1C, "Play"),
    (0x11, 0x1C, "Record"),
    (0x12, 0x1C, "Scrub"),
    (0x13, 0x1C, "Shuttle"),
    // 0x1D: monitor, inserts, assignment, sends, pans, channel bar scroll.
    (0x00, 0x1D, "Monitor"),
    (0x01, 0x1D, "Remote Mic Pre"),
    (0x02, 0x1D, "Compare"),
    (0x03, 0x1D, "Master Bypass"),
    (0x04, 0x1D, "Inserts/Param"),
    (0x09, 0x1D, "Plug-in Safe"),
    (0x05, 0x1D, "Input"),
    (0x06, 0x1D, "Output"),
    (0x07, 0x1D, "Assign"),
    (0x08, 0x1D, "Esc/Cancel"),
    (0x0A, 0x1D, "Flip"),
    (0x0B, 0x1D, "Send A/F"),
    (0x0C, 0x1D, "Send B/G"),
    (0x0D, 0x1D, "Send C/H"),
    (0x0E, 0x1D, "Send D/I"),
    (0x0F, 0x1D, "Send E/J"),
    (0x10, 0x1D, "Pan LCR"),
    (0x11, 0x1D, "Pan Rear"),
    (0x12, 0x1D, "Pan F/R"),
    (0x13, 0x1D, "Pan Center"),
    (0x14, 0x1D, "Channel Bar More <"),
    (0x15, 0x1D, "Channel Bar More >"),
    (0x16, 0x1D, "Pan LFE"),
    (0x17, 0x1D, "Pan L/R"),
];

/// A named button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Button {
    /// The channel strip, for strip buttons.
    pub strip: Option<Track>,
    /// Name as printed on the desk.
    pub name: &'static str,
}

impl fmt::Display for Button {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.strip {
            Some(track) => write!(f, "Ch{} {}", track.index() + 1, self.name),
            None => f.write_str(self.name),
        }
    }
}

/// The button with this ID, if known.
#[must_use]
pub fn lookup(id: ButtonId) -> Option<Button> {
    let ButtonId([index, group]) = id;
    if group < TRACKS {
        let strip = Track::try_from(group).ok();
        return STRIP
            .iter()
            .find(|&&(i, _)| i == index)
            .map(|&(_, name)| Button { strip, name });
    }
    SECTIONS
        .iter()
        .find(|&&(i, g, _)| i == index && g == group)
        .map(|&(_, _, name)| Button { strip: None, name })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_and_names_are_unique() {
        let ids: HashSet<_> = SECTIONS.iter().map(|&(i, g, _)| (i, g)).collect();
        assert_eq!(ids.len(), SECTIONS.len());
        let names: HashSet<_> = SECTIONS.iter().map(|&(_, _, n)| n).collect();
        assert_eq!(names.len(), SECTIONS.len());
        assert!(SECTIONS.iter().all(|&(_, g, _)| (0x18..=0x1D).contains(&g)));
    }

    #[test]
    fn names_strip_and_section_buttons() {
        let mute_2 = lookup(ButtonId([0x08, 0x01])).unwrap();
        assert_eq!(mute_2.to_string(), "Ch2 Mute");
        assert_eq!(lookup(ButtonId([0x10, 0x1C])).unwrap().to_string(), "Play");
        assert_eq!(lookup(ButtonId([0x7F, 0x1C])), None);
    }

    #[test]
    fn keypad_digits_match_their_index() {
        // The recording gives an independent check: digit n has index n.
        for n in 0..10u8 {
            let button = lookup(ButtonId([n, 0x1A])).unwrap();
            assert_eq!(button.name, format!("Keypad {n}"));
        }
    }
}
