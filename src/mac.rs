//! Ethernet MAC addresses.

use std::fmt;

/// A 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// `FF:FF:FF:FF:FF:FF`, used by the desk's announcement (PROTOCOL.md §4.1).
    pub const BROADCAST: Self = Self([0xFF; 6]);

    /// Digidesign OUI carried by the desk's own address (PROTOCOL.md §1).
    pub const DIGIDESIGN_OUI: [u8; 3] = [0x00, 0xA0, 0x7E];

    /// True for the all-ones broadcast address.
    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self == Self::BROADCAST
    }

    /// True when the first three bytes match the Digidesign OUI.
    #[must_use]
    pub fn is_digidesign(self) -> bool {
        self.0[..3] == Self::DIGIDESIGN_OUI
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: Vec<String> = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        f.write_str(&text.join(":"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        let desk = MacAddress([0x00, 0xA0, 0x7E, 0x12, 0x34, 0x56]);
        assert!(desk.is_digidesign());
        assert!(!desk.is_broadcast());
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert_eq!(desk.to_string(), "00:a0:7e:12:34:56");
    }
}
