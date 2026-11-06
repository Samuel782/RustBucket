//! Independent driver for the Digidesign Control|24 control surface.
//!
//! Written from the abstract specification in `PROTOCOL.md`; section
//! references (e.g. "PROTOCOL.md §2") point at the field definitions there.
//!
//! Layers, bottom up:
//! - [`frame`], [`header`], [`announce`]: Ethernet frames and the C24 header (§1–§4.1);
//! - [`message`]: payload messages in both directions (§5);
//! - [`session`]: handshake, ACK window, retries and keepalive, without I/O (§4);
//! - [`driver`]: runs a session over any raw Ethernet [`driver::Link`].
//!
//! Tools for working with real hardware:
//! - [`pcap`]: records a live session and reads captures back;
//! - [`analysis`]: checks a capture against the specification;
//! - [`buttons`]: names of the buttons, from the recorded sessions;
//! - [`debounce`]: removes contact bounce from button messages.

pub mod analysis;
pub mod announce;
pub mod buttons;
pub mod debounce;
pub mod driver;
pub mod error;
pub mod frame;
pub mod header;
pub mod mac;
pub mod message;
pub mod pcap;
pub mod session;

pub use announce::Announce;
pub use error::ParseError;
pub use frame::Frame;
pub use header::{Command, Header};
pub use mac::MacAddress;
pub use message::{DeskMessage, HostMessage, parse_messages};
pub use session::{Config, Event, Output, Session, State};

/// `EtherType` used by the desk (PROTOCOL.md §1).
pub const ETHERTYPE: u16 = 0x885F;
