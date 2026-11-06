//! Connects a [`Session`] to a raw Ethernet link.
//!
//! The link is a trait so the driver loop can be tested with a simulated
//! desk; the binary `rustbucketd` provides the real implementation.

use std::io;
use std::time::Instant;

use crate::{Config, Event, Frame, HostMessage, MacAddress, Output, Session, State};

/// Shortest Ethernet frame without the FCS; shorter frames are zero-padded
/// before sending (PROTOCOL.md §1).
pub const MIN_ETHERNET_FRAME: usize = 60;

/// A raw Ethernet interface.
pub trait Link {
    /// Waits briefly for one frame. `Ok(None)` means nothing arrived before
    /// the link's own read timeout.
    ///
    /// # Errors
    /// Any I/O failure of the interface.
    fn recv(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Sends one complete Ethernet frame.
    ///
    /// # Errors
    /// Any I/O failure of the interface.
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
}

impl<L: Link + ?Sized> Link for Box<L> {
    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        (**self).recv()
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        (**self).send(frame)
    }
}

/// Runs a [`Session`] over a [`Link`].
#[derive(Debug)]
pub struct Driver<L> {
    link: L,
    session: Session,
}

impl<L: Link> Driver<L> {
    /// Driver for the interface whose own MAC address is `host`.
    pub fn new(link: L, host: MacAddress, config: Config) -> Self {
        Self {
            link,
            session: Session::new(host, config),
        }
    }

    /// Current connection state.
    #[must_use]
    pub fn state(&self) -> State {
        self.session.state()
    }

    /// Ends the driver and returns its link.
    pub fn into_link(self) -> L {
        self.link
    }

    /// Messages waiting to be sent; see [`Session::queued`].
    #[must_use]
    pub fn queued(&self) -> usize {
        self.session.queued()
    }

    /// Queues messages for the desk; they go out on a later [`Driver::poll`].
    pub fn queue(&mut self, messages: &[HostMessage], now: Instant) {
        self.session.queue(messages, now);
    }

    /// One step of the loop: receive at most one frame, run due timers,
    /// transmit what the session produced, and return its events.
    ///
    /// Frames that are not Control|24 frames are skipped silently.
    ///
    /// # Errors
    /// I/O failures from the link. The session state stays consistent, so
    /// the caller may keep polling.
    pub fn poll(&mut self, now: Instant) -> io::Result<Vec<Event>> {
        if let Some(bytes) = self.link.recv()?
            && let Ok(frame) = Frame::parse(&bytes)
        {
            self.session.handle_frame(&frame, now);
        }
        if self.session.next_timeout().is_some_and(|due| now >= due) {
            self.session.handle_timeout(now);
        }

        let mut events = Vec::new();
        while let Some(output) = self.session.poll_output() {
            match output {
                Output::Transmit(frame) => self.link.send(&padded(&frame))?,
                Output::Event(event) => events.push(event),
            }
        }
        Ok(events)
    }
}

/// Wire bytes of `frame`, zero-padded to the Ethernet minimum.
fn padded(frame: &Frame) -> Vec<u8> {
    let mut bytes = frame.to_bytes();
    if bytes.len() < MIN_ETHERNET_FRAME {
        bytes.resize(MIN_ETHERNET_FRAME, 0);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;
    use crate::header::{Command, Header};
    use crate::message::{DeskMessage, FaderPosition, Track, parse_messages};

    const DESK: MacAddress = MacAddress([0x00, 0xA0, 0x7E, 1, 2, 3]);
    const HOST: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    /// Link that replays scripted frames and records what was sent.
    #[derive(Debug, Default)]
    struct FakeLink {
        incoming: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Link for FakeLink {
        fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.incoming.pop_front())
        }

        fn send(&mut self, frame: &[u8]) -> io::Result<()> {
            self.sent.push(frame.to_vec());
            Ok(())
        }
    }

    impl FakeLink {
        fn desk_sends(&mut self, frame: &Frame) {
            self.incoming.push_back(frame.to_bytes());
        }

        fn take_sent(&mut self) -> Vec<Frame> {
            self.sent
                .drain(..)
                .map(|b| Frame::parse(&b).expect("driver sent an invalid frame"))
                .collect()
        }
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

    fn desk_data(send_counter: u32, payload: &[u8]) -> Frame {
        let mut header = Header::new(Command::Data, 1);
        header.send_counter = send_counter;
        Frame::new(HOST, DESK, header, payload.to_vec())
    }

    #[test]
    fn full_exchange_with_a_simulated_desk() {
        let t0 = Instant::now();
        let mut driver = Driver::new(FakeLink::default(), HOST, Config::default());

        // Nothing on the wire yet.
        assert_eq!(driver.poll(t0).unwrap(), []);

        // Desk announces: handshake goes out, padded to the Ethernet minimum.
        driver.link.desk_sends(&announce());
        let events = driver.poll(t0).unwrap();
        assert!(matches!(events[..], [Event::DeskFound { desk: DESK, .. }]));
        assert!(
            driver
                .link
                .sent
                .iter()
                .all(|f| f.len() >= MIN_ETHERNET_FRAME)
        );
        let sent = driver.link.take_sent();
        assert_eq!(sent[0].header.command, Command::Online);
        assert_eq!(sent[1].header.checksum, 0x0244);

        // Desk acknowledges, then moves fader 3.
        driver.link.desk_sends(&Frame::ack(HOST, DESK, 1));
        driver.poll(t0).unwrap();
        driver
            .link
            .desk_sends(&desk_data(1, &[0xB0, 0x03, 0x40, 0x23, 0x50]));
        let events = driver.poll(t0 + Duration::from_millis(1)).unwrap();

        let ack = driver.link.take_sent();
        assert_eq!(ack[0].header.command, Command::Ack);
        assert_eq!(ack[0].header.ack_counter, 1);

        let [Event::Messages { payload, .. }] = &events[..] else {
            panic!("expected one Messages event, got {events:?}");
        };
        let messages: Vec<_> = parse_messages(payload).collect();
        assert_eq!(
            messages,
            [Ok(DeskMessage::Fader {
                track: Track::try_from(3).unwrap(),
                position: FaderPosition::try_from(517).unwrap(),
            })]
        );

        // Host writes a scribble strip.
        let track = Track::try_from(3).unwrap();
        driver.queue(
            &[HostMessage::scribble(track, "Vox")],
            t0 + Duration::from_millis(2),
        );
        driver.poll(t0 + Duration::from_millis(2)).unwrap();
        let sent = driver.link.take_sent();
        assert_eq!(
            sent[0].payload,
            HostMessage::scribble(track, "Vox").encode()
        );
    }

    #[test]
    fn ignores_foreign_traffic() {
        let t0 = Instant::now();
        let mut link = FakeLink::default();
        let mut ipv4 = announce().to_bytes();
        ipv4[12..14].copy_from_slice(&[0x08, 0x00]);
        link.incoming.push_back(ipv4);
        link.incoming.push_back(vec![1, 2, 3]);

        let mut driver = Driver::new(link, HOST, Config::default());
        assert_eq!(driver.poll(t0).unwrap(), []);
        assert_eq!(driver.poll(t0).unwrap(), []);
        assert_eq!(driver.state(), State::Discovering);
        assert_eq!(driver.link.sent, Vec::<Vec<u8>>::new());
    }

    #[test]
    fn link_errors_propagate() {
        struct Broken;
        impl Link for Broken {
            fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
                Err(io::Error::other("cable unplugged"))
            }
            fn send(&mut self, _: &[u8]) -> io::Result<()> {
                Ok(())
            }
        }
        let mut driver = Driver::new(Broken, HOST, Config::default());
        assert!(driver.poll(Instant::now()).is_err());
    }
}
