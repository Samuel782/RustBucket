//! Session state machine (PROTOCOL.md §4), without I/O.
//!
//! The caller owns the network and the clock:
//! - feed every captured frame to [`Session::handle_frame`];
//! - call [`Session::handle_timeout`] at [`Session::next_timeout`];
//! - queue outgoing messages with [`Session::queue_message`];
//! - drain [`Session::poll_output`] after each call and transmit or handle
//!   what it returns.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::header::{Command, Header};
use crate::{Announce, Frame, HostMessage, MacAddress};

/// Timing and batching limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Idle time before a keepalive is sent (§4.5).
    pub keepalive: Duration,
    /// How long to wait for the desk's ACK before reporting it overdue (§4.3).
    pub ack_overdue: Duration,
    /// Pause in sending after the desk retransmits (§4.4).
    pub retry_backoff: Duration,
    /// Most messages per data packet (§2).
    pub max_messages: u8,
    /// Most payload bytes per data packet (§2: ~314-byte buffer minus 30 bytes of headers).
    pub max_payload: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(10),
            ack_overdue: Duration::from_millis(100),
            retry_backoff: Duration::from_millis(300),
            max_messages: 48,
            max_payload: 284,
        }
    }
}

/// Something the caller has to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send this frame on the wire.
    Transmit(Frame),
    /// Report this to the application.
    Event(Event),
}

/// Session events for the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A desk announced itself and the handshake was sent (§4.1–4.2).
    /// Also raised again when an already-connected desk re-announces, which
    /// is assumed to mean it restarted [INF].
    DeskFound {
        /// The desk's MAC address.
        desk: MacAddress,
        /// Its announcement.
        announce: Announce,
    },
    /// New messages from the desk, decoded with [`crate::parse_messages`].
    Messages {
        /// Concatenated message bytes (§5).
        payload: Vec<u8>,
    },
    /// No ACK for our packet within [`Config::ack_overdue`]. Reported once
    /// per packet; the retransmission policy is still open (§4.3).
    AckOverdue {
        /// `send_counter` of the unacknowledged packet.
        send_counter: u32,
    },
    /// The desk sent a packet type this driver does not handle (§3).
    UnknownPacket {
        /// Raw `command` byte.
        command: u8,
    },
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for a desk announcement.
    Discovering,
    /// Handshake sent; exchanging data with this desk.
    Online {
        /// The desk's MAC address.
        desk: MacAddress,
    },
}

/// A data packet waiting for its ACK (window of one, §4.3).
#[derive(Debug, Clone, Copy)]
struct InFlight {
    send_counter: u32,
    sent_at: Instant,
    overdue_reported: bool,
}

/// Host side of a Control|24 session.
#[derive(Debug)]
pub struct Session {
    host: MacAddress,
    config: Config,
    state: State,
    /// Our counter: advanced by the number of messages in each data packet.
    send_counter: u32,
    /// Last desk `send_counter` delivered to the application, to drop retransmitted duplicates.
    last_delivered: Option<u32>,
    in_flight: Option<InFlight>,
    backoff_until: Option<Instant>,
    last_transmit: Option<Instant>,
    /// Messages waiting to be packed into data packets.
    queue: VecDeque<Vec<u8>>,
    outputs: VecDeque<Output>,
}

impl Session {
    /// New session for the host interface with MAC `host`.
    #[must_use]
    pub fn new(host: MacAddress, config: Config) -> Self {
        Self {
            host,
            config,
            state: State::Discovering,
            send_counter: 0,
            last_delivered: None,
            in_flight: None,
            backoff_until: None,
            last_transmit: None,
            queue: VecDeque::new(),
            outputs: VecDeque::new(),
        }
    }

    /// Current connection state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Next pending output, if any.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// Queues messages for the desk. They are batched into data packets as
    /// the send window allows, so a burst should be queued in one call.
    ///
    /// Messages queued before the desk is online are sent after the handshake.
    pub fn queue(&mut self, messages: &[HostMessage], now: Instant) {
        self.queue.extend(messages.iter().map(HostMessage::encode));
        self.flush(now);
    }

    /// Messages waiting to be sent.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Processes one captured frame. Frames that are not for this host, not
    /// from the connected desk, or with a wrong checksum, are ignored.
    pub fn handle_frame(&mut self, frame: &Frame, now: Instant) {
        if let Some(announce) = Announce::from_frame(frame) {
            self.on_announce(frame, announce, now);
            return;
        }
        let State::Online { desk } = self.state else {
            return;
        };
        if frame.src != desk || frame.dst != self.host {
            return;
        }
        match frame.header.command {
            Command::Ack => self.on_ack(frame.header.ack_counter, now),
            // Not acknowledged, so the desk sends it again (§4.4).
            Command::Data if !frame.checksum_ok() => {}
            Command::Data => self.on_data(frame, now),
            Command::Online | Command::Announce | Command::Beacon => {}
            Command::Unknown(command) => {
                self.emit(Event::UnknownPacket { command });
            }
        }
    }

    /// When [`Session::handle_timeout`] should next be called, if ever.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        let State::Online { .. } = self.state else {
            return None;
        };
        let overdue = self
            .in_flight
            .filter(|f| !f.overdue_reported)
            .map(|f| f.sent_at + self.config.ack_overdue);
        let backoff = self.backoff_until.filter(|_| !self.queue.is_empty());
        let keepalive = match (self.in_flight, self.last_transmit) {
            (None, Some(last)) => Some(last + self.config.keepalive),
            _ => None,
        };
        [overdue, backoff, keepalive].into_iter().flatten().min()
    }

    /// Runs timers that are due at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        let State::Online { .. } = self.state else {
            return;
        };

        if let Some(f) = self.in_flight.as_mut()
            && !f.overdue_reported
            && now >= f.sent_at + self.config.ack_overdue
        {
            f.overdue_reported = true;
            let send_counter = f.send_counter;
            self.emit(Event::AckOverdue { send_counter });
        }
        if self.backoff_until.is_some_and(|until| now >= until) {
            self.backoff_until = None;
        }
        let idle = self
            .last_transmit
            .is_some_and(|last| now >= last + self.config.keepalive);
        if idle && self.in_flight.is_none() && self.queue.is_empty() {
            self.queue.push_back(HostMessage::Keepalive.encode());
        }
        self.flush(now);
    }

    /// Announcement or beacon (§4.1).
    ///
    /// - announcement (`0xE0`): the desk is looking for a host, connect;
    /// - beacon (`0xE1`) naming another host: the desk is bound elsewhere, leave it;
    /// - beacon naming this host while connected: nothing to do;
    /// - beacon naming this host otherwise (e.g. after a restart of this
    ///   program): connect.
    fn on_announce(&mut self, frame: &Frame, announce: Announce, now: Instant) {
        let desk = frame.src;
        if frame.header.command == Command::Beacon
            && (announce.host != Some(self.host) || self.state == (State::Online { desk }))
        {
            return;
        }
        self.connect(desk, announce, now);
    }

    /// (Re)starts the session and sends the handshake (§4.2).
    fn connect(&mut self, desk: MacAddress, announce: Announce, now: Instant) {
        self.state = State::Online { desk };
        self.send_counter = 0;
        self.last_delivered = None;
        self.in_flight = None;
        self.backoff_until = None;
        self.emit(Event::DeskFound { desk, announce });

        self.transmit(Frame::online(desk, self.host), now);
        // The clock reset goes on its own, ahead of anything already queued.
        let clock_reset = HostMessage::Clock {
            dots: 0,
            segments: [0; 8],
        };
        self.send_data(desk, clock_reset.encode(), 1, now);
    }

    /// The desk acknowledged a packet. The window frees only when it is our
    /// packet in flight: the desk also ACKs the `online` packet, with
    /// `ack_counter` 0 (§4.3).
    fn on_ack(&mut self, ack_counter: u32, now: Instant) {
        if self
            .in_flight
            .is_some_and(|f| f.send_counter == ack_counter)
        {
            self.in_flight = None;
            self.flush(now);
        }
    }

    /// Data from the desk: acknowledge it, back off on retries, deliver once (§4.3–4.4).
    fn on_data(&mut self, frame: &Frame, now: Instant) {
        let header = frame.header;
        if header.n_messages == 0 {
            return;
        }
        if header.is_retry() {
            self.backoff_until = Some(now + self.config.retry_backoff);
        }
        let ack = Frame::ack(frame.src, self.host, header.send_counter);
        self.transmit(ack, now);

        // A retransmission of a packet we already delivered only needs the ACK [INF].
        let duplicate = header.is_retry() && self.last_delivered == Some(header.send_counter);
        if !duplicate {
            self.last_delivered = Some(header.send_counter);
            self.emit(Event::Messages {
                payload: frame.payload.clone(),
            });
        }
    }

    /// Sends the next data packet if online, the window is free and no backoff is active.
    fn flush(&mut self, now: Instant) {
        let State::Online { desk } = self.state else {
            return;
        };
        if self.in_flight.is_some() || self.queue.is_empty() {
            return;
        }
        if self.backoff_until.is_some_and(|until| now < until) {
            return;
        }

        let mut payload = Vec::new();
        let mut count: u8 = 0;
        while let Some(message) = self.queue.front() {
            let fits = payload.len() + message.len() <= self.config.max_payload;
            // Always take the first message so an oversized one cannot block the queue.
            if count == self.config.max_messages || (count > 0 && !fits) {
                break;
            }
            payload.extend_from_slice(message);
            self.queue.pop_front();
            count += 1;
        }
        self.send_data(desk, payload, count, now);
    }

    /// Sends one data packet and occupies the send window until its ACK.
    fn send_data(&mut self, desk: MacAddress, payload: Vec<u8>, count: u8, now: Instant) {
        self.send_counter = self.send_counter.wrapping_add(u32::from(count));
        let mut header = Header::new(Command::Data, count);
        header.send_counter = self.send_counter;

        self.in_flight = Some(InFlight {
            send_counter: self.send_counter,
            sent_at: now,
            overdue_reported: false,
        });
        self.transmit(Frame::new(desk, self.host, header, payload), now);
    }

    fn transmit(&mut self, frame: Frame, now: Instant) {
        self.last_transmit = Some(now);
        self.outputs.push_back(Output::Transmit(frame));
    }

    fn emit(&mut self, event: Event) {
        self.outputs.push_back(Output::Event(event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Handshake clock reset (§4.2).
    const CLOCK_RESET: [u8; 15] = [
        0xF0, 0x13, 0x01, 0x30, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF7,
    ];
    const KEEPALIVE: [u8; 1] = [0x00];

    impl Session {
        /// One raw message, sent as soon as the window allows.
        fn queue_message(&mut self, message: Vec<u8>, now: Instant) {
            self.queue.push_back(message);
            self.flush(now);
        }
    }

    const DESK: MacAddress = MacAddress([0x00, 0xA0, 0x7E, 1, 2, 3]);
    const HOST: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn announce_frame() -> Frame {
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

    /// The desk's ACK for whatever packet is in flight.
    fn desk_ack(s: &Session) -> Frame {
        Frame::ack(HOST, DESK, s.in_flight.map_or(0, |f| f.send_counter))
    }

    fn beacon(host: MacAddress) -> Frame {
        let mut frame = announce_frame();
        frame.header.command = Command::Beacon;
        frame.payload[..6].copy_from_slice(&host.0);
        Frame::new(frame.dst, frame.src, frame.header, frame.payload)
    }

    fn desk_data(send_counter: u32, retry: u16, payload: &[u8]) -> Frame {
        let mut header = Header::new(Command::Data, 1);
        header.send_counter = send_counter;
        header.retry = retry;
        Frame::new(HOST, DESK, header, payload.to_vec())
    }

    fn drain(session: &mut Session) -> Vec<Output> {
        std::iter::from_fn(|| session.poll_output()).collect()
    }

    fn transmitted(outputs: &[Output]) -> Vec<&Frame> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::Transmit(f) => Some(f),
                Output::Event(_) => None,
            })
            .collect()
    }

    /// Session that has completed the handshake at time `t0`.
    fn online_session(t0: Instant) -> Session {
        let mut s = Session::new(HOST, Config::default());
        s.handle_frame(&announce_frame(), t0);
        s.handle_frame(&desk_ack(&s), t0);
        drain(&mut s);
        s
    }

    #[test]
    fn handshake_follows_announcement() {
        let t0 = Instant::now();
        let mut s = Session::new(HOST, Config::default());
        assert_eq!(s.state(), State::Discovering);
        assert_eq!(s.next_timeout(), None);

        s.handle_frame(&announce_frame(), t0);
        assert_eq!(s.state(), State::Online { desk: DESK });

        let out = drain(&mut s);
        assert!(matches!(
            &out[0],
            Output::Event(Event::DeskFound { desk, announce }) if *desk == DESK && announce.device == "C24"
        ));
        let sent = transmitted(&out);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].header.command, Command::Online);
        assert_eq!(sent[0].dst, DESK);
        assert_eq!(sent[1].header.command, Command::Data);
        assert_eq!(sent[1].header.checksum, 0x0244);
        assert_eq!(sent[1].header.send_counter, 1);
        assert_eq!(sent[1].payload, CLOCK_RESET);
    }

    #[test]
    fn window_of_one_and_batching() {
        let t0 = Instant::now();
        let mut s = online_session(t0);

        s.queue_message(vec![0x90, 0x01, 0x40], t0);
        s.queue_message(vec![0x90, 0x02, 0x40], t0);
        s.queue_message(vec![0x90, 0x03, 0x40], t0);
        let sent = drain(&mut s);
        let first = transmitted(&sent);
        assert_eq!(
            first.len(),
            1,
            "only the first message goes out before the ACK"
        );
        assert_eq!(first[0].header.n_messages, 1);
        assert_eq!(first[0].header.send_counter, 2);
        assert_eq!(first[0].header.checksum, 0x90 + 0x01 + 0x40);

        s.handle_frame(&desk_ack(&s), t0 + ms(1));
        let out = drain(&mut s);
        let second = transmitted(&out);
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].header.n_messages, 2,
            "waiting messages are batched"
        );
        assert_eq!(
            second[0].header.send_counter, 4,
            "counter advances by message count"
        );
        assert_eq!(second[0].payload, [0x90, 0x02, 0x40, 0x90, 0x03, 0x40]);
    }

    #[test]
    fn batching_respects_limits() {
        let t0 = Instant::now();
        let config = Config {
            max_messages: 2,
            max_payload: 5,
            ..Config::default()
        };
        let mut s = Session::new(HOST, config);
        s.handle_frame(&announce_frame(), t0);
        drain(&mut s);
        for i in 0..4 {
            s.queue_message(vec![i, i], t0);
        }
        s.handle_frame(&desk_ack(&s), t0);
        let out = drain(&mut s);
        let sent = transmitted(&out);
        assert_eq!(sent[0].header.n_messages, 2);
        assert_eq!(sent[0].payload.len(), 4);
    }

    #[test]
    fn acks_desk_data_and_delivers_once() {
        let t0 = Instant::now();
        let mut s = online_session(t0);

        s.handle_frame(&desk_data(9, 0, &[0xB0, 0x00, 0x40, 0x20, 0x00]), t0);
        let out = drain(&mut s);
        let ack = transmitted(&out)[0];
        assert_eq!(ack.header.command, Command::Ack);
        assert_eq!(ack.header.ack_counter, 9);
        assert!(out.contains(&Output::Event(Event::Messages {
            payload: vec![0xB0, 0x00, 0x40, 0x20, 0x00],
        })));

        // Retransmission of the same packet: ACK again, but no second delivery.
        s.handle_frame(
            &desk_data(9, 1, &[0xB0, 0x00, 0x40, 0x20, 0x00]),
            t0 + ms(5),
        );
        let out = drain(&mut s);
        assert_eq!(transmitted(&out).len(), 1);
        assert!(
            !out.iter()
                .any(|o| matches!(o, Output::Event(Event::Messages { .. })))
        );
    }

    #[test]
    fn desk_retry_pauses_sending() {
        let t0 = Instant::now();
        let mut s = online_session(t0);

        s.handle_frame(&desk_data(3, 1, &[0x90, 0x00, 0x40]), t0);
        drain(&mut s);
        s.queue_message(vec![0x90, 0x05, 0x40], t0 + ms(10));
        assert!(
            transmitted(&drain(&mut s)).is_empty(),
            "held during backoff"
        );

        assert_eq!(s.next_timeout(), Some(t0 + ms(300)));
        s.handle_timeout(t0 + ms(300));
        let out = drain(&mut s);
        let sent = transmitted(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, [0x90, 0x05, 0x40]);
    }

    #[test]
    fn reports_overdue_ack_once() {
        let t0 = Instant::now();
        let mut s = online_session(t0);
        s.queue_message(vec![0x90, 0x01, 0x40], t0);
        drain(&mut s);

        assert_eq!(s.next_timeout(), Some(t0 + ms(100)));
        s.handle_timeout(t0 + ms(100));
        assert_eq!(
            drain(&mut s),
            [Output::Event(Event::AckOverdue { send_counter: 2 })]
        );
        s.handle_timeout(t0 + ms(200));
        assert_eq!(drain(&mut s), []);
    }

    #[test]
    fn sends_keepalive_when_idle() {
        let t0 = Instant::now();
        let mut s = online_session(t0);

        let due = s.next_timeout().unwrap();
        assert_eq!(due, t0 + Duration::from_secs(10));
        s.handle_timeout(t0 + ms(9_999));
        assert_eq!(drain(&mut s), [], "not idle long enough yet");

        s.handle_timeout(due);
        let out = drain(&mut s);
        let sent = transmitted(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, KEEPALIVE);
        assert_eq!(sent[0].header.n_messages, 1);
    }

    #[test]
    fn ignores_foreign_frames_and_reports_unknown_packets() {
        let t0 = Instant::now();
        let mut s = online_session(t0);

        let stranger = MacAddress([0x00, 0xA0, 0x7E, 9, 9, 9]);
        let mut other = desk_data(1, 0, &[0x90, 0x00, 0x40]);
        other.src = stranger;
        s.handle_frame(&other, t0);
        assert_eq!(drain(&mut s), []);

        let e3 = Frame::new(
            HOST,
            DESK,
            Header::new(Command::Unknown(0x42), 0),
            Vec::new(),
        );
        s.handle_frame(&e3, t0);
        assert_eq!(
            drain(&mut s),
            [Output::Event(Event::UnknownPacket { command: 0x42 })]
        );
    }

    #[test]
    fn reannouncement_restarts_the_session() {
        let t0 = Instant::now();
        let mut s = online_session(t0);
        s.queue_message(vec![0x90, 0x01, 0x40], t0);
        drain(&mut s);

        s.handle_frame(&announce_frame(), t0 + ms(50));
        let out = drain(&mut s);
        let sent = transmitted(&out);
        assert_eq!(sent[0].header.command, Command::Online);
        assert_eq!(
            sent[1].header.send_counter, 1,
            "counters restart with the handshake"
        );
    }

    #[test]
    fn messages_queued_before_connection_follow_the_handshake() {
        let t0 = Instant::now();
        let mut s = Session::new(HOST, Config::default());
        s.queue_message(vec![0x90, 0x07, 0x40], t0);
        assert_eq!(drain(&mut s), []);

        s.handle_frame(&announce_frame(), t0);
        drain(&mut s);
        s.handle_frame(&desk_ack(&s), t0 + ms(1));
        let out = drain(&mut s);
        let sent = transmitted(&out);
        assert_eq!(sent[0].payload, [0x90, 0x07, 0x40]);
    }

    #[test]
    fn beacons_keep_the_session() {
        let t0 = Instant::now();
        let mut s = online_session(t0);
        s.handle_frame(&beacon(HOST), t0);
        assert_eq!(drain(&mut s), [], "own beacon while online: nothing to do");

        let stranger = MacAddress([0x02, 0, 0, 0, 0, 7]);
        let mut fresh = Session::new(HOST, Config::default());
        fresh.handle_frame(&beacon(stranger), t0);
        assert_eq!(
            fresh.state(),
            State::Discovering,
            "desk bound to another host"
        );
        fresh.handle_frame(&beacon(HOST), t0);
        assert_eq!(
            fresh.state(),
            State::Online { desk: DESK },
            "bound to us: reconnect"
        );
    }

    #[test]
    fn only_the_matching_ack_frees_the_window() {
        let t0 = Instant::now();
        let mut s = Session::new(HOST, Config::default());
        s.handle_frame(&announce_frame(), t0);
        drain(&mut s);
        s.queue_message(vec![0x90, 0x01, 0x40], t0);

        // ACK of the `online` packet: the clock reset is still in flight.
        s.handle_frame(&Frame::ack(HOST, DESK, 0), t0);
        assert_eq!(drain(&mut s), []);
        s.handle_frame(&Frame::ack(HOST, DESK, 1), t0);
        assert_eq!(transmitted(&drain(&mut s)).len(), 1);
    }

    #[test]
    fn data_with_a_bad_checksum_is_not_acknowledged() {
        let t0 = Instant::now();
        let mut s = online_session(t0);
        let mut frame = desk_data(5, 0, &[0x90, 0x01, 0x40]);
        frame.header.checksum ^= 1;
        s.handle_frame(&frame, t0);
        assert_eq!(drain(&mut s), []);
    }
}
