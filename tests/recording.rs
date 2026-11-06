//! A session with a simulated desk, recorded and analysed again: the same
//! path a real `rustbucketd --record` capture takes through `rustbucket file.pcap`.

use std::collections::VecDeque;
use std::io;
use std::time::Instant;

use rustbucket::analysis::Analyzer;
use rustbucket::driver::{Driver, Link};
use rustbucket::header::Header;
use rustbucket::message::ButtonId;
use rustbucket::pcap::{self, Recorder, Writer};
use rustbucket::{Command, Config, Frame, MacAddress};

const DESK: MacAddress = MacAddress([0x00, 0xA0, 0x7E, 1, 2, 3]);
const HOST: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

#[derive(Default)]
struct SimulatedDesk {
    incoming: VecDeque<Vec<u8>>,
}

impl Link for SimulatedDesk {
    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.incoming.pop_front())
    }
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

fn desk_data(counter: u32, payload: &[u8]) -> Vec<u8> {
    let mut header = Header::new(Command::Data, 1);
    header.send_counter = counter;
    Frame::new(HOST, DESK, header, payload.to_vec()).to_bytes()
}

#[test]
fn recorded_session_analyses_cleanly() {
    let mut announce = vec![0; 14];
    announce.extend_from_slice(b"1.0\0\0\0\0\0\0\0");
    announce.extend_from_slice(b"C24\0\0\0\0\0\0\0");
    let mut desk = SimulatedDesk::default();
    desk.incoming.extend([
        Frame::new(
            MacAddress::BROADCAST,
            DESK,
            Header::new(Command::Announce, 1),
            announce,
        )
        .to_bytes(),
        Frame::ack(HOST, DESK, 1).to_bytes(),
        desk_data(1, &[0x90, 0x18, 0x40]),
        desk_data(2, &[0x90, 0x18, 0x00]),
    ]);

    let recorder = Recorder::new(desk, Writer::new(Vec::new()).unwrap());
    let mut driver = Driver::new(recorder, HOST, Config::default());
    let now = Instant::now();
    for _ in 0..6 {
        driver.poll(now).unwrap();
    }
    let (_, writer) = driver.into_link().into_parts();

    let packets = pcap::read(&writer.into_inner()).unwrap();
    let mut analyzer = Analyzer::new();
    let lines: Vec<_> = packets.iter().filter_map(|p| analyzer.add(p)).collect();
    let summary = analyzer.summary();

    // announce, online, clock reset, desk ACK, 2 × (desk data + our ACK)
    assert_eq!(lines.len(), 8, "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains('!')), "{lines:#?}");
    assert_eq!(summary.ack_matches, 3);
    assert_eq!(summary.buttons[&ButtonId([0x18, 0x00])], 1);
}
