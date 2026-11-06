//! `rustbucketd`: connects to a Control|24 on a network interface and prints
//! what happens.
//!
//! ```text
//! rustbucketd --list                           list interfaces
//! sudo rustbucketd en5                         run on interface en5
//! sudo rustbucketd en5 --record session.pcap   also save the traffic
//! ```
//!
//! One exercise may be added: `--demo`, `--wave-test`, `--ring-test`,
//! `--meter-test` or `--clock-test` (see [`exercises`] and [`wave`]).
//!
//! Button bounce is filtered, and every fader move is sent back to the desk
//! so the motor holds the fader where it was left (without it, the desk
//! pulls a released fader back to the last position the host set).
//!
//! Raw Ethernet needs access to `/dev/bpf*` on macOS (or `CAP_NET_RAW` on
//! Linux), hence `sudo`.

mod exercises;
mod wave;

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use pnet_datalink::{Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use rustbucket::debounce::Debouncer;
use rustbucket::driver::{Driver, Link};
use rustbucket::pcap::{Recorder, Writer};
use rustbucket::{Config, DeskMessage, Event, HostMessage, MacAddress, parse_messages};

use exercises::Exercise;

/// Exercises wait while this many messages are still queued for the desk.
const MAX_BACKLOG: usize = 200;

/// How long one receive call may block, so timers keep running.
const READ_TIMEOUT: Duration = Duration::from_millis(5);

/// [`Link`] over a pnet datalink channel (BPF on macOS, packet socket on Linux).
struct EthernetLink {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    /// Our own address: BPF also hands back the frames we send, which are dropped.
    own: MacAddress,
}

impl EthernetLink {
    fn open(interface: &NetworkInterface, own: MacAddress) -> io::Result<Self> {
        let config = pnet_datalink::Config {
            read_timeout: Some(READ_TIMEOUT),
            promiscuous: false,
            ..Default::default()
        };
        match pnet_datalink::channel(interface, config)? {
            Channel::Ethernet(tx, rx) => Ok(Self { tx, rx, own }),
            _ => Err(io::Error::other(
                "interface does not provide an Ethernet channel",
            )),
        }
    }
}

impl Link for EthernetLink {
    fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.rx.next() {
            Ok(frame) if frame.get(6..12) == Some(&self.own.0[..]) => Ok(None),
            Ok(frame) => Ok(Some(frame.to_vec())),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.tx
            .send_to(frame, None)
            .unwrap_or_else(|| Err(io::Error::other("send queue unavailable")))
    }
}

const USAGE: &str = "usage: rustbucketd --list | rustbucketd <interface> [--mac aa:bb:cc:dd:ee:ff] [--record file.pcap] [--demo | --wave-test | --ring-test | --meter-test | --clock-test]";

/// Command-line options for a run.
#[derive(Default)]
struct Options {
    interface: String,
    mac: Option<MacAddress>,
    record: Option<PathBuf>,
    exercise: Option<Box<dyn Exercise>>,
}

/// The exercise selected by a command-line flag.
fn exercise_for(flag: &str) -> Option<Box<dyn Exercise>> {
    Some(match flag {
        "--demo" => Box::new(exercises::Demo::default()),
        "--wave-test" => Box::new(wave::WaveTest::default()),
        "--ring-test" => Box::new(exercises::ring_test()),
        "--meter-test" => Box::new(exercises::meter_test()),
        "--clock-test" => Box::new(exercises::clock_test()),
        _ => return None,
    })
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mac" => {
                let text = args.next().ok_or("--mac needs an address")?;
                options.mac = Some(parse_mac(text).ok_or(format!("invalid MAC address {text:?}"))?);
            }
            "--record" => {
                let path = args.next().ok_or("--record needs a file name")?;
                options.record = Some(PathBuf::from(path));
            }
            flag if flag.starts_with('-') => {
                let exercise = exercise_for(flag).ok_or(format!("unknown option {flag}"))?;
                if options.exercise.replace(exercise).is_some() {
                    return Err("only one exercise at a time".into());
                }
            }
            name if options.interface.is_empty() => options.interface = name.to_string(),
            extra => return Err(format!("unexpected argument {extra:?}")),
        }
    }
    if options.interface.is_empty() {
        return Err("no interface given".into());
    }
    Ok(options)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let interfaces = pnet_datalink::interfaces();
    if args.len() == 1 && args[0] == "--list" {
        for i in &interfaces {
            let mac = host_mac(i).map_or_else(|| "-".to_string(), |m| m.to_string());
            let state = if i.is_up() { "up" } else { "down" };
            println!("{:<10} {mac:<17} {state}", i.name);
        }
        return ExitCode::SUCCESS;
    }
    let options = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let arg = &options.interface;

    let Some(interface) = interfaces.into_iter().find(|i| &i.name == arg) else {
        eprintln!("no interface named {arg:?}; try --list");
        return ExitCode::from(2);
    };
    let Some(mac) = options.mac.or_else(|| host_mac(&interface)) else {
        eprintln!("cannot read the MAC address of {arg} (macOS may be hiding it).");
        eprintln!("find it with `ifconfig {arg} | grep ether` in Terminal and pass it with --mac");
        return ExitCode::from(2);
    };
    let link = match open_link(&interface, mac, options.record.as_deref()) {
        Ok(link) => link,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!("listening on {arg} ({mac}) for a Control|24...");
    let mut driver = Driver::new(link, mac, Config::default());
    let mut exercise = options.exercise;
    let input = exercise
        .as_ref()
        .filter(|e| e.reads_terminal())
        .map(|_| terminal_lines());
    let mut debouncer = Debouncer::default();
    let start = Instant::now();
    loop {
        let now = Instant::now();
        let events = match driver.poll(now) {
            Ok(events) => events,
            Err(e) => {
                eprintln!("link error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let mut replies = Vec::new();
        for event in events {
            let elapsed = now.duration_since(start);
            match event {
                Event::Messages { payload } => replies.extend(handle_messages(
                    &payload,
                    &mut debouncer,
                    &mut exercise,
                    elapsed,
                )),
                Event::DeskFound { desk, announce } => {
                    println!(
                        "desk {desk}: {} firmware {} (handshake sent)",
                        announce.device, announce.firmware
                    );
                    if let Some(exercise) = exercise.as_mut() {
                        replies.extend(exercise.on_connect(now));
                    }
                }
                Event::AckOverdue { send_counter } => {
                    println!("warning: no ACK yet for packet {send_counter}");
                }
                Event::UnknownPacket { command } => {
                    println!("unknown packet type {command:#04x}");
                }
            }
        }
        if let Some(exercise) = exercise.as_mut() {
            for line in input.iter().flat_map(mpsc::Receiver::try_iter) {
                exercise.on_line(&line);
            }
            if driver.queued() < MAX_BACKLOG {
                replies.extend(exercise.tick(now));
            }
        }
        if !replies.is_empty() {
            driver.queue(&replies, now);
        }
    }
}

/// Opens the interface, recording to `record` if given.
fn open_link(
    interface: &NetworkInterface,
    mac: MacAddress,
    record: Option<&Path>,
) -> Result<Box<dyn Link>, String> {
    let ethernet = EthernetLink::open(interface, mac).map_err(|e| {
        // pnet tries every /dev/bpf* and reports the last error, so a
        // permission problem can surface as "not found".
        let hint = if matches!(
            e.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
        ) {
            "\nraw Ethernet access needs root on macOS: run with sudo"
        } else {
            ""
        };
        format!("cannot open {}: {e}{hint}", interface.name)
    })?;
    let Some(path) = record else {
        return Ok(Box::new(ethernet));
    };
    let writer =
        open_recording(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    println!("recording Control|24 traffic to {}", path.display());
    Ok(Box::new(Recorder::new(ethernet, writer)))
}

/// Prints the desk's messages and returns the replies: the fader echo, and
/// the exercise's responses.
fn handle_messages(
    payload: &[u8],
    debouncer: &mut Debouncer,
    exercise: &mut Option<Box<dyn Exercise>>,
    elapsed: Duration,
) -> Vec<HostMessage> {
    let mut replies = Vec::new();
    for message in parse_messages(payload) {
        let message = match message {
            Ok(m) => m,
            Err(e) => {
                println!("  error: {e}");
                continue;
            }
        };
        if let DeskMessage::Button { id, pressed } = message
            && !debouncer.accept(id, pressed, elapsed)
        {
            continue;
        }
        println!("  {message}");
        if let DeskMessage::Fader { track, position } = message {
            replies.push(HostMessage::FaderMove { track, position });
        }
        if let Some(exercise) = exercise.as_mut() {
            replies.extend(exercise.on_message(&message));
        }
    }
    replies
}

/// Creates the pcap file. Under `sudo` it is handed back to the invoking
/// user, so it can be opened and deleted without root.
fn open_recording(path: &Path) -> io::Result<Writer<File>> {
    let writer = Writer::new(File::create(path)?)?;
    let id = |name| std::env::var(name).ok().and_then(|v| v.parse::<u32>().ok());
    if let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    Ok(writer)
}

/// Lines typed in the terminal, read on a background thread so the driver
/// loop never blocks.
fn terminal_lines() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in io::stdin().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// The address the interface currently uses on the wire, if it can be read.
///
/// Recent macOS hides MAC addresses from some processes and reports the
/// placeholder `02:00:00:00:00:00` instead, both through `getifaddrs` (pnet)
/// and through `ifconfig` run as a child. Using that placeholder would make
/// the desk reply to an address the card drops, so it counts as unknown and
/// the caller must pass `--mac`.
fn host_mac(interface: &NetworkInterface) -> Option<MacAddress> {
    interface
        .mac
        .map(|m| MacAddress(m.octets()))
        .filter(|&mac| !is_placeholder(mac))
        .or_else(|| ifconfig_mac(&interface.name))
}

fn is_placeholder(mac: MacAddress) -> bool {
    mac.0 == [0; 6] || mac.0 == [0x02, 0, 0, 0, 0, 0]
}

/// Reads the `ether` line of `ifconfig <name>`.
fn ifconfig_mac(name: &str) -> Option<MacAddress> {
    let output = std::process::Command::new("ifconfig")
        .arg(name)
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("ether "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(parse_mac)
        .filter(|&mac| !is_placeholder(mac))
}

/// Parses `aa:bb:cc:dd:ee:ff`.
fn parse_mac(text: &str) -> Option<MacAddress> {
    let parts: Vec<u8> = text
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<_>>()?;
    Some(MacAddress(parts.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(list: &[&str]) -> Result<Options, String> {
        let args: Vec<String> = list.iter().map(ToString::to_string).collect();
        parse_args(&args)
    }

    #[test]
    fn parses_options_in_any_order() {
        let o = parse(&[
            "--demo",
            "en7",
            "--record",
            "a.pcap",
            "--mac",
            "00:11:22:33:44:55",
        ])
        .unwrap();
        assert_eq!(o.interface, "en7");
        assert!(o.exercise.is_some());
        assert_eq!(o.record, Some(PathBuf::from("a.pcap")));
        assert_eq!(o.mac, Some(MacAddress([0, 0x11, 0x22, 0x33, 0x44, 0x55])));
    }

    #[test]
    fn rejects_bad_command_lines() {
        for bad in [
            &["--record"][..],
            &["en7", "en8"],
            &["--loud", "en7"],
            &["en7", "--demo", "--wave-test"],
            &[],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
