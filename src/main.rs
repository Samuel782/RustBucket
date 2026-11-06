//! `rustbucket`: offline tools for Control|24 traffic.
//!
//! ```text
//! rustbucket <file.pcap> [--summary]   analyse a recording (e.g. from `rustbucketd --record`)
//! rustbucket <hex>                     decode one frame, e.g. Wireshark "Copy as Hex Stream"
//! ```

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rustbucket::analysis::Analyzer;
use rustbucket::pcap::{self, Packet};

const USAGE: &str = "usage: rustbucket <file.pcap> [--summary] | rustbucket <frame as hex>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (arg, summary_only) = match args.as_slice() {
        [arg] => (arg, false),
        [arg, flag] if flag == "--summary" => (arg, true),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if Path::new(arg).is_file() {
        return analyse_file(Path::new(arg), summary_only);
    }
    decode_frame(arg)
}

/// Prints every Control|24 frame of a capture, then the summary.
fn analyse_file(path: &Path, summary_only: bool) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let packets = match pcap::read(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let mut analyzer = Analyzer::new();
    for packet in &packets {
        if let Some(description) = analyzer.add(packet)
            && !summary_only
        {
            println!("{description}");
        }
    }
    if !summary_only {
        println!();
    }
    print!("{}", analyzer.summary());
    ExitCode::SUCCESS
}

fn decode_frame(arg: &str) -> ExitCode {
    let data = match decode_hex(arg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid hex: {e}");
            return ExitCode::from(2);
        }
    };
    let packet = Packet {
        timestamp: Duration::ZERO,
        data,
    };
    if let Some(description) = Analyzer::new().add(&packet) {
        println!("{description}");
        ExitCode::SUCCESS
    } else {
        eprintln!("not a Control|24 frame");
        ExitCode::FAILURE
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    digits
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(s, 16).map_err(|e| format!("{s:?}: {e}"))
        })
        .collect()
}
