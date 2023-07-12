use log::{error, LevelFilter};
use std::sync::mpsc::channel;
use fuser::MountOption;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::PathBuf;
use std::io;
use clap::{Arg, Command};
use std::fs::File;
use log::{debug, warn};

use uproc::fs::UProcFS;
use uproc::fs::Msg;

fn main() {
    let matches = Command::new("Fuser")
        .arg(
            Arg::new("mount-point")
                .long("mount-point")
                .value_name("MOUNT_POINT")
                .default_value("")
                .help("Act as a client, and mount FUSE at given path")
                .takes_value(true),
        )
        .arg(
            Arg::new("v")
                .short('v')
                .multiple_occurrences(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let verbosity: u64 = matches.occurrences_of("v");
    let log_level = match verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let options = vec![MountOption::FSName("fuser".to_string()), MountOption::DefaultPermissions];

    let mountpoint: String = matches
        .value_of("mount-point")
        .unwrap_or_default()
        .to_string();

    let (fs_tx, ext_rx) = channel();
    let (ext_tx, fs_rx) = channel();

    let fs = fuser::spawn_mount2(
        UProcFS::new(fs_tx, fs_rx),
        mountpoint,
        &options,
    ).unwrap();

    while let request = ext_rx.recv() {
        match request.unwrap() {
            Msg { path: f, content: Some(c) } => debug!("the message is {:?}", c),
            Msg { path: f, content: None } => ext_tx.send("did someone cat me?".to_string()).unwrap(),
        };
    };
}
