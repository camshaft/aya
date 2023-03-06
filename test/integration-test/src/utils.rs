//! Utilities to run tests

use std::{
    fs::File,
    io::Write,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use libc::{setns, CLONE_NEWNET};

fn script(script: &str) {
    // We pipe stdout/err to capture it and print it ourselves, so that it gets captured by the
    // test harness
    let mut bash = Command::new("/bin/bash")
        .arg("-e")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    // Send script
    let mut stdin = bash.stdin.take().unwrap();
    stdin.write_all(script.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);

    // Wait for it to finish
    let status = bash.wait().unwrap();

    assert_eq!(status.code(), Some(0));
}

pub struct Netns {
    pub name: String,
    pub fd: File,
}

impl Netns {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = format!("aya-test-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
        script(&format!(
            "
            ip netns add {name}
            ip -netns {name} link set lo up
        "
        ));
        let fd = File::open(format!("/var/run/netns/{name}")).unwrap();
        Self { name, fd }
    }

    pub fn exec<F, U>(&self, f: F) -> U
    where
        F: FnOnce() -> U + Send,
        U: Send,
    {
        let fd = self.fd.as_raw_fd();
        std::thread::scope(|s| {
            s.spawn(|| {
                // SAFETY: we are in a scoped thread, so the file descriptor is valid for the whole
                // context
                unsafe { setns(fd, CLONE_NEWNET) };
                f()
            })
            .join()
            .unwrap()
        })
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        script(&format!("ip netns del {}", self.name))
    }
}
