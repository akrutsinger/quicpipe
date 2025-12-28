//! CLI integration tests for quicpipe
//!
//! These tests verify end-to-end functionality of the quicpipe binary, adapted from dumbpipe's test
//! suite.

#![cfg_attr(target_os = "windows", allow(unused_imports, dead_code))]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Barrier},
    time::Duration,
};

// binary path
fn quicpipe_bin() -> &'static str {
    env!("CARGO_BIN_EXE_quicpipe")
}

/// Read `n` lines from `reader`, returning the bytes read including the newlines.
///
/// This assumes that the header lines are ASCII and can be parsed byte by byte.
fn read_ascii_lines(mut n: usize, reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    let mut res = Vec::new();
    loop {
        if reader.read(&mut buf)? != 1 {
            break;
        }
        let char = buf[0];
        res.push(char);
        if char != b'\n' {
            continue;
        }
        if n > 1 {
            n -= 1;
        } else {
            break;
        }
    }
    Ok(res)
}

fn wait2() -> Arc<Barrier> {
    Arc::new(Barrier::new(2))
}

/// Generate a random, non privileged port
fn random_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static PORT: AtomicU16 = AtomicU16::new(15000);
    PORT.fetch_add(1, Ordering::SeqCst)
}

/// Tests the basic functionality of the connect and listen pair
///
/// Connect and listen both write a limited amount of data and then EOF. The interaction should stop
/// when both sides have EOF'd.
#[test]
fn connect_listen_happy() {
    let listen_to_connect = b"hello from listen";
    let connect_to_listen = b"hello from connect";
    let port = random_port();

    // Start server in background, keeping stdin open
    let listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(listen_to_connect)
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    // Wait for server to be ready
    std::thread::sleep(Duration::from_millis(500));

    // Connect and complete the exchange
    let connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stdin_bytes(connect_to_listen)
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect.status.success(), "connect failed");
    assert_eq!(&connect.stdout, listen_to_connect);

    // Wait for server to finish
    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success(), "listen failed");
    assert_eq!(&listen_output.stdout, connect_to_listen);
}

/// Tests the basic functionality with custom ALPN
#[test]
fn connect_listen_custom_alpn_happy() {
    let listen_to_connect = b"hello from listen";
    let connect_to_listen = b"hello from connect";
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        [
            "listen",
            "-p",
            &port.to_string(),
            "--alpn",
            "utf8:mysuperalpn/0.1.0",
            "--once",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(listen_to_connect)
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(
        quicpipe_bin(),
        [
            "connect",
            &format!("127.0.0.1:{}", port),
            "--alpn",
            "utf8:mysuperalpn/0.1.0",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(connect_to_listen)
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, listen_to_connect);

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
    assert_eq!(&listen_output.stdout, connect_to_listen);
}

#[cfg(unix)]
#[test]
#[ignore = "flaky"]
fn connect_listen_ctrlc_connect() {
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    let port = random_port();
    let mut listen = duct::cmd(quicpipe_bin(), ["listen", "-p", &port.to_string()])
        .env_remove("RUST_LOG")
        .stdin_bytes(b"hello from listen\n")
        .stderr_null()
        .reader()
        .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let mut connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stderr_null()
        .stdout_capture()
        .reader()
        .unwrap();

    // wait until we get a line from the listen process
    read_ascii_lines(1, &mut connect).unwrap();
    for pid in connect.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    // we don't care about the results. This test is just to make sure that the
    // listen command stops when the connect command stops.
    listen.read_to_end(&mut tmp).ok();
    connect.read_to_end(&mut tmp).ok();
}

#[cfg(unix)]
#[test]
#[ignore = "flaky"]
fn connect_listen_ctrlc_listen() {
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    let port = random_port();
    let mut listen = duct::cmd(quicpipe_bin(), ["listen", "-p", &port.to_string()])
        .env_remove("RUST_LOG")
        .stderr_null()
        .reader()
        .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let mut connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stderr_null()
        .stdout_capture()
        .reader()
        .unwrap();

    std::thread::sleep(Duration::from_secs(1));
    for pid in listen.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    listen.read_to_end(&mut tmp).ok();
    connect.read_to_end(&mut tmp).ok();
}

#[test]
#[cfg(unix)]
fn listen_tcp_happy() {
    let b1 = wait2();
    let b2 = b1.clone();
    let port = random_port();
    let tcp_port = random_port();

    // start a dummy tcp server and wait for a single incoming connection
    let host_port = format!("localhost:{}", tcp_port);
    let host_port_2 = host_port.clone();
    std::thread::spawn(move || {
        let server = TcpListener::bind(host_port_2).unwrap();
        b1.wait();
        let (mut stream, _addr) = server.accept().unwrap();
        stream.write_all(b"hello from tcp").unwrap();
        stream.flush().unwrap();
        drop(stream);
    });

    // wait for the tcp listener to start
    b2.wait();

    // start a quicpipe listen-tcp process
    let _listen_tcp = duct::cmd(
        quicpipe_bin(),
        [
            "listen-tcp",
            "--backend",
            &host_port,
            "-p",
            &port.to_string(),
        ],
    )
    .env_remove("RUST_LOG")
    .stderr_null()
    .reader()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    // poke the listen-tcp process with a connect command
    let connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stderr_null()
        .stdout_capture()
        .stdin_bytes(b"hello from connect")
        .run()
        .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, b"hello from tcp");
}

#[test]
fn connect_tcp_happy() {
    let port = random_port();
    let tcp_port = random_port();
    let host_port = format!("localhost:{}", tcp_port);

    // start a quicpipe listen process
    let _listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello from listen\n")
    .stderr_null()
    .reader()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    // start a quicpipe connect-tcp process
    let _connect_tcp = duct::cmd(
        quicpipe_bin(),
        [
            "connect-tcp",
            &format!("127.0.0.1:{}", port),
            "--listen",
            &host_port,
        ],
    )
    .env_remove("RUST_LOG")
    .stderr_null()
    .reader()
    .unwrap();

    std::thread::sleep(Duration::from_secs(1));

    // connect via TCP
    let mut conn = TcpStream::connect(host_port).unwrap();
    conn.write_all(b"hello from tcp").unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf, b"hello from listen\n");
}

#[test]
fn test_handshake_matching() {
    let port = random_port();
    let handshake = "howdoyoudo";

    let listen = duct::cmd(
        quicpipe_bin(),
        [
            "listen",
            "-p",
            &port.to_string(),
            "--handshake",
            handshake,
            "--once",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(
        quicpipe_bin(),
        [
            "connect",
            &format!("127.0.0.1:{}", port),
            "--handshake",
            handshake,
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"world")
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(
        connect.status.success(),
        "connect failed: {:?}\nstderr: {}",
        connect.status,
        String::from_utf8_lossy(&connect.stderr)
    );
    assert_eq!(&connect.stdout, b"hello");

    let listen_output = listen.wait().unwrap();
    assert!(
        listen_output.status.success(),
        "listen failed: {:?}",
        listen_output.status
    );
    assert_eq!(&listen_output.stdout, b"world");
}

#[test]
#[ignore = "flaky"]
fn test_handshake_hex() {
    let port = random_port();
    let handshake = "hex:deadbeef";

    let listen = duct::cmd(
        quicpipe_bin(),
        [
            "listen",
            "-p",
            &port.to_string(),
            "--handshake",
            handshake,
            "--once",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(
        quicpipe_bin(),
        [
            "connect",
            &format!("127.0.0.1:{}", port),
            "--handshake",
            handshake,
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"world")
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(
        connect.status.success(),
        "connect failed: {:?}",
        connect.status
    );
    assert_eq!(&connect.stdout, b"hello");

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
    assert_eq!(&listen_output.stdout, b"world");
}

#[test]
fn test_recv_only_listen() {
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--recv-only", "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_null()
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stdin_bytes(b"test message")
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect.status.success());

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
    assert_eq!(&listen_output.stdout, b"test message");
}

#[test]
fn test_recv_only_connect() {
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"server message")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(
        quicpipe_bin(),
        ["connect", &format!("127.0.0.1:{}", port), "--recv-only"],
    )
    .env_remove("RUST_LOG")
    .stdin_null()
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, b"server message");

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
}

#[test]
fn test_once_flag() {
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    // First connection
    let connect1 = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stdin_bytes(b"client1")
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect1.status.success());
    assert_eq!(&connect1.stdout, b"hello");

    // Wait for listen to exit (it should exit after first connection)
    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
}

#[test]
fn test_retry_flag() {
    let port = random_port();

    // Start client with retry before server is up
    let connect = duct::cmd(
        quicpipe_bin(),
        [
            "connect",
            &format!("127.0.0.1:{}", port),
            "--retry",
            "--retry-interval",
            "1",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"client message")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    // Wait a bit then start server
    std::thread::sleep(Duration::from_millis(1500));

    let listen = duct::cmd(
        quicpipe_bin(),
        ["listen", "-p", &port.to_string(), "--once"],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"server message")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    // Wait for both to complete
    let connect_output = connect.wait().unwrap();
    assert!(connect_output.status.success());
    assert_eq!(&connect_output.stdout, b"server message");

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
    assert_eq!(&listen_output.stdout, b"client message");
}

#[test]
fn test_ipv4_binding() {
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        [
            "listen",
            "--ipv4-addr",
            &format!("127.0.0.1:{}", port),
            "--once",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello ipv4")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(quicpipe_bin(), ["connect", &format!("127.0.0.1:{}", port)])
        .env_remove("RUST_LOG")
        .stdin_bytes(b"client")
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, b"hello ipv4");

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
}

#[test]
#[ignore = "flaky"]
fn test_ipv6_binding() {
    let port = random_port();

    let listen = duct::cmd(
        quicpipe_bin(),
        [
            "listen",
            "--ipv6-addr",
            &format!("[::1]:{}", port),
            "--once",
        ],
    )
    .env_remove("RUST_LOG")
    .stdin_bytes(b"hello ipv6")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    std::thread::sleep(Duration::from_millis(500));

    let connect = duct::cmd(quicpipe_bin(), ["connect", &format!("[::1]:{}", port)])
        .env_remove("RUST_LOG")
        .stdin_bytes(b"client")
        .stderr_null()
        .stdout_capture()
        .run()
        .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, b"hello ipv6");

    let listen_output = listen.wait().unwrap();
    assert!(listen_output.status.success());
}
