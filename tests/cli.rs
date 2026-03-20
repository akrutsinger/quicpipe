//! CLI integration tests for quicpipe
//!
//! These tests verify end-to-end functionality of the quicpipe binary.
//!
//! Instead of hardcoding ports and sleeping, each test uses port 0 (OS-assigned) and reads the
//! server's stderr for the "listening on: <addr>" readiness line to extract the actual bound
//! address. This eliminates both port collisions and timing flakes.

#![cfg_attr(target_os = "windows", allow(unused_imports, dead_code))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Arc, Barrier},
    time::Duration,
};

fn quicpipe_bin() -> &'static str {
    env!("CARGO_BIN_EXE_quicpipe")
}

/// A running quicpipe server process with its bound address parsed from stderr.
struct TestServer {
    child: Child,
    /// The address the server is actually listening on (parsed from stderr).
    addr: String,
    /// Remaining stderr lines are available here.
    _stderr_reader: std::thread::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a quicpipe server process with the given CLI args.
///
/// Feeds `stdin_data` into the process's stdin (then closes it), and waits for the readiness line
/// on stderr that contains `ready_prefix` (e.g. `"listening on: "`). Returns the parsed address
/// and a handle to the running child.
fn start_server(args: &[&str], stdin_data: &[u8], ready_prefix: &str) -> TestServer {
    let mut child = Command::new(quicpipe_bin())
        .arg("-v")
        .args(args)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn quicpipe");

    // Write stdin data in a background thread so we don't block.
    let mut stdin = child.stdin.take().expect("no stdin");
    let data = stdin_data.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
        // stdin is dropped here, sending EOF
    });

    // Read stderr lines until we find the readiness line.
    let stderr = child.stderr.take().expect("no stderr");
    let mut reader = BufReader::new(stderr);
    let prefix = ready_prefix.to_string();
    let addr;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("failed to read stderr");
        if n == 0 {
            panic!(
                "server exited before printing readiness line (prefix: {:?})",
                prefix
            );
        }
        if let Some((_, rest)) = line.split_once(&prefix) {
            // Replace wildcard bind addresses with loopback for connecting.
            addr = rest
                .trim()
                .replace("0.0.0.0", "127.0.0.1")
                .replace("[::]", "[::1]");
            break;
        }
    }

    // Drain remaining stderr in background so the process doesn't block on a full pipe.
    let stderr_drainer = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });

    TestServer {
        child,
        addr,
        _stderr_reader: stderr_drainer,
    }
}

/// Convenience: start a `quicpipe listen` server on an OS-assigned port.
///
/// Adds a short idle timeout so tests don't hang for 5 minutes on edge cases.
fn start_listen(extra_args: &[&str], stdin_data: &[u8]) -> TestServer {
    let mut args = vec!["-v", "listen", "--idle-timeout-s", "30"];
    args.extend_from_slice(extra_args);
    // Don't pass -p; the default is port 0 (OS-assigned).
    start_server(&args, stdin_data, "listening on: ")
}

/// Convenience: start a `quicpipe listen-tcp` server on an OS-assigned port.
fn start_listen_tcp(backend: &str, extra_args: &[&str]) -> TestServer {
    let mut args = vec![
        "-v",
        "listen-tcp",
        "--backend",
        backend,
        "--idle-timeout-s",
        "30",
    ];
    args.extend_from_slice(extra_args);
    start_server(&args, &[], "listening on: ")
}

/// Run a `quicpipe connect` command to completion, returning (stdout, exit status).
fn run_connect(addr: &str, extra_args: &[&str], stdin_data: &[u8]) -> (Vec<u8>, bool) {
    let mut args = vec!["connect", addr, "--idle-timeout-s", "30"];
    args.extend_from_slice(extra_args);

    let mut child = Command::new(quicpipe_bin())
        .arg("-v")
        .args(&args)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn connect");

    let mut stdin = child.stdin.take().expect("no stdin");
    let data = stdin_data.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });

    let output = child.wait_with_output().expect("failed to wait");
    (output.stdout, output.status.success())
}

/// Wait for a `TestServer` to exit and capture its stdout.
fn collect_server_output(mut server: TestServer) -> (Vec<u8>, bool) {
    let mut stdout = server.child.stdout.take().expect("no stdout");
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).expect("failed to read stdout");
    let status = server.child.wait().expect("failed to wait");
    // Prevent the Drop impl from trying to kill/wait again.
    std::mem::forget(server);
    (buf, status.success())
}

/// Run a `quicpipe connect` command to completion, returning (stdout, stderr, success).
fn run_connect_full(
    addr: &str,
    extra_args: &[&str],
    stdin_data: &[u8],
) -> (Vec<u8>, Vec<u8>, bool) {
    let mut args = vec!["connect", addr, "--idle-timeout-s", "30"];
    args.extend_from_slice(extra_args);

    let mut child = Command::new(quicpipe_bin())
        .arg("-v")
        .args(&args)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn connect");

    let mut stdin = child.stdin.take().expect("no stdin");
    let data = stdin_data.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });

    let output = child.wait_with_output().expect("failed to wait");
    (output.stdout, output.stderr, output.status.success())
}

/// Read `n` ASCII lines from a reader.
fn read_ascii_lines(mut n: usize, reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    let mut res = Vec::new();
    loop {
        if reader.read(&mut buf)? != 1 {
            break;
        }
        let ch = buf[0];
        res.push(ch);
        if ch != b'\n' {
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

#[test]
fn connect_listen_happy() {
    let server = start_listen(&["--once"], b"hello from listen");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"hello from connect");
    assert!(connect_ok, "connect failed");
    assert_eq!(&connect_stdout, b"hello from listen");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok, "listen failed");
    assert_eq!(&listen_stdout, b"hello from connect");
}

#[test]
fn connect_listen_custom_alpn_happy() {
    let server = start_listen(
        &["--once", "--alpn", "utf8:mysuperalpn/0.1.0"],
        b"hello from listen",
    );
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(
        &addr,
        &["--alpn", "utf8:mysuperalpn/0.1.0"],
        b"hello from connect",
    );
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"hello from listen");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert_eq!(&listen_stdout, b"hello from connect");
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_connect() {
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    let server = start_listen(&[], b"hello from listen\n");
    let addr = server.addr.clone();

    let mut connect = Command::new(quicpipe_bin())
        .arg("-v")
        .args(["connect", &addr])
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn connect");

    // Wait until we get a line from the server through the connect process.
    let mut connect_stdout = connect.stdout.take().expect("no stdout");
    read_ascii_lines(1, &mut connect_stdout).expect("failed to read line");

    // Send SIGINT to the connect process.
    signal::kill(Pid::from_raw(connect.id() as i32), Signal::SIGINT).expect("kill failed");

    let mut tmp = Vec::new();
    let _ = connect_stdout.read_to_end(&mut tmp);
    let _ = connect.wait();
    // The listen side should also stop (we just need it to not hang forever).
    drop(server);
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_listen() {
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    let server = start_listen(&[], b"");
    let addr = server.addr.clone();

    let mut connect = Command::new(quicpipe_bin())
        .arg("-v")
        .args(["connect", &addr])
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn connect");

    // Give the connection time to establish.
    std::thread::sleep(Duration::from_secs(1));

    // Send SIGINT to the listen process.
    signal::kill(Pid::from_raw(server.child.id() as i32), Signal::SIGINT).expect("kill failed");

    // Give the connect process a moment to notice the server is gone, then kill it.
    std::thread::sleep(Duration::from_secs(2));
    let _ = connect.kill();
    let _ = connect.wait();
    drop(server);
}

#[cfg(unix)]
#[test]
fn listen_tcp_happy() {
    // Start a dummy TCP backend server on an OS-assigned port.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind TCP");
    let tcp_addr = tcp_listener.local_addr().expect("no local addr");
    let tcp_host_port = tcp_addr.to_string();

    let tcp_handle = std::thread::spawn(move || {
        let (mut stream, _) = tcp_listener.accept().expect("accept failed");
        stream.write_all(b"hello from tcp").expect("write failed");
        stream.flush().expect("flush failed");
        drop(stream);
    });

    let server = start_listen_tcp(&tcp_host_port, &[]);
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"hello from connect");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"hello from tcp");

    tcp_handle.join().expect("tcp thread panicked");
    drop(server);
}

#[test]
fn connect_tcp_happy() {
    let server = start_listen(&["--once"], b"hello from listen\n");
    let quic_addr = server.addr.clone();

    // Start connect-tcp, which opens a local TCP listener and connects to the QUIC server.
    let connect_tcp = start_server(
        &["connect-tcp", &quic_addr, "--listen", "127.0.0.1:0"],
        &[],
        "TCP listening on: ",
    );
    let tcp_addr = connect_tcp.addr.clone();

    // Connect via TCP.
    let mut conn = TcpStream::connect(&tcp_addr).expect("TCP connect failed");
    conn.write_all(b"hello from tcp").expect("write failed");
    conn.flush().expect("flush failed");
    // Shut down the write half so the server sees EOF.
    conn.shutdown(std::net::Shutdown::Write)
        .expect("shutdown failed");

    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).expect("read failed");
    assert_eq!(&buf, b"hello from listen\n");

    drop(connect_tcp);
    drop(server);
}

#[test]
fn test_handshake_matching() {
    let server = start_listen(&["--once", "--handshake", "howdoyoudo"], b"hello");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &["--handshake", "howdoyoudo"], b"world");
    assert!(connect_ok, "connect failed");
    assert_eq!(&connect_stdout, b"hello");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok, "listen failed");
    assert_eq!(&listen_stdout, b"world");
}

#[test]
fn test_handshake_hex() {
    let server = start_listen(&["--once", "--handshake", "hex:deadbeef"], b"hello");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) =
        run_connect(&addr, &["--handshake", "hex:deadbeef"], b"world");
    assert!(connect_ok, "connect failed");
    assert_eq!(&connect_stdout, b"hello");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert_eq!(&listen_stdout, b"world");
}

#[test]
fn connect_listen_with_migration() {
    let server = start_listen(&["--once"], b"hello from listen");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"hello from connect");
    assert!(connect_ok, "connect with migration failed");
    assert_eq!(&connect_stdout, b"hello from listen");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok, "listen failed");
    assert_eq!(&listen_stdout, b"hello from connect");
}

#[test]
fn connect_listen_no_migration() {
    let server = start_listen(&["--once"], b"hello from listen");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &["--no-migrate"], b"hello from connect");
    assert!(connect_ok, "connect without migration failed");
    assert_eq!(&connect_stdout, b"hello from listen");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok, "listen failed");
    assert_eq!(&listen_stdout, b"hello from connect");
}

#[test]
fn test_recv_only_listen() {
    let server = start_listen(&["--recv-only", "--once"], b"");
    let addr = server.addr.clone();

    let (_, connect_ok) = run_connect(&addr, &[], b"test message");
    assert!(connect_ok);

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert_eq!(&listen_stdout, b"test message");
}

#[test]
fn test_recv_only_connect() {
    let server = start_listen(&["--once"], b"server message");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &["--recv-only"], b"");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"server message");

    let (_listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
}

#[test]
fn test_once_flag() {
    let server = start_listen(&["--once"], b"hello");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"client1");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"hello");

    // The listen process should exit after the first connection.
    let (_, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
}

#[test]
fn test_retry_flag() {
    // Find a free port first, then start the client with --retry pointing at it.
    // The server isn't up yet, so the client will retry until it appears.
    let tmp_listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind tmp socket");
    let port = tmp_listener.local_addr().expect("no addr").port();
    drop(tmp_listener);

    let addr = format!("127.0.0.1:{}", port);
    let addr_clone = addr.clone();

    // Start the client in a thread — it will retry until the server appears.
    let connect_handle = std::thread::spawn(move || {
        run_connect(
            &addr_clone,
            &["--retry", "--retry-interval", "1"],
            b"client message",
        )
    });

    // Wait a bit then start the server on that port.
    std::thread::sleep(Duration::from_millis(1500));

    let server = start_server(
        &["listen", "-p", &port.to_string(), "--once"],
        b"server message",
        "listening on: ",
    );

    let (connect_stdout, connect_ok) = connect_handle.join().expect("connect thread panicked");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"server message");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert_eq!(&listen_stdout, b"client message");
}

#[test]
fn test_ipv4_binding() {
    let server = start_server(
        &["listen", "--ipv4-addr", "127.0.0.1:0", "--once"],
        b"hello ipv4",
        "listening on: ",
    );
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"client");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"hello ipv4");

    let (_, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
}

#[test]
fn test_ipv6_binding() {
    let server = start_server(
        &["listen", "--ipv6-addr", "[::1]:0", "--once"],
        b"hello ipv6",
        "listening on: ",
    );
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &[], b"client");
    assert!(connect_ok);
    assert_eq!(&connect_stdout, b"hello ipv6");

    let (_, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
}

/// Server should reject a client that sends the wrong handshake — no data should be exchanged.
#[test]
fn test_handshake_mismatch_rejected() {
    let server = start_listen(
        &["--once", "--handshake", "correct-secret"],
        b"should not arrive",
    );
    let addr = server.addr.clone();

    let (stdout, _stderr, _connect_ok) =
        run_connect_full(&addr, &["--handshake", "wrong-secret"], b"hello");

    // The connect side may exit 0 (it treats the server closing the connection as graceful),
    // but the key invariant is that no data should have been exchanged.
    assert!(
        stdout.is_empty(),
        "client should not have received data from server"
    );

    // Server should also exit (--once) without forwarding the client's data.
    let (listen_stdout, _listen_ok) = collect_server_output(server);
    assert!(
        listen_stdout.is_empty(),
        "server should not have forwarded data from rejected client"
    );
}

/// Both sides using --no-handshake should connect and exchange data.
#[test]
fn test_no_handshake_flag() {
    let server = start_listen(&["--once", "--no-handshake"], b"no handshake needed");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &["--no-handshake"], b"client data");
    assert!(connect_ok, "connect failed with --no-handshake");
    assert_eq!(&connect_stdout, b"no handshake needed");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert_eq!(&listen_stdout, b"client data");
}

/// Mismatched ALPN protocols should prevent connection.
#[test]
fn test_alpn_mismatch_rejected() {
    let server = start_listen(
        &["--once", "--alpn", "utf8:server-proto"],
        b"should not arrive",
    );
    let addr = server.addr.clone();

    let (_stdout, _stderr, connect_ok) =
        run_connect_full(&addr, &["--alpn", "utf8:client-proto"], b"hello");
    assert!(
        !connect_ok,
        "connect should have failed with mismatched ALPN"
    );

    drop(server);
}

/// --max-retries should stop after the specified number of attempts.
#[test]
fn test_max_retries_exhausted() {
    // Use a port that nothing is listening on.
    let tmp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind failed");
    let port = tmp.local_addr().expect("no addr").port();
    drop(tmp);

    let addr = format!("127.0.0.1:{}", port);

    let (_stdout, _stderr, ok) = run_connect_full(
        &addr,
        &[
            "--retry",
            "--max-retries",
            "2",
            "--retry-interval",
            "1",
            "--idle-timeout-s",
            "5",
        ],
        b"",
    );
    assert!(!ok, "connect should have failed after exhausting retries");
}

/// Multiple concurrent TCP connections should each get their own QUIC stream.
#[cfg(unix)]
#[test]
fn test_multiple_concurrent_tcp_connections() {
    // Start a TCP backend that accepts 3 connections, echoing back a unique response for each.
    let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind TCP");
    let tcp_addr = tcp_listener
        .local_addr()
        .expect("no local addr")
        .to_string();

    let tcp_handle = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = tcp_listener.accept().expect("accept failed");
            // Read what the client sent, echo it back uppercased.
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).expect("read failed");
            let response: Vec<u8> = buf.iter().map(|b| b.to_ascii_uppercase()).collect();
            stream.write_all(&response).expect("write failed");
            stream.flush().expect("flush failed");
        }
    });

    let server = start_listen_tcp(&tcp_addr, &[]);
    let quic_addr = server.addr.clone();

    // Start connect-tcp to bridge TCP -> QUIC.
    let connect_tcp = start_server(
        &[
            "connect-tcp",
            &quic_addr,
            "--listen",
            "127.0.0.1:0",
            "--idle-timeout-s",
            "30",
        ],
        &[],
        "TCP listening on: ",
    );
    let local_tcp_addr = connect_tcp.addr.clone();

    // Open 3 TCP connections concurrently.
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for i in 0..3u8 {
        let addr = local_tcp_addr.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            let mut conn = TcpStream::connect(&addr).expect("TCP connect failed");
            let msg = vec![b'a' + i; 4]; // "aaaa", "bbbb", "cccc"
            conn.write_all(&msg).expect("write failed");
            conn.shutdown(std::net::Shutdown::Write)
                .expect("shutdown failed");
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).expect("read failed");
            buf
        }));
    }

    let mut results: Vec<Vec<u8>> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();
    results.sort();

    assert_eq!(results[0], b"AAAA");
    assert_eq!(results[1], b"BBBB");
    assert_eq!(results[2], b"CCCC");

    tcp_handle.join().expect("tcp backend panicked");
    drop(connect_tcp);
    drop(server);
}

/// listen-tcp with an unreachable backend should not crash the server.
#[cfg(unix)]
#[test]
fn test_tcp_backend_unreachable() {
    // Use a port nothing is listening on as the "backend".
    let tmp = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let dead_addr = tmp.local_addr().expect("no addr").to_string();
    drop(tmp); // close it so nothing is listening

    let server = start_listen_tcp(&dead_addr, &[]);
    let addr = server.addr.clone();

    // Connect — the server should accept the QUIC connection but fail to reach the backend.
    // The connect side should see a failed/closed stream.
    let (_stdout, _stderr, _ok) = run_connect_full(&addr, &[], b"hello");
    // We don't assert success — the important thing is the server didn't crash.

    // Server should still be running (it's not --once). Kill it cleanly.
    drop(server);
}

/// Transfer a non-trivial amount of data to exercise QUIC flow control.
#[test]
fn test_large_data_transfer() {
    // 1 MB of patterned data
    let size = 1024 * 1024;
    let send_data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let server = start_listen(&["--once", "--recv-only"], b"");
    let addr = server.addr.clone();

    let (_, connect_ok) = run_connect(&addr, &[], &send_data);
    assert!(connect_ok, "connect failed during large transfer");

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok, "listen failed during large transfer");
    assert_eq!(
        listen_stdout.len(),
        size,
        "received {} bytes, expected {}",
        listen_stdout.len(),
        size
    );
    assert_eq!(
        listen_stdout, send_data,
        "data corruption in large transfer"
    );
}

/// Both sides using --recv-only should close cleanly without hanging.
#[test]
fn test_recv_only_both_sides() {
    let server = start_listen(&["--recv-only", "--once"], b"");
    let addr = server.addr.clone();

    let (connect_stdout, connect_ok) = run_connect(&addr, &["--recv-only"], b"");
    assert!(connect_ok);
    assert!(connect_stdout.is_empty());

    let (listen_stdout, listen_ok) = collect_server_output(server);
    assert!(listen_ok);
    assert!(listen_stdout.is_empty());
}
