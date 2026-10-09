mod common;

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use common::*;
use tangy_lib::TangyLib;

// A bounded, loopback-only adapter for the external client test, not a server API.
struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Vec<String>>>>,
}

impl Server {
    fn start(lib: TangyLib) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut paths = Vec::new();
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => paths.push(serve(&lib, stream)?),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(paths)
        });
        Self {
            url,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(lib: &TangyLib, mut stream: TcpStream) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.by_ref().take(8192).read_line(&mut request)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").to_owned();
    let mut length = 0;
    let mut header_bytes = request.len();
    loop {
        let mut line = String::new();
        let read = reader.by_ref().take(8192).read_line(&mut line)?;
        header_bytes += read;
        if read == 0 || header_bytes > 8192 {
            return Err(io::Error::other("Invalid test HTTP headers"));
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().map_err(io::Error::other)?;
            }
        }
    }
    if length > 8192 {
        return Err(io::Error::other("Test request too large"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8(body).map_err(io::Error::other)?;
    let (content_type, result) = match (method, path.as_str()) {
        ("GET", "/adv" | "/adv/") => ("application/jose+json", lib.adv(None)),
        ("GET", path) if path.starts_with("/adv/") => {
            ("application/jose+json", lib.adv(Some(&path[5..])))
        }
        ("POST", path) if path.starts_with("/rec/") => {
            ("application/jwk+json", lib.rec(&path[5..], &body))
        }
        _ => return Err(io::Error::other("Unexpected test HTTP route")),
    };
    let (status, response) = match result {
        Ok(body) => ("200 OK", body),
        Err(error) => ("400 Bad Request", error.to_string()),
    };
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len())?;
    Ok(path)
}

/// Assures: INTEROP-001
#[test]
fn clevis_encrypts_and_recovers_using_library_endpoints() {
    for signing in [vec![SIGNING], vec![SIGNING, SECOND_SIGNING]] {
        let mut keys = signing.clone();
        let selected = thumbprint(signing.last().unwrap());
        keys.push(RECOVERY);
        let server = Server::start(library(&keys));
        let output = Command::new("python3")
            .arg("scripts/clevis-round-trip.py")
            .arg(&server.url)
            .arg(&selected)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Python 3 is required for interop tests");
        assert!(
            output.status.success(),
            "Clevis failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let paths = server.finish();
        assert!(paths.iter().any(|p| p == "/adv/" || p == "/adv"));
        assert!(paths.contains(&format!("/adv/{selected}")));
        assert_eq!(
            paths
                .iter()
                .filter(|p| **p == format!("/rec/{}", thumbprint(RECOVERY)))
                .count(),
            2
        );
    }
}
