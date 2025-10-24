use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "rust-ftp-server",
    version,
    about = "A minimal FTP server that supports uploads and downloads."
)]
struct Args {
    /// Port to listen on for FTP control connections.
    #[arg(long, default_value_t = 2121)]
    port: u16,

    /// Username required to log in. Defaults to anonymous mode.
    #[arg(long, default_value = "anonymous")]
    user: String,

    /// Password required to log in. Defaults to empty.
    #[arg(long, default_value = "")]
    pass: String,

    /// Root directory exposed over FTP. Defaults to the current directory.
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(Clone)]
struct ServerConfig {
    root: PathBuf,
    username: String,
    password: String,
    read_only: bool,
}

#[derive(Clone, Copy)]
enum TransferType {
    Ascii,
    Binary,
}

struct PassiveListener {
    listener: TcpListener,
    reply_ip: Ipv4Addr,
    reply_port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let requested_root = args
        .path
        .clone()
        .unwrap_or(std::env::current_dir().context("Failed to read current directory")?);
    let root = requested_root
        .canonicalize()
        .with_context(|| format!("Cannot access {}", requested_root.display()))?;
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }

    let read_only = args.user.trim() == "anonymous";
    let config = Arc::new(ServerConfig {
        root: root.clone(),
        username: args.user,
        password: args.pass,
        read_only,
    });

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), args.port);
    let listener = TcpListener::bind(bind_addr)
        .with_context(|| format!("Failed to bind 0.0.0.0:{}", args.port))?;

    println!(
        "FTP server listening on 0.0.0.0:{} (root: {})",
        args.port,
        root.display()
    );
    if config.read_only {
        println!("Operating in anonymous read-only mode.");
    } else {
        println!("Writable mode enabled for user '{}'.", config.username);
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = config.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, cfg) {
                        eprintln!("Session ended with error: {err:?}");
                    }
                });
            }
            Err(err) => eprintln!("Failed to accept connection: {err}"),
        }
    }

    Ok(())
}

fn handle_client(stream: TcpStream, config: Arc<ServerConfig>) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("Failed to set TCP_NODELAY on control connection")?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    send_response(&mut writer, 220, "Welcome to the Rust FTP server")?;

    let mut logged_in = false;
    let mut pending_user: Option<String> = None;
    let mut current_dir = config.root.clone();
    let mut passive_listener: Option<PassiveListener> = None;
    let mut transfer_type = TransferType::Binary;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }

        let raw_line = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if raw_line.is_empty() {
            continue;
        }

        let mut parts = raw_line.splitn(2, ' ');
        let command = parts
            .next()
            .map(|c| c.to_uppercase())
            .unwrap_or_else(|| "".to_string());
        let argument = parts.next().map(str::trim).unwrap_or("");

        match command.as_str() {
            "USER" => {
                passive_listener = None;
                let username = argument.to_string();
                logged_in = false;
                pending_user = Some(username.clone());
                if username.eq_ignore_ascii_case("anonymous") {
                    send_response(
                        &mut writer,
                        331,
                        "Anonymous login ok, send your email as password",
                    )?;
                } else {
                    send_response(&mut writer, 331, "User name ok, need password")?;
                }
            }
            "PASS" => {
                passive_listener = None;
                if pending_user.is_none() {
                    send_response(&mut writer, 503, "Login with USER first")?;
                    continue;
                }

                let attempted_user = pending_user.clone().unwrap();
                if is_valid_credentials(&config, &attempted_user, argument) {
                    logged_in = true;
                    pending_user = None;
                    send_response(&mut writer, 230, "User logged in, proceed")?;
                } else {
                    pending_user = None;
                    send_response(&mut writer, 530, "Login incorrect")?;
                }
            }
            "QUIT" => {
                send_response(&mut writer, 221, "Goodbye")?;
                break;
            }
            "PWD" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }

                let display_path = ftp_path(&config.root, &current_dir);
                send_response(
                    &mut writer,
                    257,
                    &format!("\"{}\" is the current directory", display_path),
                )?;
            }
            "TYPE" => {
                let arg = argument.to_uppercase();
                match arg.as_str() {
                    "I" => {
                        transfer_type = TransferType::Binary;
                        send_response(&mut writer, 200, "Switching to Binary mode")?;
                    }
                    "A" => {
                        transfer_type = TransferType::Ascii;
                        send_response(&mut writer, 200, "Switching to ASCII mode")?;
                    }
                    _ => send_response(&mut writer, 504, "Type not supported")?,
                }
            }
            "SYST" => {
                send_response(&mut writer, 215, "UNIX Type: L8")?;
            }
            "NOOP" => {
                send_response(&mut writer, 200, "OK")?;
            }
            "CLNT" => {
                send_response(&mut writer, 200, "Client name noted")?;
            }
            "FEAT" => {
                send_multiline_response(
                    &mut writer,
                    211,
                    &["Extensions supported:", " UTF8", " EPSV", " PASV", " SIZE"],
                )?;
            }
            "PASV" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }

                let control_addr = writer
                    .local_addr()
                    .context("Unable to fetch control connection address")?;
                let peer_addr = writer
                    .peer_addr()
                    .context("Unable to fetch client address")?;
                match enter_passive_mode(control_addr, peer_addr) {
                    Ok(listener) => {
                        let reply = format!(
                            "{},{},{},{},{},{}",
                            listener.reply_ip.octets()[0],
                            listener.reply_ip.octets()[1],
                            listener.reply_ip.octets()[2],
                            listener.reply_ip.octets()[3],
                            listener.reply_port / 256,
                            listener.reply_port % 256
                        );
                        send_response(
                            &mut writer,
                            227,
                            &format!("Entering Passive Mode ({reply})"),
                        )?;
                        passive_listener = Some(listener);
                    }
                    Err(err) => {
                        send_response(&mut writer, 425, "Cannot open passive connection")?;
                        eprintln!("Failed to enter passive mode: {err:?}");
                    }
                }
            }
            "LIST" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                let passive = match passive_listener.take() {
                    Some(p) => p,
                    None => {
                        send_response(&mut writer, 425, "Use PASV first")?;
                        continue;
                    }
                };
                let path_arg = extract_path_argument(argument);
                let target = match if path_arg.is_empty() {
                    Ok(current_dir.clone())
                } else {
                    resolve_path(&config.root, &current_dir, path_arg)
                } {
                    Ok(p) => p,
                    Err(err) => {
                        send_response(&mut writer, 550, "Failed to access path")?;
                        eprintln!("LIST path error: {err:?}");
                        continue;
                    }
                };
                send_response(&mut writer, 150, "Opening data connection for LIST")?;
                match passive.accept() {
                    Ok(mut data_stream) => {
                        if let Err(err) = send_directory_listing(&target, &mut data_stream) {
                            send_response(&mut writer, 451, "Error while listing directory")?;
                            eprintln!("LIST error: {err:?}");
                        } else {
                            let _ = data_stream.shutdown(Shutdown::Both);
                            send_response(&mut writer, 226, "Directory send OK")?;
                        }
                    }
                    Err(err) => {
                        send_response(&mut writer, 425, "Cannot open data connection")?;
                        eprintln!("Failed to accept LIST data connection: {err:?}");
                    }
                }
            }
            "RETR" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                if argument.is_empty() {
                    send_response(&mut writer, 501, "RETR requires a path")?;
                    continue;
                }
                let passive = match passive_listener.take() {
                    Some(p) => p,
                    None => {
                        send_response(&mut writer, 425, "Use PASV first")?;
                        continue;
                    }
                };
                let target = match resolve_path(&config.root, &current_dir, argument) {
                    Ok(p) => p,
                    Err(err) => {
                        send_response(&mut writer, 550, "Failed to access file")?;
                        eprintln!("RETR path error: {err:?}");
                        continue;
                    }
                };
                if !target.is_file() {
                    send_response(&mut writer, 550, "Not a regular file")?;
                    continue;
                }
                send_response(&mut writer, 150, "Opening data connection for RETR")?;
                match passive.accept() {
                    Ok(mut data_stream) => {
                        if let Err(err) = send_file(&target, &mut data_stream, transfer_type) {
                            send_response(&mut writer, 451, "Error while reading file")?;
                            eprintln!("RETR error: {err:?}");
                        } else {
                            let _ = data_stream.shutdown(Shutdown::Both);
                            send_response(&mut writer, 226, "Transfer complete")?;
                        }
                    }
                    Err(err) => {
                        send_response(&mut writer, 425, "Cannot open data connection")?;
                        eprintln!("Failed to accept RETR data connection: {err:?}");
                    }
                }
            }
            "STOR" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                if config.read_only {
                    send_response(&mut writer, 550, "Permission denied in anonymous mode")?;
                    continue;
                }
                if argument.is_empty() {
                    send_response(&mut writer, 501, "STOR requires a path")?;
                    continue;
                }
                let passive = match passive_listener.take() {
                    Some(p) => p,
                    None => {
                        send_response(&mut writer, 425, "Use PASV first")?;
                        continue;
                    }
                };
                let target = match resolve_path(&config.root, &current_dir, argument) {
                    Ok(p) => p,
                    Err(err) => {
                        send_response(&mut writer, 550, "Failed to access path")?;
                        eprintln!("STOR path error: {err:?}");
                        continue;
                    }
                };
                if let Some(parent) = target.parent() {
                    if let Err(err) = fs::create_dir_all(parent) {
                        send_response(&mut writer, 550, "Failed to prepare target directory")?;
                        eprintln!("STOR create_dir_all error: {err:?}");
                        continue;
                    }
                }
                send_response(&mut writer, 150, "Opening data connection for STOR")?;
                match passive.accept() {
                    Ok(mut data_stream) => {
                        if let Err(err) = receive_file(&target, &mut data_stream) {
                            send_response(&mut writer, 451, "Error while writing file")?;
                            eprintln!("STOR error: {err:?}");
                        } else {
                            let _ = data_stream.shutdown(Shutdown::Both);
                            send_response(&mut writer, 226, "Transfer complete")?;
                        }
                    }
                    Err(err) => {
                        send_response(&mut writer, 425, "Cannot open data connection")?;
                        eprintln!("Failed to accept STOR data connection: {err:?}");
                    }
                }
            }
            "CWD" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                let requested = argument.trim();
                if requested.is_empty() {
                    send_response(&mut writer, 501, "CWD requires a directory path")?;
                    continue;
                }
                match resolve_path(&config.root, &current_dir, requested) {
                    Ok(path) if path.is_dir() => {
                        current_dir = path;
                        send_response(&mut writer, 250, "Directory successfully changed")?;
                    }
                    Ok(_) => {
                        send_response(&mut writer, 550, "Not a directory")?;
                    }
                    Err(err) => {
                        send_response(&mut writer, 550, "Failed to change directory")?;
                        eprintln!("CWD error: {err:?}");
                    }
                }
            }
            "CDUP" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                if current_dir != config.root {
                    current_dir = current_dir
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| config.root.clone());
                }
                send_response(&mut writer, 200, "Directory changed to parent")?;
            }
            "SIZE" => {
                if !logged_in {
                    send_response(&mut writer, 530, "Please log in with USER and PASS")?;
                    continue;
                }
                if argument.is_empty() {
                    send_response(&mut writer, 501, "SIZE requires a path")?;
                    continue;
                }
                match resolve_path(&config.root, &current_dir, argument) {
                    Ok(path) if path.is_file() => match path.metadata() {
                        Ok(metadata) => {
                            send_response(&mut writer, 213, &metadata.len().to_string())?;
                        }
                        Err(err) => {
                            send_response(&mut writer, 550, "Cannot read file size")?;
                            eprintln!("SIZE metadata error: {err:?}");
                        }
                    },
                    Ok(_) => send_response(&mut writer, 550, "Not a regular file")?,
                    Err(err) => {
                        send_response(&mut writer, 550, "Failed to access file")?;
                        eprintln!("SIZE error: {err:?}");
                    }
                }
            }
            "OPTS" => {
                send_response(&mut writer, 200, "Command okay")?;
            }
            "" => {}
            _ => {
                send_response(&mut writer, 502, "Command not implemented")?;
            }
        }
    }

    Ok(())
}

fn send_response(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    let line = format!("{code} {message}\r\n");
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn send_multiline_response(stream: &mut TcpStream, code: u16, lines: &[&str]) -> Result<()> {
    if lines.is_empty() {
        return send_response(stream, code, "OK");
    }
    let mut first = true;
    for line in lines {
        if first {
            let line = format!("{code}-{}\r\n", line.trim_start());
            stream.write_all(line.as_bytes())?;
            first = false;
        } else {
            let line = format!("{code}-{}\r\n", line.trim_start());
            stream.write_all(line.as_bytes())?;
        }
    }
    let final_line = format!("{code} End\r\n");
    stream.write_all(final_line.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn is_valid_credentials(config: &ServerConfig, user: &str, pass: &str) -> bool {
    if config.username.eq_ignore_ascii_case("anonymous") {
        user.eq_ignore_ascii_case("anonymous") || user.eq_ignore_ascii_case("ftp")
    } else {
        user == config.username && pass == config.password
    }
}

fn ftp_path(root: &Path, current: &Path) -> String {
    if let Ok(path) = current.strip_prefix(root) {
        let parts: Vec<_> = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect();
        if parts.is_empty() {
            "/".to_string()
        } else {
            let joined = parts.join("/");
            format!("/{}", joined)
        }
    } else {
        "/".to_string()
    }
}

fn resolve_path(root: &Path, current: &Path, raw_path: &str) -> Result<PathBuf> {
    let normalized = raw_path.replace('\\', "/");
    let mut candidate = if normalized.starts_with('/') {
        root.to_path_buf()
    } else {
        current.to_path_buf()
    };

    for component in normalized.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                if candidate != *root {
                    candidate.pop();
                }
            }
            chunk => candidate.push(chunk),
        }
    }

    if !candidate.starts_with(root) {
        bail!("Access outside of root is not permitted");
    }
    Ok(candidate)
}

fn enter_passive_mode(control_addr: SocketAddr, peer_addr: SocketAddr) -> Result<PassiveListener> {
    let reply_ip = match (control_addr, peer_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(peer)) => {
            resolve_passive_reply_ip(*local.ip(), *peer.ip(), peer.port())?
        }
        (SocketAddr::V4(local), SocketAddr::V6(_)) => {
            let ip = *local.ip();
            if ip.is_unspecified() || ip.is_loopback() {
                bail!("IPv6 clients require EPSV");
            } else {
                ip
            }
        }
        (SocketAddr::V6(_), _) => {
            bail!("IPv6 control connections are not supported");
        }
    };

    let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .context("Failed to bind data socket")?;
    let reply_port = listener
        .local_addr()
        .context("Failed to read data socket address")?
        .port();

    Ok(PassiveListener {
        listener,
        reply_ip,
        reply_port,
    })
}

impl PassiveListener {
    fn accept(self) -> Result<TcpStream> {
        let (stream, _) = self.listener.accept()?;
        Ok(stream)
    }
}

fn extract_path_argument(argument: &str) -> &str {
    let trimmed = argument.trim();
    if trimmed.starts_with('-') {
        let mut parts = trimmed.split_whitespace();
        while let Some(part) = parts.next() {
            if !part.starts_with('-') {
                return part;
            }
        }
        ""
    } else {
        trimmed
    }
}

fn send_directory_listing(path: &Path, data_stream: &mut TcpStream) -> Result<()> {
    if path.is_file() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("unknown"));
        let metadata = path.metadata()?;
        let line = format_list_line(&name, metadata.len(), metadata.is_dir());
        data_stream.write_all(line.as_bytes())?;
        data_stream.write_all(b"\r\n")?;
        data_stream.flush()?;
        return Ok(());
    }

    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let line = format_list_line(&name, metadata.len(), metadata.is_dir());
        data_stream.write_all(line.as_bytes())?;
        data_stream.write_all(b"\r\n")?;
    }
    data_stream.flush()?;
    Ok(())
}

fn format_list_line(name: &str, size: u64, is_dir: bool) -> String {
    let file_type = if is_dir { 'd' } else { '-' };
    // Simple, consistent listing (permissions and dates are placeholders).
    format!("{file_type}rwxr-xr-x 1 user group {size:>10} Jan 01 00:00 {name}")
}

fn send_file(path: &Path, data_stream: &mut TcpStream, transfer_type: TransferType) -> Result<()> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    match transfer_type {
        TransferType::Binary => {
            let _ = std::io::copy(&mut file, data_stream)?;
        }
        TransferType::Ascii => {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let mut prev = 0u8;
            for &byte in &buffer {
                if byte == b'\n' && prev != b'\r' {
                    data_stream.write_all(b"\r\n")?;
                } else if byte != b'\r' {
                    data_stream.write_all(&[byte])?;
                } else {
                    data_stream.write_all(&[byte])?;
                }
                prev = byte;
            }
        }
    }
    data_stream.flush()?;
    Ok(())
}

fn receive_file(path: &Path, data_stream: &mut TcpStream) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    std::io::copy(data_stream, &mut file)?;
    file.flush()?;
    Ok(())
}

fn resolve_passive_reply_ip(
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    peer_port: u16,
) -> Result<Ipv4Addr> {
    if !local_ip.is_unspecified() && !local_ip.is_loopback() {
        return Ok(local_ip);
    }

    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("Failed to bind helper UDP socket for PASV detection")?;
    udp.connect(SocketAddr::new(IpAddr::V4(peer_ip), peer_port))
        .context("Failed to connect helper UDP socket to client")?;
    let bound_addr = udp
        .local_addr()
        .context("Failed to read helper UDP socket address")?;

    if let SocketAddr::V4(bound_v4) = bound_addr {
        let candidate = *bound_v4.ip();
        if !candidate.is_unspecified() && !candidate.is_loopback() {
            return Ok(candidate);
        }
    }

    bail!("Unable to determine a routable IPv4 address for passive mode");
}
