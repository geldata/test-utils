use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::process;
use std::sync::Mutex;

use anyhow::Context;
use command_fds::{CommandFdExt, FdMapping};
use once_cell::sync::Lazy;

pub static SERVER: Lazy<ServerGuard> = Lazy::new(ServerGuard::start);

pub struct ServerGuard {
    pub info: ServerInfo,
    pub version_major: u8,
    process: Mutex<Option<process::Child>>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ServerInfo {
    pub port: u16,
    pub socket_dir: String,
    pub main_pid: i32,
    pub tls_cert_file: String,
    pub tls_cert_newly_generated: bool,
    pub jws_keys_newly_generated: bool,
    pub listen_addrs: Vec<(String, u16)>,
}

impl ServerGuard {
    pub fn start() -> ServerGuard {
        let bin_name = if let Ok(ver) = env::var("EDGEDB_MAJOR_VERSION") {
            format!("edgedb-server-{}", ver)
        } else {
            "edgedb-server".to_string()
        };

        let version_major = get_edgedb_server_version(&bin_name);

        let mut cmd = process::Command::new(&bin_name);
        cmd.env("EDGEDB_SERVER_SECURITY", "insecure_dev_mode");
        cmd.arg("--temp-dir");
        cmd.arg("--testmode");
        cmd.arg("--emit-server-status=fd://3");
        cmd.arg("--port=auto");
        cmd.arg("--tls-cert-mode=generate_self_signed");

        // pipe server status on fd 3 into a reader bellow
        let (status_read, status_write) = nix::unistd::pipe().unwrap();
        cmd.fd_mappings(vec![FdMapping {
            parent_fd: status_write,
            child_fd: 3,
        }])
        .unwrap();

        // pipe stderr into a buffer that's printed only when there is an error
        cmd.stderr(process::Stdio::piped());

        #[cfg(unix)]
        if nix::unistd::Uid::effective().as_raw() == 0 {
            use std::os::unix::process::CommandExt;
            // This is moslty true in vagga containers, so run edgedb/postgres
            // by any non-root user
            cmd.uid(1);
        }

        eprintln!("Starting {}...", bin_name);

        let mut process = cmd
            .spawn()
            .unwrap_or_else(|_| panic!("Can run {}", bin_name));

        shutdown_hooks::add_shutdown_hook(stop_server);

        // write log file
        let stdout = process.stderr.take().unwrap();
        std::thread::spawn(move || write_log_into_file(stdout));

        // wait for server to start
        let info = wait_for_server_status(status_read).unwrap();

        ServerGuard {
            info,
            version_major,
            process: Mutex::new(Some(process)),
        }
    }

    pub fn cli_admin(&self) -> process::Command {       
        let mut cmd = process::Command::new("edgedb");
        cmd.arg("--no-cli-update-check");
        cmd.arg("--admin");
        cmd.arg("--unix-path").arg(&self.info.socket_dir);
        cmd.arg("--port").arg(self.info.port.to_string());
        cmd.env("CLICOLOR", "0");
        cmd
    }

    fn stop(&self) {
        use nix::sys::signal;
        use nix::unistd::Pid;

        let Some(mut process) = self.process.lock().unwrap().take() else {
            return;
        };

        eprintln!("Stopping...");

        let pid = Pid::from_raw(process.id() as i32);
        if let Err(e) = signal::kill(pid, signal::Signal::SIGTERM) {
            eprintln!("could not send SIGTERM to edgedb-server: {:?}", e);
        }

        process.wait().ok();

        eprintln!("Stopped.");
    }
}

extern "C" fn stop_server() {
    SERVER.stop();
}

fn get_edgedb_server_version(bin_name: &str) -> u8 {
    let mut cmd = process::Command::new(bin_name);
    cmd.arg("--version");
    cmd.stdout(process::Stdio::piped());

    let mut process = cmd.spawn().with_context(|| format!("Cannot run executable {bin_name}")).unwrap();
    let server_stdout = process.stdout.take().expect("stdout is pipe");
    let buf = BufReader::new(server_stdout);

    let mut version_str = None;
    for line in buf.lines() {
        match line {
            Ok(line) => {
                if let Some(line) = line.strip_prefix("edgedb-server, version ") {
                    version_str = Some(line.split('+').next().unwrap().to_string());
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading from server: {}", e);
                break;
            }
        }
    }

    let version_str = version_str.unwrap();
    let major = version_str.split('.').next().unwrap();
    major.parse::<u8>().unwrap()
}

/// Reads the stream at file descriptor `status_read` until edgedb-server notifies that it is ready
fn wait_for_server_status(status_read: OwnedFd) -> anyhow::Result<ServerInfo> {
    eprintln!("Reading status...");

    let pipe = BufReader::new(File::from(status_read));
    let mut result = Err(anyhow::anyhow!("no server info emitted"));
    for line in pipe.lines() {
        match line {
            Ok(line) => {
                if let Some(data) = line.strip_prefix("READY=") {
                    eprintln!("READY={data}");
                    result = Ok(serde_json::from_str(data).expect("valid server data"));
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading from server: {}", e);
                result = Err(e.into());
                break;
            }
        }
    }
    result
}

/// Writes a stream to a log file in a temporary directory.
fn write_log_into_file(stream: impl std::io::Read) {
    let log_dir = env::temp_dir();

    let time_the_epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let mut log_file = log_dir.clone();
    let file_name = format!("edgedb-server-{time_the_epoch}.log").to_string();
    log_file.push(file_name);

    eprintln!("Writing server logs into {:?}", &log_file);

    std::fs::create_dir_all(&log_dir).unwrap();
    let mut log_file = File::create(log_file).unwrap();

    let mut reader = BufReader::new(stream);
    std::io::copy(&mut reader, &mut log_file).unwrap();
}
