use std::{path::PathBuf, str::FromStr};

use once_cell::sync::Lazy;
use test_utils::server::ServerInstance;

pub static SERVER: Lazy<ServerInstance> = Lazy::new(start);

fn start() -> ServerInstance {
    shutdown_hooks::add_shutdown_hook(stop_server);

    let server = ServerInstance::start();
    server.apply_schema(&PathBuf::from_str("./tests/dbschema").unwrap());
    server
}

extern "C" fn stop_server() {
    SERVER.stop();
}

#[test]
fn test_01() {
    assert!(SERVER.version_major > 0);
    assert!(SERVER.info.port > 1000);

    assert!(SERVER
        .cli_admin()
        .arg("query")
        .arg("--output-format=tab-separated")
        .arg("SELECT sys::get_current_database()")
        .status()
        .expect("cannot run edgedb CLI")
        .success());
}
