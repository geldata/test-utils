use std::{path::PathBuf, str::FromStr};

use once_cell::sync::Lazy;
use test_utils::{cmd_execute::DebugCommand, server::ServerInstance};
use dtor::dtor;

pub static SERVER: Lazy<ServerInstance> = Lazy::new(start);

fn start() -> ServerInstance {
    let server = ServerInstance::start();
    server.apply_schema(&PathBuf::from_str("./tests/dbschema").unwrap());
    server
}

#[dtor]
unsafe fn stop_server() {
    SERVER.stop();
}

#[test]
fn test_01() {
    assert!(SERVER.info.port > 1000);

    SERVER
        .cli()
        .arg("query")
        .arg("--output-format=tab-separated")
        .arg("SELECT sys::get_current_database()")
        .execute_and_print_errors(None, "a simple query");
}
