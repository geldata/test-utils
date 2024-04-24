use std::borrow::Borrow;


#[test]
fn run_the_server() {
    let server = test_utils::server::SERVER.borrow();

    assert!(server.version_major > 0);
    assert!(server.info.port > 1000);
}
