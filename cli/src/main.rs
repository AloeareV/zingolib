mod regtest;

pub fn main() {
    let argdispatcher = zingo_cli::ArgDispatcher::parse_args();
    let server = argdispatcher.launch_and_validate_server();
    argdispatcher.start_interactive_or_dispatch_command(server);
}
