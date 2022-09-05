mod regtest;
use log::error;
use zingo_cli::{report_permission_error, start_interactive};

pub fn main() {
    let argdispatcher = zingo_cli::ArgDispatcher::parse_args();
    let server = argdispatcher.launch_and_validate_server();
    let Ok((command_transmitter, resp_receiver)) = argdispatcher.startup_and_check(server);

    if command.is_none() {
        start_interactive(command_transmitter, resp_receiver);
    } else {
        command_transmitter
            .send((
                command.unwrap().to_string(),
                params
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            ))
            .unwrap();

        match resp_receiver.recv() {
            Ok(s) => println!("{}", s),
            Err(e) => {
                let e = format!("Error executing command {}: {}", command.unwrap(), e);
                eprintln!("{}", e);
                error!("{}", e);
            }
        }

        // Save before exit
        command_transmitter
            .send(("save".to_string(), vec![]))
            .unwrap();
        resp_receiver.recv().unwrap();
    }
}
