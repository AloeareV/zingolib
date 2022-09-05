mod regtest;
use log::error;
use zingo_cli::{report_permission_error, start_interactive, startup};

pub fn main() {
    let argdispatcher = zingo_cli::ArgDispatcher::parse_args();
    let server = argdispatcher.launch_and_validate_server();
    let startup_chan = argdispatcher.startup(server);
    let (command_transmitter, resp_receiver) = match startup_chan {
        Ok(c) => c,
        Err(e) => {
            let emsg = format!("Error during startup:{}\nIf you repeatedly run into this issue, you might have to restore your wallet from your seed phrase.", e);
            eprintln!("{}", emsg);
            error!("{}", emsg);
            if cfg!(target_os = "unix") {
                match e.raw_os_error() {
                    Some(13) => report_permission_error(),
                    _ => {}
                }
            };
            return;
        }
    };

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
