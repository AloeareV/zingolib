use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use log::{error, info};

use zingoconfig::{Network, ZingoConfig};
use zingolib::{commands, create_on_data_dir, lightclient::LightClient};

pub mod regtest;
mod version;

#[macro_export]
macro_rules! configure_clapapp {
    ( $freshapp: expr ) => {
    $freshapp.version(version::VERSION)
            .arg(Arg::with_name("nosync")
                .help("By default, zingo-cli will sync the wallet at startup. Pass --nosync to prevent the automatic sync at startup.")
                .long("nosync")
                .short('n')
                .takes_value(false))
            .arg(Arg::with_name("recover")
                .long("recover")
                .help("Attempt to recover the seed from the wallet")
                .takes_value(false))
            .arg(Arg::with_name("password")
                .long("password")
                .help("When recovering seed, specify a password for the encrypted wallet")
                .takes_value(true))
            .arg(Arg::with_name("seed")
                .short('s')
                .long("seed")
                .value_name("seed_phrase")
                .help("Create a new wallet with the given 24-word seed phrase. Will fail if wallet already exists")
                .takes_value(true))
            .arg(Arg::with_name("birthday")
                .long("birthday")
                .value_name("birthday")
                .help("Specify wallet birthday when restoring from seed. This is the earlist block height where the wallet has a transaction.")
                .takes_value(true))
            .arg(Arg::with_name("server")
                .long("server")
                .value_name("server")
                .help("Lightwalletd server to connect to.")
                .takes_value(true)
                .default_value(zingoconfig::DEFAULT_SERVER)
                .takes_value(true))
            .arg(Arg::with_name("data-dir")
                .long("data-dir")
                .value_name("data-dir")
                .help("Absolute path to use as data directory")
                .takes_value(true))
            .arg(Arg::with_name("regtest")
                .long("regtest")
                .value_name("regtest")
                .help("Regtest mode")
                .takes_value(false))
            .arg(Arg::with_name("no-clean")
                .long("no-clean")
                .value_name("no-clean")
                .help("Don't clean regtest state before running. Regtest mode only")
                .takes_value(false))
            .arg(Arg::with_name("COMMAND")
                .help("Command to execute. If a command is not specified, zingo-cli will start in interactive mode.")
                .required(false)
                .index(1))
            .arg(Arg::with_name("PARAMS")
                .help("Params to execute command with. Run the 'help' command to get usage help.")
                .required(false)
                .multiple(true))
    };
}

pub struct ArgDispatcher<'a> {
    clean_regtest_data: bool,
    command: Option<&'a str>,
    params: Vec<&'a str>,
    maybe_server: Option<String>,
    maybe_data_dir: Option<String>,
    seed: Option<String>,
    birthday: u64,
    regtest_mode_enabled: bool,
    nosync: Option<String>,
}

impl<'a> ArgDispatcher<'a> {
    pub fn parse_args() -> Self {
        // Get command line arguments
        use clap::{Arg, Command};
        let fresh_app = Command::new("Zingo CLI");
        let configured_app = configure_clapapp!(fresh_app);
        let matches = configured_app.get_matches();

        let command = matches.get_one::<Option<&str>>("COMMAND").unwrap().clone();
        let params = matches.get_one::<Vec<&str>>("PARAMS").unwrap().clone();

        let maybe_server = matches.value_of("server").map(|s| s.to_string());

        let maybe_data_dir = matches.value_of("data-dir").map(|s| s.to_string());

        let seed = matches.value_of("seed").map(|s| s.to_string());
        let maybe_birthday = matches.get_one::<Option<&str>>("birthday").unwrap().clone();

        if seed.is_some() && maybe_birthday.is_none() {
            eprintln!("ERROR!");
            eprintln!("Please specify the wallet birthday (eg. '--birthday 600000') to restore from seed." );
            panic!("This should be the block height where the wallet was created. If you don't remember the block height, you can pass '--birthday 0' to scan from the start of the blockchain.");
        }

        let birthday = match maybe_birthday.unwrap_or("0").parse::<u64>() {
            Ok(b) => b,
            Err(e) => {
                panic!(
                    "Couldn't parse birthday. This should be a block number. Error={}",
                    e
                );
            }
        };
        let regtest_mode_enabled = matches.is_present("regtest");
        let clean_regtest_data = !matches.is_present("no-clean");
        let nosync = matches.get_one::<Option<String>>("nosync").unwrap().clone();
        ArgDispatcher {
            clean_regtest_data,
            command,
            params,
            maybe_server,
            maybe_data_dir,
            seed,
            birthday,
            regtest_mode_enabled,
            nosync,
        }
    }

    pub fn launch_and_validate_server(&self) -> http::Uri {
        let server = if self.regtest_mode_enabled {
            regtest::launch(self.clean_regtest_data);
            ZingoConfig::get_server_or_default(Some("http://127.0.0.1".to_string()))
            // do the regtest
        } else {
            ZingoConfig::get_server_or_default(self.maybe_server.clone())
        };

        // Test to make sure the server has all of scheme, host and port
        if server.scheme_str().is_none() || server.host().is_none() || server.port().is_none() {
            panic!(
                "Please provide the --server parameter as [scheme]://[host]:[port].\nYou provided: {}",
                server
            );
        };
        server
    }
    pub fn startup(
        &self,
        server: http::Uri,
    ) -> std::io::Result<(Sender<(String, Vec<String>)>, Receiver<String>)> {
        // Try to get the configuration
        let (config, latest_block_height) =
            create_on_data_dir(server.clone(), self.maybe_data_dir.clone())?;

        // Diagnostic check for regtest flag and network in config, panic if mis-matched.
        if self.regtest_mode_enabled && config.chain == Network::Regtest {
            info!("regtest detected and network set correctly!");
        } else if self.regtest_mode_enabled && config.chain != Network::Regtest {
            eprintln!("Regtest flag detected, but unexpected network set! Exiting.");
            panic!("Regtest Network Problem");
        } else if config.chain == Network::Regtest {
            panic!("WARNING! regtest network in use but no regtest flag recognized!");
        }

        let lightclient = match self.seed.clone() {
            Some(phrase) => Arc::new(LightClient::new_from_phrase(
                phrase,
                &config,
                self.birthday,
                false,
            )?),
            None => {
                if config.wallet_exists() {
                    Arc::new(LightClient::read_from_disk(&config)?)
                } else {
                    info!("Creating a new wallet");
                    // Create a wallet with height - 100, to protect against reorgs
                    Arc::new(LightClient::new(
                        &config,
                        latest_block_height.saturating_sub(100),
                    )?)
                }
            }
        };

        // Initialize logging
        lightclient.init_logging()?;

        // Print startup Messages
        info!(""); // Blank line
        info!("Starting Zingo-CLI");
        info!("Light Client config {:?}", config);

        info!(
            "Lightclient connecting to {}",
            config.server.read().unwrap()
        );

        // At startup, run a sync.
        if self.nosync.is_none() {
            let update = commands::do_user_command("sync", &vec![], lightclient.as_ref());
            info!("{}", update);
        }

        // Start the command loop
        let (command_transmitter, resp_receiver) = command_loop(lightclient.clone());

        Ok((command_transmitter, resp_receiver))
    }
}
/// This function is only tested against Linux.
pub fn report_permission_error() {
    let user = std::env::var("USER").expect("Unexpected error reading value of $USER!");
    let home = std::env::var("HOME").expect("Unexpected error reading value of $HOME!");
    let current_executable =
        std::env::current_exe().expect("Unexpected error reporting executable path!");
    eprintln!("USER: {}", user);
    eprintln!("HOME: {}", home);
    eprintln!("Executable: {}", current_executable.display());
    if home == "/" {
        eprintln!(
            "User {} must have permission to write to '{}.zcash/' .",
            user, home
        );
    } else {
        eprintln!(
            "User {} must have permission to write to '{}/.zcash/' .",
            user, home
        );
    }
}

pub fn start_interactive(
    command_transmitter: Sender<(String, Vec<String>)>,
    resp_receiver: Receiver<String>,
) {
    // `()` can be used when no completer is required
    let mut rl = rustyline::Editor::<()>::new();

    info!("Ready!");

    let send_command = |cmd: String, args: Vec<String>| -> String {
        command_transmitter.send((cmd.clone(), args)).unwrap();
        match resp_receiver.recv() {
            Ok(s) => s,
            Err(e) => {
                let e = format!("Error executing command {}: {}", cmd, e);
                eprintln!("{}", e);
                error!("{}", e);
                return "".to_string();
            }
        }
    };

    let info = send_command("info".to_string(), vec![]);
    let chain_name = json::parse(&info).unwrap()["chain_name"]
        .as_str()
        .unwrap()
        .to_string();

    loop {
        // Read the height first
        let height = json::parse(&send_command(
            "height".to_string(),
            vec!["false".to_string()],
        ))
        .unwrap()["height"]
            .as_i64()
            .unwrap();

        let readline = rl.readline(&format!(
            "({}) Block:{} (type 'help') >> ",
            chain_name, height
        ));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                // Parse command line arguments
                let mut cmd_args = match shellwords::split(&line) {
                    Ok(args) => args,
                    Err(_) => {
                        println!("Mismatched Quotes");
                        continue;
                    }
                };

                if cmd_args.is_empty() {
                    continue;
                }

                let cmd = cmd_args.remove(0);
                let args: Vec<String> = cmd_args;

                println!("{}", send_command(cmd, args));

                // Special check for Quit command.
                if line == "quit" {
                    break;
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("CTRL-C");
                info!("CTRL-C");
                println!("{}", send_command("save".to_string(), vec![]));
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("CTRL-D");
                info!("CTRL-D");
                println!("{}", send_command("save".to_string(), vec![]));
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}

pub fn command_loop(
    lightclient: Arc<LightClient>,
) -> (Sender<(String, Vec<String>)>, Receiver<String>) {
    let (command_transmitter, command_receiver) = channel::<(String, Vec<String>)>();
    let (resp_transmitter, resp_receiver) = channel::<String>();

    let lc = lightclient.clone();
    std::thread::spawn(move || {
        LightClient::start_mempool_monitor(lc.clone());

        loop {
            if let Ok((cmd, args)) = command_receiver.recv() {
                let args = args.iter().map(|s| s.as_ref()).collect();

                let cmd_response = commands::do_user_command(&cmd, &args, lc.as_ref());
                resp_transmitter.send(cmd_response).unwrap();

                if cmd == "quit" {
                    info!("Quit");
                    break;
                }
            } else {
                break;
            }
        }
    });

    (command_transmitter, resp_receiver)
}
