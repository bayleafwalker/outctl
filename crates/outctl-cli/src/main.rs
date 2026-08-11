use std::process::ExitCode;

fn main() -> ExitCode {
    match outctl_cli::parse_args(std::env::args().skip(1)) {
        Ok(outctl_cli::Request::Capabilities) => {
            println!("{}", outctl_cli::capabilities_output());
            ExitCode::SUCCESS
        }
        Ok(outctl_cli::Request::Version) => {
            println!("{}", outctl_cli::version_output());
            ExitCode::SUCCESS
        }
        Ok(outctl_cli::Request::Help) => {
            print!("{}", outctl_cli::HELP_OUTPUT);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("outctl-native: {}", error.message());
            ExitCode::from(2)
        }
    }
}
