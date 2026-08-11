use std::process::ExitCode;

fn main() -> ExitCode {
    match outctl_cli::parse_args(std::env::args_os().skip(1)).and_then(outctl_cli::execute) {
        Ok((output, code)) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("outctl-native: {}", error.message());
            ExitCode::from(error.exit_code())
        }
    }
}
