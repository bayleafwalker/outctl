//! Argument and rendering surface for the metadata-only native binary.

#[derive(Debug, Eq, PartialEq)]
pub enum Request {
    Capabilities,
    Version,
    Help,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CliError {
    message: String,
}

impl CliError {
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Parse only metadata commands.  In particular, `run` is rejected before
/// any action can be selected; this crate has no command-execution path.
pub fn parse_args<I>(arguments: I) -> Result<Request, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(Request::Capabilities);
    };

    match first.as_str() {
        "capabilities" | "--capabilities" => {
            let mut format_flag = false;
            while let Some(argument) = arguments.next() {
                match argument.as_str() {
                    "--json" => format_flag = true,
                    "--format=json" => format_flag = true,
                    "--format" if arguments.next().as_deref() == Some("json") => {
                        format_flag = true;
                    }
                    _ => {
                        return Err(CliError {
                            message: format!(
                                "unsupported capabilities option {argument:?}; only JSON output is available"
                            ),
                        });
                    }
                }
            }
            let _ = format_flag;
            Ok(Request::Capabilities)
        }
        "version" | "--version" => {
            if arguments.next().is_some() {
                return Err(CliError {
                    message: "version does not accept additional arguments".to_owned(),
                });
            }
            Ok(Request::Version)
        }
        "help" | "--help" => Ok(Request::Help),
        "run" | "exec" => Err(CliError {
            message: "command execution is unsupported in the W2 native skeleton".to_owned(),
        }),
        other => Err(CliError {
            message: format!("unsupported native command {other:?}"),
        }),
    }
}

pub fn capabilities_output() -> String {
    outctl_engine::capabilities().to_json()
}

pub fn version_output() -> &'static str {
    outctl_engine::ENGINE_VERSION
}

pub const HELP_OUTPUT: &str =
    "outctl-native capabilities [--json]\noutctl-native version\nmetadata-only W2 native skeleton; command execution is unsupported\n";

#[cfg(test)]
mod tests {
    use super::{capabilities_output, parse_args, version_output, Request};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn capabilities_is_the_default_metadata_path() {
        assert_eq!(parse_args(args(&[])), Ok(Request::Capabilities));
        assert_eq!(
            parse_args(args(&["capabilities", "--json"])),
            Ok(Request::Capabilities)
        );
        assert!(capabilities_output().contains("\"direct_argv\":true"));
    }

    #[test]
    fn execution_requests_are_rejected_without_a_runner() {
        let error = parse_args(args(&["run", "echo", "unsafe-to-run"])).unwrap_err();
        assert!(error.message().contains("execution is unsupported"));
    }

    #[test]
    fn version_is_metadata_only() {
        assert!(!version_output().is_empty());
        assert_eq!(parse_args(args(&["version"])), Ok(Request::Version));
    }
}
