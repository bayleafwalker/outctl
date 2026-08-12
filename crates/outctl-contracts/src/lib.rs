//! Small, dependency-free Rust representations of the W1 v2 contracts.
//!
//! W2 only needs the capability document.  The other v2 families remain
//! represented by their language-neutral schemas until the corresponding
//! implementation waves add behavior.

use std::fmt::Write as _;

pub const ENGINE_CAPABILITIES_SCHEMA_VERSION: &str = "vuoro.outctl.engine-capabilities/v2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineMetadata {
    pub id: String,
    pub version: String,
    pub platform: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractVersions {
    pub run_request: Vec<String>,
    pub policy_snapshot: Vec<String>,
    pub run_result: Vec<String>,
    pub capture_manifest: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineFeatures {
    pub direct_argv: bool,
    pub explicit_shell: bool,
    pub stdin: bool,
    pub retrieval: bool,
    pub one_version_back_read: bool,
    pub pty: bool,
    pub live_output: bool,
    pub parent_shell_state: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineLimits {
    pub max_argv_items: u64,
    pub max_capture_bytes: u64,
    pub max_projection_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineCapabilities {
    pub schema_version: String,
    pub engine: EngineMetadata,
    pub contract_versions: ContractVersions,
    pub features: EngineFeatures,
    pub limits: EngineLimits,
}

impl EngineCapabilities {
    /// Serialize the capability contract in stable schema-field order.
    ///
    /// This intentionally avoids a runtime or a third-party serialization
    /// dependency in the W2 metadata path.  The contract is small and all
    /// values are escaped as JSON strings or emitted as typed primitives.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":{},\"engine\":{{\"id\":{},\"version\":{},\"platform\":{}}},\"contract_versions\":{{\"run_request\":{},\"policy_snapshot\":{},\"run_result\":{},\"capture_manifest\":{}}},\"features\":{{\"direct_argv\":{},\"explicit_shell\":{},\"stdin\":{},\"retrieval\":{},\"one_version_back_read\":{},\"pty\":{},\"live_output\":{},\"parent_shell_state\":{}}},\"limits\":{{\"max_argv_items\":{},\"max_capture_bytes\":{},\"max_projection_bytes\":{}}}}}",
            json_string(&self.schema_version),
            json_string(&self.engine.id),
            json_string(&self.engine.version),
            json_string(&self.engine.platform),
            json_string_array(&self.contract_versions.run_request),
            json_string_array(&self.contract_versions.policy_snapshot),
            json_string_array(&self.contract_versions.run_result),
            json_string_array(&self.contract_versions.capture_manifest),
            self.features.direct_argv,
            self.features.explicit_shell,
            self.features.stdin,
            self.features.retrieval,
            self.features.one_version_back_read,
            self.features.pty,
            self.features.live_output,
            self.features.parent_shell_state,
            self.limits.max_argv_items,
            self.limits.max_capture_bytes,
            self.limits.max_projection_bytes,
        )
    }
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn json_string_array(values: &[String]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&json_string(value));
    }
    output.push(']');
    output
}

#[cfg(test)]
mod tests {
    use super::{EngineCapabilities, EngineFeatures, EngineLimits, EngineMetadata};

    #[test]
    fn capability_json_escapes_metadata_strings() {
        let capabilities = EngineCapabilities {
            schema_version: "schema".to_owned(),
            engine: EngineMetadata {
                id: "native\"skeleton".to_owned(),
                version: "0.1\n0".to_owned(),
                platform: "test".to_owned(),
            },
            contract_versions: super::ContractVersions {
                run_request: vec!["v2".to_owned()],
                policy_snapshot: vec!["v2".to_owned()],
                run_result: vec!["v2".to_owned()],
                capture_manifest: vec!["v1alpha1".to_owned(), "v2".to_owned()],
            },
            features: EngineFeatures {
                direct_argv: true,
                explicit_shell: false,
                stdin: false,
                retrieval: false,
                one_version_back_read: true,
                pty: false,
                live_output: false,
                parent_shell_state: false,
            },
            limits: EngineLimits {
                max_argv_items: 1,
                max_capture_bytes: 1,
                max_projection_bytes: 1,
            },
        };

        let json = capabilities.to_json();
        assert!(json.contains("native\\\"skeleton"));
        assert!(json.contains("0.1\\n0"));
        assert!(!json.contains("native\"skeleton"));
    }
}
