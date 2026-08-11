//! Native Linux command capture and v1-compatible evidence reads.

pub mod capture;
pub mod retrieval;
mod storage;

use capture::MAX_CAPTURE_BYTES;
use outctl_contracts::{
    ContractVersions, EngineCapabilities, EngineFeatures, EngineLimits, EngineMetadata,
    ENGINE_CAPABILITIES_SCHEMA_VERSION,
};

pub const ENGINE_ID: &str = "rust-w3-capture";

/// The native package version is also the reported engine version.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Return the capabilities implemented by the W3 process/capture slice.
pub fn capabilities() -> EngineCapabilities {
    EngineCapabilities {
        schema_version: ENGINE_CAPABILITIES_SCHEMA_VERSION.to_owned(),
        engine: EngineMetadata {
            id: ENGINE_ID.to_owned(),
            version: ENGINE_VERSION.to_owned(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        },
        contract_versions: ContractVersions {
            // W3 still does not consume the v2 run or policy contracts. It
            // does read Python v1 captures without claiming to write v1.
            run_request: Vec::new(),
            policy_snapshot: Vec::new(),
            run_result: Vec::new(),
            capture_manifest: vec!["v1alpha1".to_owned()],
        },
        features: EngineFeatures {
            // W1 freezes direct argv and one-version-back as schema-level
            // baseline invariants.  Empty contract lists above keep this
            // metadata-only binary out of execution/read negotiation.
            direct_argv: true,
            explicit_shell: false,
            stdin: false,
            retrieval: true,
            one_version_back_read: true,
        },
        limits: EngineLimits {
            max_argv_items: 256,
            max_capture_bytes: MAX_CAPTURE_BYTES,
            max_projection_bytes: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{capabilities, ENGINE_ID, MAX_CAPTURE_BYTES};

    #[test]
    fn skeleton_capabilities_are_conservative() {
        let value = capabilities();
        assert_eq!(value.engine.id, ENGINE_ID);
        assert!(value.features.direct_argv);
        assert!(!value.features.explicit_shell);
        assert!(!value.features.stdin);
        assert!(value.features.retrieval);
        assert!(value.features.one_version_back_read);
        assert!(value.contract_versions.run_request.is_empty());
        assert!(value.contract_versions.policy_snapshot.is_empty());
        assert!(value.contract_versions.run_result.is_empty());
        assert_eq!(value.contract_versions.capture_manifest, ["v1alpha1"]);
        assert_eq!(value.limits.max_capture_bytes, MAX_CAPTURE_BYTES);
        assert_eq!(value.limits.max_projection_bytes, 1);
    }

    #[test]
    fn capability_serialization_is_metadata_only() {
        let json = capabilities().to_json();
        assert!(json.contains("\"schema_version\":\"vuoro.outctl.engine-capabilities/v2\""));
        assert!(json.contains("\"direct_argv\":true"));
        assert!(json.contains("\"explicit_shell\":false"));
        assert!(json.contains("\"retrieval\":true"));
    }
}
