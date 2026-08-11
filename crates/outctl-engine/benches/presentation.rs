use outctl_engine::presentation::{render_capture_files, PresentationMode, PresentationOptions};
use std::fs;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn main() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("outctl-w4-bench-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("create benchmark directory");
    let stdout = root.join("stdout.raw");
    let stderr = root.join("stderr.raw");
    let mut output = Vec::with_capacity(8 * 1024 * 1024);
    for index in 0..200_000 {
        output.extend_from_slice(format!("routine line {index}\n").as_bytes());
    }
    output.extend_from_slice(b"ERROR benchmark-marker\n");
    fs::write(&stdout, output).expect("write benchmark fixture");
    fs::write(&stderr, b"warning: benchmark fixture\n").expect("write stderr fixture");
    let options = PresentationOptions {
        mode: PresentationMode::Auto,
        max_bytes: 64 * 1024,
        max_lines: 1_200,
        max_estimated_tokens: 12_000,
        ..PresentationOptions::default()
    };
    let started = Instant::now();
    let result = render_capture_files(&stdout, &stderr, "benchmark", &options)
        .expect("render benchmark fixture");
    let elapsed_ms = started.elapsed().as_millis();
    println!(
        "w4-presentation bytes={} exposed={} tokens={} omitted={} elapsed_ms={elapsed_ms}",
        result.raw_bytes, result.exposed_bytes, result.estimated_tokens, result.omission
    );
    let _ = fs::remove_dir_all(root);
}
