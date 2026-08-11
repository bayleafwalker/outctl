use outctl_engine::presentation::{
    render_capture_files, PersistenceMode, PresentationMode, PresentationOptions, SpillBuffer,
};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn render_once(stdout: &std::path::Path, stderr: &std::path::Path) -> (u128, usize, bool) {
    let options = PresentationOptions {
        mode: PresentationMode::Auto,
        max_bytes: 64 * 1024,
        max_lines: 1_200,
        max_estimated_tokens: 12_000,
        full_if_bytes: 32 * 1024,
        ..PresentationOptions::default()
    };
    let started = Instant::now();
    let result = render_capture_files(stdout, stderr, "benchmark", &options)
        .expect("render benchmark fixture");
    let elapsed = started.elapsed().as_millis();
    assert!(result.exposed_bytes <= options.max_bytes);
    assert!(result.exposed_lines <= options.max_lines);
    assert!(result.estimated_tokens <= options.max_estimated_tokens);
    assert!(result.omission);
    assert!(result
        .body
        .as_deref()
        .is_some_and(|body| body.contains("ERROR benchmark-marker")));
    (elapsed, result.exposed_bytes, result.omission)
}

fn baseline_scan(path: &std::path::Path) -> (Duration, u64) {
    let started = Instant::now();
    let mut file = File::open(path).expect("open baseline fixture");
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer).expect("read baseline fixture");
        if read == 0 {
            break;
        }
        bytes += read as u64;
    }
    (started.elapsed(), bytes)
}

fn main() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("outctl-w4-bench-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("create benchmark directory");
    let stdout = root.join("stdout.raw");
    let stderr = root.join("stderr.raw");

    // Generate the large candidate incrementally so the benchmark itself does
    // not construct an 8 MiB Vec before exercising the streaming renderer.
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&stdout)
        .expect("create stdout fixture");
    let mut writer = BufWriter::new(file);
    for index in 0..200_000 {
        writeln!(writer, "routine line {index}").expect("write routine line");
    }
    writeln!(writer, "ERROR benchmark-marker").expect("write candidate line");
    writer.flush().expect("flush stdout fixture");
    fs::write(&stderr, b"warning: benchmark fixture\n").expect("write stderr fixture");

    let (baseline_elapsed, baseline_bytes) = baseline_scan(&stdout);
    let mut elapsed = Vec::new();
    for _ in 0..5 {
        let (rendered_ms, exposed, omitted) = render_once(&stdout, &stderr);
        assert!(exposed > 0 && omitted);
        elapsed.push(rendered_ms);
    }
    let min_ms = elapsed.iter().copied().min().unwrap_or_default();
    let max_ms = elapsed.iter().copied().max().unwrap_or_default();
    println!(
        "w4-presentation raw_bytes={baseline_bytes} baseline_ms={} render_ms_min={min_ms} render_ms_max={max_ms}",
        baseline_elapsed.as_millis()
    );

    let safe_stdout = root.join("safe-stdout.raw");
    let safe_stderr = root.join("safe-stderr.raw");
    fs::write(&safe_stdout, b"small\n").expect("write safe stdout fixture");
    fs::write(&safe_stderr, b"").expect("write safe stderr fixture");
    let safe = render_capture_files(
        &safe_stdout,
        &safe_stderr,
        "safe-small",
        &PresentationOptions {
            mode: PresentationMode::Auto,
            full_if_bytes: 64,
            ..PresentationOptions::default()
        },
    )
    .expect("render safe-small fixture");
    assert_eq!(safe.mode, "safe");
    assert_ne!(safe.savings.reason, "safe-small-output-is-cheaper");

    for mode in [
        PresentationMode::Compact,
        PresentationMode::Projected,
        PresentationMode::Metadata,
    ] {
        let result = render_capture_files(
            &stdout,
            &stderr,
            mode.as_str(),
            &PresentationOptions {
                mode,
                persistence: PersistenceMode::HostPersistent,
                ..PresentationOptions::default()
            },
        )
        .expect("render explicit mode");
        assert_eq!(result.mode, mode.as_str());
    }

    let tiny = PresentationOptions {
        max_bytes: 1,
        max_lines: 1,
        max_estimated_tokens: 1,
        ..PresentationOptions::default()
    };
    assert!(tiny.validate().is_err());

    let spill_path = root.join("bounded-spill.raw");
    let mut spill = SpillBuffer::with_max_bytes(1024, 64 * 1024, Some(&spill_path))
        .expect("create bounded spill buffer");
    let chunk = [b'x'; 4096];
    for _ in 0..16 {
        spill.write(&chunk).expect("write bounded spill buffer");
    }
    assert!(spill.spilled());
    assert_eq!(
        spill
            .read_prefix(64 * 1024)
            .expect("read bounded spill")
            .len(),
        64 * 1024
    );
    assert!(!spill_path.exists());

    fs::remove_dir_all(root).expect("remove benchmark directory");
}
