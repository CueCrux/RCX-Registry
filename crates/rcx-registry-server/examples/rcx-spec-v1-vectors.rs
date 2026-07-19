#[path = "../tests/support/conformance_vectors.rs"]
mod conformance_vectors;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next();
    if args.next().is_some() {
        usage_and_exit();
    }

    let result = match mode.as_deref() {
        Some("--write") => conformance_vectors::write_vectors(),
        Some("--check") => conformance_vectors::check_vectors(),
        _ => usage_and_exit(),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: cargo run -p rcx-registry-server --example rcx-spec-v1-vectors -- \
         (--write|--check)"
    );
    std::process::exit(2);
}
