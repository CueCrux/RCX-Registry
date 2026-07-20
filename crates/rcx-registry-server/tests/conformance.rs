#[path = "support/conformance_vectors.rs"]
mod conformance_vectors;

#[test]
fn checked_in_v1_vectors_match_production_code_paths() {
    conformance_vectors::check_vectors()
        .unwrap_or_else(|error| panic!("RCX Protocol Spec v1 conformance failure:\n{error}"));
}
