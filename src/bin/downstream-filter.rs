use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "downstream-filter is retired: transit ASNs cannot determine prefix ownership; use china-asset-pipeline"
    );
    ExitCode::FAILURE
}
