use std::path::PathBuf;

use anyhow::Result;
use china_asset_pipeline::pipeline::{PipelineOptions, run};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "china-asset-pipeline",
    about = "Classify BGP-announced Chinese network assets with RIR WHOIS and dynamic rules"
)]
struct Args {
    #[arg(long = "mrt-file", required = true)]
    mrt_files: Vec<PathBuf>,
    #[arg(long = "whois-file", required = true)]
    whois_files: Vec<PathBuf>,
    #[arg(long = "rules", default_value = "operators.yaml")]
    rules: PathBuf,
    #[arg(long = "geo-file")]
    geo_file: Option<PathBuf>,
    #[arg(long = "output", default_value = "result")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let summary = run(PipelineOptions {
        rule_file: args.rules,
        mrt_files: args.mrt_files,
        whois_files: args.whois_files,
        geo_file: args.geo_file,
        output_dir: args.output,
    })?;
    eprintln!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
