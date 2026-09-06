use std::path::PathBuf;

use anyhow::Result;
use china_asset_pipeline::pipeline::{
    ExtractBgpOptions, PipelineOptions, extract_bgp, merge_generate, run,
};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "china-asset-pipeline",
    about = "Classify BGP-announced Chinese network assets with RIR WHOIS and dynamic rules"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Generate(GenerateArgs),
    ExtractBgp(ExtractBgpArgs),
    MergeGenerate(MergeGenerateArgs),
}

#[derive(Debug, Args)]
struct GenerateArgs {
    #[arg(long = "mrt-file", required = true)]
    mrt_files: Vec<PathBuf>,
    #[command(flatten)]
    generation: GenerationArgs,
}

#[derive(Debug, Args)]
struct ExtractBgpArgs {
    #[arg(long = "mrt-file", required = true)]
    mrt_files: Vec<PathBuf>,
    #[arg(long = "rules", default_value = "operators.yaml")]
    rules: PathBuf,
    #[arg(long = "shard-index")]
    shard_index: u32,
    #[arg(long = "shard-count")]
    shard_count: u32,
    #[arg(long = "artifact", default_value = "bgp-shard.json")]
    artifact: PathBuf,
}

#[derive(Debug, Args)]
struct MergeGenerateArgs {
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<PathBuf>,
    #[command(flatten)]
    generation: GenerationArgs,
}

#[derive(Debug, Args)]
struct GenerationArgs {
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
    match Cli::parse().command {
        Command::Generate(args) => {
            let summary = run(&args.mrt_files, pipeline_options(args.generation))?;
            eprintln!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::ExtractBgp(args) => {
            if args.shard_count == 0 || args.shard_index >= args.shard_count {
                anyhow::bail!("shard index/count must be valid");
            }
            extract_bgp(ExtractBgpOptions {
                rule_file: args.rules,
                mrt_files: args.mrt_files,
                shard: (args.shard_index, args.shard_count),
                artifact_path: args.artifact,
            })?;
        }
        Command::MergeGenerate(args) => {
            let summary = merge_generate(pipeline_options(args.generation), &args.artifacts)?;
            eprintln!("{}", serde_json::to_string_pretty(&summary)?);
        }
    }
    Ok(())
}

fn pipeline_options(args: GenerationArgs) -> PipelineOptions {
    PipelineOptions {
        rule_file: args.rules,
        whois_files: args.whois_files,
        geo_file: args.geo_file,
        output_dir: args.output,
    }
}
