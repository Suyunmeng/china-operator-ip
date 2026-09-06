use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, BufWriter, Read},
    path::Path,
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::BgpObservation;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpSource {
    pub filename: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BgpShardArtifact {
    pub schema_version: u32,
    pub rules_sha256: String,
    pub sources: Vec<BgpSource>,
    pub shard_index: u32,
    pub shard_count: u32,
    pub observations: BTreeMap<IpNet, BgpObservation>,
    pub announced_prefixes: Option<BTreeSet<IpNet>>,
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn write_artifact(path: &Path, artifact: &BgpShardArtifact) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("failed to create shard artifact {}", path.display()))?;
    serde_json::to_writer(BufWriter::new(file), artifact)
        .with_context(|| format!("failed to write shard artifact {}", path.display()))?;
    Ok(())
}

pub fn read_artifact(path: &Path) -> Result<BgpShardArtifact> {
    let file = File::open(path)
        .with_context(|| format!("failed to open shard artifact {}", path.display()))?;
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("failed to read shard artifact {}", path.display()))
}
