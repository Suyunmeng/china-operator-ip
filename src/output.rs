use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Serialize;

use crate::{
    asn_graph::FamilyMembership,
    config::Config,
    model::{PrefixAsnMetadata, PrefixMetadata, PrefixPathMetadata},
};

const METADATA_SHARD_COUNT: usize = 16;

pub fn write_all(
    output_dir: &Path,
    config: &Config,
    classified: &[(PrefixMetadata, PrefixAsnMetadata, PrefixPathMetadata)],
    families: &BTreeMap<u32, FamilyMembership>,
) -> Result<()> {
    let staging = output_dir.with_extension("staging");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    if output_dir.exists() && !output_dir.is_dir() {
        anyhow::bail!("output path {} is not a directory", output_dir.display());
    }

    let mut lists: BTreeMap<String, BTreeSet<IpNet>> = BTreeMap::new();
    for (owner, _, _) in classified {
        if let Some(rule) = config.assets.get(&owner.asset) {
            for output in &rule.outputs {
                lists
                    .entry(output.clone())
                    .or_default()
                    .insert(owner.prefix);
            }
            if owner.include_in_china && owner.announced {
                lists
                    .entry("china".to_string())
                    .or_default()
                    .insert(owner.prefix);
            }
        }
    }
    for rule in config.assets.values() {
        for basename in &rule.outputs {
            lists.entry(basename.clone()).or_default();
        }
    }
    lists.entry("china".to_string()).or_default();

    for (basename, prefixes) in lists {
        write_prefix_family(&staging, &basename, &prefixes)?;
    }
    write_jsonl_shards(
        &staging.join(&config.settings.metadata_files.owner),
        classified.iter().map(|(owner, _, _)| owner),
        |owner| owner.prefix,
    )?;
    write_jsonl_shards(
        &staging.join(&config.settings.metadata_files.asn),
        classified.iter().map(|(_, asn, _)| asn),
        |asn| asn.prefix,
    )?;
    write_jsonl_shards(
        &staging.join(&config.settings.metadata_files.path),
        classified.iter().map(|(_, _, path)| path),
        |path| path.prefix,
    )?;
    write_json(
        &staging.join(&config.settings.metadata_files.family),
        &families.values().collect::<Vec<_>>(),
    )?;
    write_manifest(&staging, classified.len())?;

    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::rename(&staging, output_dir).with_context(|| {
        format!(
            "failed to atomically move {} to {}",
            staging.display(),
            output_dir.display()
        )
    })?;
    Ok(())
}

fn write_prefix_family(dir: &Path, basename: &str, prefixes: &BTreeSet<IpNet>) -> Result<()> {
    let v4: Vec<_> = prefixes
        .iter()
        .filter(|prefix| matches!(prefix, IpNet::V4(_)))
        .collect();
    let v6: Vec<_> = prefixes
        .iter()
        .filter(|prefix| matches!(prefix, IpNet::V6(_)))
        .collect();
    write_lines(&dir.join(format!("{basename}.txt")), v4.iter().copied())?;
    write_lines(&dir.join(format!("{basename}6.txt")), v6.iter().copied())?;
    write_lines(&dir.join(format!("{basename}46.txt")), prefixes.iter())?;
    Ok(())
}

fn write_lines<'a>(path: &Path, values: impl Iterator<Item = &'a IpNet>) -> Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    for value in values {
        writeln!(writer, "{value}")?;
    }
    writer.flush()?;
    Ok(())
}

fn write_jsonl_shards<'a, T: Serialize + 'a>(
    dir: &Path,
    values: impl Iterator<Item = &'a T>,
    prefix: impl Fn(&T) -> IpNet,
) -> Result<()> {
    fs::create_dir_all(dir)?;
    let mut shards = (0..METADATA_SHARD_COUNT)
        .map(|_| Vec::new())
        .collect::<Vec<_>>();
    for value in values {
        shards[metadata_shard(prefix(value))].push(value);
    }
    for (index, values) in shards.iter_mut().enumerate() {
        values.sort_by_key(|value| prefix(value));
        write_jsonl(
            &dir.join(format!("{index:02x}.jsonl")),
            values.iter().copied(),
        )?;
    }
    Ok(())
}

fn metadata_shard(prefix: IpNet) -> usize {
    let bytes = match prefix {
        IpNet::V4(prefix) => prefix.network().octets().to_vec(),
        IpNet::V6(prefix) => prefix.network().octets().to_vec(),
    };
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    }) as usize
        % METADATA_SHARD_COUNT
}

fn write_jsonl<'a, T: Serialize + 'a>(
    path: &Path,
    values: impl Iterator<Item = &'a T>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    for value in values {
        serde_json::to_writer(&mut writer, value)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn write_manifest(dir: &Path, classified: usize) -> Result<()> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    write_json(
        &dir.join("manifest.json"),
        &serde_json::json!({
            "schema_version": 5,
            "classified_prefixes": classified,
            "files": files,
        }),
    )
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("failed to relativize {}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            files.push(relative);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whois_only_prefix_stays_out_of_china_aggregate() {
        let mut config: Config = serde_yaml::from_str(
            r#"
version: 1
assets:
  cloud:
    type: cloud
    owner: Cloud
    priority: 1
    require_announced: false
    match:
      whois_org: [Cloud]
      country: [CN]
    outputs: [cloud]
"#,
        )
        .unwrap();
        config.validate_and_compile().unwrap();
        let prefix = "198.51.100.0/24";
        let owner = PrefixMetadata {
            prefix: prefix.parse().unwrap(),
            announced: false,
            ip_version: 4,
            asset: "cloud".to_string(),
            origin_asn: Vec::new(),
            asn_path: Vec::new(),
            owner: "Cloud".to_string(),
            asset_type: "cloud".to_string(),
            include_in_china: true,
            operator_family: None,
            observed_immediate_upstream_asn: Vec::new(),
            immediate_upstream_evidence_complete: false,
            observed_final_upstream_asn: Vec::new(),
            whois_org: Some("Cloud".to_string()),
            org_id: None,
            maintainer: Vec::new(),
            netname: None,
            rir: "APNIC".to_string(),
            country: Some("CN".to_string()),
            geo_location: None,
            match_rule: "cloud:owner".to_string(),
            match_source: "whois-owner".to_string(),
            confidence_score: 94,
            last_seen: 0,
        };
        let asn = PrefixAsnMetadata {
            prefix: prefix.parse().unwrap(),
            origin_asn: Vec::new(),
            observed_origin_asn: Vec::new(),
            origin_asn_family: Vec::new(),
            peer_asn: Vec::new(),
            collectors: Vec::new(),
            last_seen: 0,
        };
        let path = PrefixPathMetadata {
            prefix: prefix.parse().unwrap(),
            origin_asn: Vec::new(),
            asn_path: Vec::new(),
            transit_asn: Vec::new(),
            observed_immediate_upstream_asn: Vec::new(),
            immediate_upstream_evidence_complete: false,
            observed_final_upstream_asn: Vec::new(),
            peer_asn: Vec::new(),
            collectors: Vec::new(),
            last_seen: 0,
        };
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result");
        write_all(&output, &config, &[(owner, asn, path)], &BTreeMap::new()).unwrap();
        assert_eq!(
            fs::read_to_string(output.join("cloud.txt")).unwrap(),
            "198.51.100.0/24\n"
        );
        assert!(
            fs::read_to_string(output.join("china.txt"))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn shared_output_basename_aggregates_assets() {
        let mut config: Config = serde_yaml::from_str(
            r#"
version: 1
assets:
  first:
    type: ixp
    owner: First
    priority: 2
    match:
      origin_asn: [64500]
    outputs: [ixp]
  second:
    type: ixp
    owner: Second
    priority: 1
    match:
      origin_asn: [64501]
    outputs: [ixp]
"#,
        )
        .unwrap();
        config.validate_and_compile().unwrap();
        let record = |prefix: &str, asset: &str| {
            (
                PrefixMetadata {
                    prefix: prefix.parse().unwrap(),
                    ip_version: if prefix.contains(':') { 6 } else { 4 },
                    asset: asset.to_string(),
                    origin_asn: vec![64500],
                    asn_path: vec![64500],
                    owner: asset.to_string(),
                    asset_type: "ixp".to_string(),
                    include_in_china: true,
                    announced: true,
                    operator_family: None,
                    observed_immediate_upstream_asn: Vec::new(),
                    immediate_upstream_evidence_complete: false,
                    observed_final_upstream_asn: Vec::new(),
                    whois_org: Some(asset.to_string()),
                    org_id: None,
                    maintainer: Vec::new(),
                    netname: Some(asset.to_string()),
                    rir: "APNIC".to_string(),
                    country: Some("CN".to_string()),
                    geo_location: None,
                    match_rule: format!("{asset}:owner"),
                    match_source: "whois-owner".to_string(),
                    confidence_score: 95,
                    last_seen: 1,
                },
                PrefixAsnMetadata {
                    prefix: prefix.parse().unwrap(),
                    origin_asn: vec![64500],
                    observed_origin_asn: vec![64500],
                    origin_asn_family: Vec::new(),
                    peer_asn: Vec::new(),
                    collectors: Vec::new(),
                    last_seen: 1,
                },
                PrefixPathMetadata {
                    prefix: prefix.parse().unwrap(),
                    origin_asn: vec![64500],
                    asn_path: vec![64500],
                    transit_asn: Vec::new(),
                    observed_immediate_upstream_asn: Vec::new(),
                    immediate_upstream_evidence_complete: false,
                    observed_final_upstream_asn: Vec::new(),
                    peer_asn: Vec::new(),
                    collectors: Vec::new(),
                    last_seen: 1,
                },
            )
        };
        let classified = vec![
            record("203.0.113.0/24", "first"),
            record("198.51.100.0/24", "second"),
            record("2001:db8::/32", "first"),
        ];
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result");
        write_all(&output, &config, &classified, &BTreeMap::new()).unwrap();
        let list = fs::read_to_string(output.join("ixp.txt")).unwrap();
        assert!(list.contains("198.51.100.0/24"));
        assert!(list.contains("203.0.113.0/24"));
        let china = fs::read_to_string(output.join("china.txt")).unwrap();
        assert!(china.contains("198.51.100.0/24"));
        assert!(china.contains("203.0.113.0/24"));
        assert_eq!(
            fs::read_to_string(output.join("china6.txt")).unwrap(),
            "2001:db8::/32\n"
        );
        let china46 = fs::read_to_string(output.join("china46.txt")).unwrap();
        assert!(china46.contains("198.51.100.0/24"));
        assert!(china46.contains("203.0.113.0/24"));
        assert!(china46.contains("2001:db8::/32"));

        let expected_prefixes: BTreeSet<_> = classified
            .iter()
            .map(|(owner, _, _)| owner.prefix)
            .collect();
        for basename in ["prefix-owner", "prefix-asn", "prefix-path"] {
            let metadata_dir = output.join("metadata").join(basename);
            let mut prefixes = BTreeSet::new();
            for index in 0..METADATA_SHARD_COUNT {
                let shard = metadata_dir.join(format!("{index:02x}.jsonl"));
                assert!(
                    shard.is_file(),
                    "missing metadata shard {}",
                    shard.display()
                );
                let mut previous = None;
                for line in fs::read_to_string(shard).unwrap().lines() {
                    let row: serde_json::Value = serde_json::from_str(line).unwrap();
                    let prefix: IpNet = row["prefix"].as_str().unwrap().parse().unwrap();
                    if let Some(previous) = previous {
                        assert!(prefix > previous, "metadata shard is not sorted");
                    }
                    previous = Some(prefix);
                    assert!(prefixes.insert(prefix), "duplicate metadata prefix");
                }
            }
            assert_eq!(prefixes, expected_prefixes);
        }

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["schema_version"], 5);
        let files = manifest["files"].as_array().unwrap();
        let file_names: Vec<_> = files.iter().map(|file| file.as_str().unwrap()).collect();
        assert!(file_names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            files
                .iter()
                .any(|file| file == "metadata/prefix-owner/00.jsonl")
        );
        assert!(files.iter().any(|file| file == "metadata/asn-family.json"));
    }
}
