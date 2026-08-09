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
            if rule.include_in_china {
                lists
                    .entry("china".to_string())
                    .or_default()
                    .insert(owner.prefix);
            }
        }
    }
    for (asset, rule) in &config.assets {
        let basenames = if rule.outputs.is_empty() {
            vec![asset.clone()]
        } else {
            rule.outputs.clone()
        };
        for basename in basenames {
            lists.entry(basename).or_default();
        }
    }
    lists.entry("china".to_string()).or_default();

    for (basename, prefixes) in lists {
        write_prefix_family(&staging, &basename, &prefixes)?;
    }
    write_jsonl(
        &staging.join(&config.settings.metadata_files.owner),
        classified.iter().map(|(owner, _, _)| owner),
    )?;
    write_jsonl(
        &staging.join(&config.settings.metadata_files.asn),
        classified.iter().map(|(_, asn, _)| asn),
    )?;
    write_jsonl(
        &staging.join(&config.settings.metadata_files.path),
        classified.iter().map(|(_, _, path)| path),
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

fn write_jsonl<'a, T: Serialize + 'a>(
    path: &Path,
    values: impl Iterator<Item = &'a T>,
) -> Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    for value in values {
        serde_json::to_writer(&mut writer, value)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn write_manifest(dir: &Path, classified: usize) -> Result<()> {
    let files: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    write_json(
        &dir.join("manifest.json"),
        &serde_json::json!({
            "schema_version": 1,
            "classified_prefixes": classified,
            "files": files,
        }),
    )
}
