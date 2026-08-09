use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result};
use ipnet::IpNet;

use crate::model::GeoLocation;

#[derive(Debug, Clone, Default)]
pub struct GeoIndex {
    entries: Vec<(IpNet, GeoLocation)>,
}

impl GeoIndex {
    pub fn load_optional(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let mut entries = Vec::new();
        for (line_number, line) in BufReader::new(
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
        )
        .lines()
        .enumerate()
        {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split(',').map(str::trim).collect();
            if fields.len() < 2 {
                anyhow::bail!(
                    "invalid geo CSV at {}:{}: expected prefix,country[,subdivision,city]",
                    path.display(),
                    line_number + 1
                );
            }
            entries.push((
                fields[0].parse().with_context(|| {
                    format!(
                        "invalid geo prefix at {}:{}",
                        path.display(),
                        line_number + 1
                    )
                })?,
                GeoLocation {
                    country: optional(fields[1]),
                    subdivision: fields.get(2).and_then(|value| optional(value)),
                    city: fields.get(3).and_then(|value| optional(value)),
                },
            ));
        }
        entries.sort_by_key(|(prefix, _)| (prefix.network(), prefix.prefix_len()));
        Ok(Self { entries })
    }

    pub fn lookup(&self, prefix: IpNet) -> Option<&GeoLocation> {
        self.entries
            .iter()
            .filter(|(candidate, _)| candidate.contains(&prefix.network()))
            .max_by_key(|(candidate, _)| candidate.prefix_len())
            .map(|(_, location)| location)
    }
}

fn optional(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
