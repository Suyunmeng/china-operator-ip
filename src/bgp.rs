use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use bgpkit_parser::BgpkitParser;
use ipnet::IpNet;

use crate::model::BgpObservation;

#[derive(Default)]
struct Aggregate {
    origin_asns: BTreeSet<u32>,
    paths: BTreeMap<Vec<u32>, usize>,
    peers: BTreeSet<u32>,
    collectors: BTreeSet<String>,
    last_seen: i64,
}

pub fn load_ribs(paths: &[PathBuf]) -> Result<BTreeMap<IpNet, BgpObservation>> {
    let mut prefixes: BTreeMap<IpNet, Aggregate> = BTreeMap::new();

    for path in paths {
        let collector = collector_name(path);
        let source = path.to_string_lossy();
        let parser = BgpkitParser::new(&source)
            .with_context(|| format!("failed to open MRT file {}", path.display()))?;
        for elem in parser.into_elem_iter() {
            if !elem.is_announcement() {
                continue;
            }
            let Some(origins) = elem.origin_asns.as_deref() else {
                continue;
            };
            if origins.is_empty() {
                continue;
            }
            let path_asns = elem
                .as_path
                .as_ref()
                .and_then(|path| path.to_u32_vec_opt(true))
                .unwrap_or_else(|| origins.iter().copied().map(u32::from).collect());
            let aggregate = prefixes.entry(elem.prefix.prefix).or_default();
            aggregate
                .origin_asns
                .extend(origins.iter().copied().map(u32::from));
            *aggregate.paths.entry(path_asns).or_default() += 1;
            aggregate.peers.insert(u32::from(elem.peer_asn));
            aggregate.collectors.insert(collector.clone());
            aggregate.last_seen = aggregate.last_seen.max(elem.timestamp.floor() as i64);
        }
    }

    Ok(prefixes
        .into_iter()
        .map(|(prefix, aggregate)| {
            let asn_path = select_representative_path(&aggregate.paths, &aggregate.origin_asns);
            let mut origin_asns = BTreeSet::new();
            if let Some(origin) = asn_path.last() {
                origin_asns.insert(*origin);
            }
            let transit_asns = asn_path
                .iter()
                .copied()
                .filter(|asn| !origin_asns.contains(asn))
                .collect();
            (
                prefix,
                BgpObservation {
                    prefix,
                    origin_asns,
                    observed_origin_asns: aggregate.origin_asns,
                    asn_path,
                    transit_asns,
                    peer_asns: aggregate.peers,
                    collectors: aggregate.collectors,
                    last_seen: aggregate.last_seen,
                },
            )
        })
        .collect())
}

fn select_representative_path(
    paths: &BTreeMap<Vec<u32>, usize>,
    origins: &BTreeSet<u32>,
) -> Vec<u32> {
    paths
        .iter()
        .filter(|(path, _)| path.last().is_some_and(|asn| origins.contains(asn)))
        .max_by(|(left_path, left_count), (right_path, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_path.len().cmp(&left_path.len()))
                .then_with(|| right_path.cmp(left_path))
        })
        .or_else(|| paths.iter().max_by_key(|(_, count)| *count))
        .map(|(path, _)| path.clone())
        .unwrap_or_default()
}

fn collector_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .trim_start_matches("rib-")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_observed_short_valid_path_wins() {
        let paths = BTreeMap::from([
            (vec![64500, 4134], 2),
            (vec![64501, 64502, 4134], 2),
            (vec![64503, 4134], 1),
        ]);
        assert_eq!(
            select_representative_path(&paths, &BTreeSet::from([4134])),
            vec![64500, 4134]
        );
    }

    #[test]
    fn representative_path_selects_single_current_origin() {
        let paths = BTreeMap::from([(vec![64500, 4134], 5), (vec![64501, 64502], 1)]);
        let observed = BTreeSet::from([4134, 64502]);
        let path = select_representative_path(&paths, &observed);
        let origins = path.last().copied().into_iter().collect::<BTreeSet<_>>();
        let transit = path
            .iter()
            .copied()
            .filter(|asn| !origins.contains(asn))
            .collect::<BTreeSet<_>>();
        assert_eq!(origins, BTreeSet::from([4134]));
        assert_eq!(transit, BTreeSet::from([64500]));
        assert!(!transit.contains(&64502));
    }

    #[test]
    fn transit_asn_does_not_become_origin() {
        let path = [64500, 4134, 65001];
        let origins = BTreeSet::from([65001]);
        let transit: BTreeSet<_> = path
            .iter()
            .copied()
            .filter(|asn| !origins.contains(asn))
            .collect();
        assert!(transit.contains(&4134));
        assert!(!origins.contains(&4134));
    }
}
