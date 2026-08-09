use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use bgpkit_parser::BgpkitParser;
use ipnet::IpNet;

use crate::model::{BgpObservation, OriginUpstreamEvidence};

#[derive(Default)]
struct Aggregate {
    origin_asns: BTreeSet<u32>,
    paths: BTreeMap<Vec<u32>, usize>,
    upstream_evidence: BTreeMap<u32, OriginEvidenceAggregate>,
    peers: BTreeSet<u32>,
    collectors: BTreeSet<String>,
    last_seen: i64,
}

#[derive(Default)]
struct OriginEvidenceAggregate {
    immediate_upstream_asns: BTreeSet<u32>,
    usable_observation: bool,
    unusable_observation: bool,
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
            let origins: BTreeSet<u32> = origins.iter().copied().map(u32::from).collect();
            let path_asns = elem
                .as_path
                .as_ref()
                .and_then(|path| path.to_u32_vec_opt(true));
            let aggregate = prefixes.entry(elem.prefix.prefix).or_default();
            aggregate.origin_asns.extend(origins.iter().copied());
            if let Some(path_asns) = path_asns.as_ref() {
                *aggregate.paths.entry(path_asns.clone()).or_default() += 1;
            }
            record_upstream_evidence(aggregate, path_asns.as_deref(), &origins);
            aggregate.peers.insert(u32::from(elem.peer_asn));
            aggregate.collectors.insert(collector.clone());
            aggregate.last_seen = aggregate.last_seen.max(elem.timestamp.floor() as i64);
        }
    }

    Ok(prefixes
        .into_iter()
        .map(|(prefix, aggregate)| {
            let asn_path = select_representative_path(&aggregate.paths, &aggregate.origin_asns);
            let mut origin_asns = asn_path
                .last()
                .copied()
                .into_iter()
                .collect::<BTreeSet<_>>();
            if origin_asns.is_empty() && aggregate.origin_asns.len() == 1 {
                origin_asns.extend(aggregate.origin_asns.iter().copied());
            }
            let transit_asns = asn_path
                .iter()
                .copied()
                .filter(|asn| !origin_asns.contains(asn))
                .collect();
            let upstream_evidence = aggregate
                .upstream_evidence
                .into_iter()
                .map(|(origin, evidence)| {
                    (
                        origin,
                        OriginUpstreamEvidence {
                            immediate_upstream_asns: evidence.immediate_upstream_asns,
                            complete: evidence.usable_observation && !evidence.unusable_observation,
                        },
                    )
                })
                .collect();
            (
                prefix,
                BgpObservation {
                    prefix,
                    origin_asns,
                    observed_origin_asns: aggregate.origin_asns,
                    asn_path,
                    transit_asns,
                    upstream_evidence,
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
        .map(|(path, _)| path.clone())
        .unwrap_or_default()
}

fn record_upstream_evidence(
    aggregate: &mut Aggregate,
    path: Option<&[u32]>,
    origins: &BTreeSet<u32>,
) {
    let Some((origin, upstream)) = path.and_then(|path| immediate_upstream(path, origins)) else {
        for origin in origins {
            aggregate
                .upstream_evidence
                .entry(*origin)
                .or_default()
                .unusable_observation = true;
        }
        return;
    };
    let evidence = aggregate.upstream_evidence.entry(origin).or_default();
    evidence.immediate_upstream_asns.insert(upstream);
    evidence.usable_observation = true;
}

fn immediate_upstream(path: &[u32], origins: &BTreeSet<u32>) -> Option<(u32, u32)> {
    if origins.len() != 1 {
        return None;
    }
    let origin = *origins.first()?;
    if path.last().copied()? != origin {
        return None;
    }
    let mut end = path.len();
    while end > 0 && path[end - 1] == origin {
        end -= 1;
    }
    let upstream = *path.get(end.checked_sub(1)?)?;
    if upstream == origin || path[..end - 1].contains(&origin) {
        return None;
    }
    Some((origin, upstream))
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
    fn immediate_upstream_requires_unambiguous_origin_adjacency() {
        assert_eq!(
            immediate_upstream(&[64500, 13335, 65000], &BTreeSet::from([65000])),
            Some((65000, 13335))
        );
        assert_eq!(
            immediate_upstream(&[64500, 13335, 65000, 65000], &BTreeSet::from([65000])),
            Some((65000, 13335))
        );
        assert_eq!(
            immediate_upstream(&[64500, 13335, 64501, 65000], &BTreeSet::from([65000])),
            Some((65000, 64501))
        );
        assert_eq!(
            immediate_upstream(&[64500, 13335, 4134, 13335], &BTreeSet::from([13335])),
            None
        );
        assert_eq!(
            immediate_upstream(&[64500, 13335], &BTreeSet::from([13335, 64501])),
            None
        );
    }

    #[test]
    fn conflicting_or_unusable_observations_prevent_complete_evidence() {
        let mut aggregate = Aggregate::default();
        let origins = BTreeSet::from([65000]);
        record_upstream_evidence(&mut aggregate, Some(&[64500, 13335, 65000]), &origins);
        record_upstream_evidence(&mut aggregate, Some(&[64500, 64501, 65000]), &origins);
        let evidence = aggregate.upstream_evidence.get(&65000).unwrap();
        assert_eq!(
            evidence.immediate_upstream_asns,
            BTreeSet::from([13335, 64501])
        );
        assert!(evidence.usable_observation);
        assert!(!evidence.unusable_observation);

        record_upstream_evidence(&mut aggregate, None, &origins);
        assert!(
            aggregate
                .upstream_evidence
                .get(&65000)
                .unwrap()
                .unusable_observation
        );
    }

    #[test]
    fn unusable_path_does_not_create_synthetic_adjacency() {
        let mut aggregate = Aggregate::default();
        record_upstream_evidence(&mut aggregate, None, &BTreeSet::from([13335, 64501]));
        assert!(
            aggregate
                .upstream_evidence
                .values()
                .all(|evidence| evidence.immediate_upstream_asns.is_empty())
        );
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
