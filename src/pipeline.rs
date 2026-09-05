use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{
    asn_graph::infer_families,
    bgp::load_ribs,
    config::Config,
    geo::GeoIndex,
    model::{PrefixAsnMetadata, PrefixMetadata, PrefixPathMetadata},
    output::write_all,
    rpsl::WhoisIndex,
    rules::classify,
};

#[derive(Default)]
struct AnnouncedPrefixIndex {
    v4: BTreeSet<(u32, u8)>,
    v6: BTreeSet<(u128, u8)>,
}

impl AnnouncedPrefixIndex {
    fn from_prefixes(prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        let mut index = Self::default();
        for prefix in prefixes {
            match prefix {
                IpNet::V4(prefix) => {
                    index
                        .v4
                        .insert((u32::from(prefix.network()), prefix.prefix_len()));
                }
                IpNet::V6(prefix) => {
                    index
                        .v6
                        .insert((u128::from(prefix.network()), prefix.prefix_len()));
                }
            }
        }
        index
    }

    fn unannounced_fragments(&self, prefix: IpNet) -> Vec<IpNet> {
        self.announced_subprefixes(prefix)
            .into_iter()
            .fold(vec![prefix], |remaining, cut| {
                remaining
                    .into_iter()
                    .flat_map(|prefix| subtract_prefix(prefix, cut))
                    .collect()
            })
    }

    fn announced_subprefixes(&self, prefix: IpNet) -> BTreeSet<IpNet> {
        match prefix {
            IpNet::V4(prefix) => self
                .v4
                .range((u32::from(prefix.network()), 0)..=(v4_last_address(prefix), u8::MAX))
                .filter_map(|&(network, length)| {
                    let announced = Ipv4Net::new(Ipv4Addr::from(network), length).ok()?;
                    contains_prefix(IpNet::V4(prefix), IpNet::V4(announced))
                        .then_some(IpNet::V4(announced))
                })
                .collect(),
            IpNet::V6(prefix) => self
                .v6
                .range((u128::from(prefix.network()), 0)..=(v6_last_address(prefix), u8::MAX))
                .filter_map(|&(network, length)| {
                    let announced = Ipv6Net::new(Ipv6Addr::from(network), length).ok()?;
                    contains_prefix(IpNet::V6(prefix), IpNet::V6(announced))
                        .then_some(IpNet::V6(announced))
                })
                .collect(),
        }
    }
}

fn contains_prefix(outer: IpNet, inner: IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(outer), IpNet::V4(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
        }
        (IpNet::V6(outer), IpNet::V6(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
        }
        _ => false,
    }
}

fn subtract_prefix(prefix: IpNet, cut: IpNet) -> Vec<IpNet> {
    if prefix == cut {
        return Vec::new();
    }
    if !contains_prefix(prefix, cut) {
        return vec![prefix];
    }
    split_prefix(prefix)
        .into_iter()
        .flat_map(|child| {
            if contains_prefix(child, cut) {
                subtract_prefix(child, cut)
            } else {
                vec![child]
            }
        })
        .collect()
}

fn split_prefix(prefix: IpNet) -> [IpNet; 2] {
    match prefix {
        IpNet::V4(prefix) => {
            let length = prefix.prefix_len() + 1;
            let start = u32::from(prefix.network());
            let offset = 1_u32 << (32 - length);
            [
                IpNet::V4(Ipv4Net::new(Ipv4Addr::from(start), length).expect("valid subnet")),
                IpNet::V4(
                    Ipv4Net::new(Ipv4Addr::from(start + offset), length).expect("valid subnet"),
                ),
            ]
        }
        IpNet::V6(prefix) => {
            let length = prefix.prefix_len() + 1;
            let start = u128::from(prefix.network());
            let offset = 1_u128 << (128 - length);
            [
                IpNet::V6(Ipv6Net::new(Ipv6Addr::from(start), length).expect("valid subnet")),
                IpNet::V6(
                    Ipv6Net::new(Ipv6Addr::from(start + offset), length).expect("valid subnet"),
                ),
            ]
        }
    }
}

fn v4_last_address(prefix: Ipv4Net) -> u32 {
    u32::from(prefix.network()) | (u32::MAX >> prefix.prefix_len())
}

fn v6_last_address(prefix: Ipv6Net) -> u128 {
    u128::from(prefix.network()) | (u128::MAX >> prefix.prefix_len())
}

fn final_upstream_asns(config: &Config, observation: &crate::model::BgpObservation) -> Vec<u32> {
    let Some(china) = config.settings.china.as_ref() else {
        return Vec::new();
    };
    if observation.observed_asn_paths.is_empty() {
        return Vec::new();
    }
    let allowed: BTreeSet<_> = china.final_upstream_asn.iter().copied().collect();
    let mut upstreams_by_origin: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for path in &observation.observed_asn_paths {
        let origin = *path.last().expect("observed path has an Origin ASN");
        if let Some(upstream) = path.iter().rev().find(|asn| allowed.contains(asn)).copied() {
            upstreams_by_origin
                .entry(origin)
                .or_default()
                .insert(upstream);
        }
    }
    upstreams_by_origin.into_values().flatten().collect()
}

fn is_configured_china_asset(config: &Config, asset: &str) -> bool {
    config
        .settings
        .china
        .as_ref()
        .is_some_and(|china| china.assets.iter().any(|configured| configured == asset))
}

pub struct PipelineOptions {
    pub rule_file: PathBuf,
    pub mrt_files: Vec<PathBuf>,
    pub whois_files: Vec<PathBuf>,
    pub geo_file: Option<PathBuf>,
    pub output_dir: PathBuf,
}

pub fn run(options: PipelineOptions) -> Result<PipelineSummary> {
    let config = Config::load(&options.rule_file)?;
    let observations = load_ribs(&options.mrt_files)?;
    let announced_prefixes = AnnouncedPrefixIndex::from_prefixes(observations.keys().copied());
    if observations.is_empty() {
        anyhow::bail!("no announced origin prefixes found in the supplied MRT files");
    }
    let whois = WhoisIndex::load(&options.whois_files)?;
    if whois.is_empty() {
        anyhow::bail!("no RIR WHOIS inetnum/inet6num records were loaded");
    }
    let geo = GeoIndex::load_optional(options.geo_file.as_deref())?;
    let families = infer_families(&config, &observations, whois.asns());
    let non_announced_records: Vec<_> = whois
        .prefixes()
        .filter(|record| {
            record.country.as_deref().is_some_and(|country| {
                country.eq_ignore_ascii_case(&config.settings.domestic_country)
            })
        })
        .collect();
    let mut classified = Vec::new();
    let mut rejected_without_whois = 0;
    let mut rejected_unclassified = 0;

    for observation in observations.values() {
        let Some(owner_record) = whois.lookup(observation.prefix) else {
            rejected_without_whois += 1;
            continue;
        };
        let geo_location = geo.lookup(observation.prefix);
        let Some(classification) = classify(
            &config,
            Some(observation),
            Some(owner_record),
            whois.asns(),
            &families,
            geo_location,
        ) else {
            rejected_unclassified += 1;
            continue;
        };
        let observed_final_upstream_asn = final_upstream_asns(&config, observation);
        let include_in_china = is_configured_china_asset(&config, &classification.asset)
            || !observed_final_upstream_asn.is_empty();
        let family_names: Vec<_> = observation
            .origin_asns
            .iter()
            .filter_map(|asn| families.get(asn).map(|family| family.family.clone()))
            .collect();
        let upstream_evidence = observation
            .origin_asns
            .iter()
            .filter_map(|asn| observation.upstream_evidence.get(asn))
            .next();
        let observed_immediate_upstream_asn: Vec<u32> = upstream_evidence
            .map(|evidence| evidence.immediate_upstream_asns.iter().copied().collect())
            .unwrap_or_default();
        let immediate_upstream_evidence_complete =
            upstream_evidence.is_some_and(|evidence| evidence.complete);
        classified.push((
            PrefixMetadata {
                prefix: observation.prefix,
                announced: true,
                ip_version: if observation.prefix.addr().is_ipv4() {
                    4
                } else {
                    6
                },
                origin_asn: observation.origin_asns.iter().copied().collect(),
                observed_origin_asn: observation.observed_origin_asns.iter().copied().collect(),
                asset: classification.asset.clone(),
                asn_path: observation.asn_path.clone(),
                owner: classification.owner.clone(),
                asset_type: classification.asset_type.clone(),
                include_in_china,
                operator_family: classification.operator_family.clone(),
                observed_immediate_upstream_asn: observed_immediate_upstream_asn.clone(),
                immediate_upstream_evidence_complete,
                observed_final_upstream_asn: observed_final_upstream_asn.clone(),
                whois_org: owner_record.whois_org.clone(),
                org_id: owner_record.org_id.clone(),
                maintainer: owner_record.maintainers.clone(),
                netname: owner_record.netname.clone(),
                rir: owner_record.rir.clone(),
                country: owner_record.country.clone(),
                geo_location: geo_location.cloned(),
                match_rule: classification.match_rule.clone(),
                match_source: classification.match_source.clone(),
                confidence_score: classification.confidence_score,
                last_seen: observation.last_seen,
            },
            PrefixAsnMetadata {
                prefix: observation.prefix,
                origin_asn: observation.origin_asns.iter().copied().collect(),
                observed_origin_asn: observation.observed_origin_asns.iter().copied().collect(),
                origin_asn_family: family_names,
                peer_asn: observation.peer_asns.iter().copied().collect(),
                collectors: observation.collectors.iter().cloned().collect(),
                last_seen: observation.last_seen,
            },
            PrefixPathMetadata {
                prefix: observation.prefix,
                origin_asn: observation.origin_asns.iter().copied().collect(),
                asn_path: observation.asn_path.clone(),
                transit_asn: observation.transit_asns.iter().copied().collect(),
                observed_immediate_upstream_asn,
                immediate_upstream_evidence_complete,
                observed_final_upstream_asn,
                peer_asn: observation.peer_asns.iter().copied().collect(),
                collectors: observation.collectors.iter().cloned().collect(),
                last_seen: observation.last_seen,
            },
        ));
    }
    for record in non_announced_records {
        let prefix = record
            .prefix
            .expect("WHOIS prefix record must contain a prefix");
        let geo_location = geo.lookup(prefix);
        let Some(classification) = classify(
            &config,
            None,
            Some(record),
            whois.asns(),
            &families,
            geo_location,
        ) else {
            continue;
        };
        let Some(rule) = config.assets.get(&classification.asset) else {
            continue;
        };
        if rule.require_announced {
            continue;
        }
        let prefixes = if rule.exclude_announced {
            announced_prefixes.unannounced_fragments(prefix)
        } else if observations.contains_key(&prefix) {
            Vec::new()
        } else {
            vec![prefix]
        };
        for prefix in prefixes {
            classified.push((
                PrefixMetadata {
                    prefix,
                    announced: false,
                    ip_version: if prefix.addr().is_ipv4() { 4 } else { 6 },
                    asset: classification.asset.clone(),
                    origin_asn: Vec::new(),
                    observed_origin_asn: Vec::new(),
                    asn_path: Vec::new(),
                    owner: classification.owner.clone(),
                    asset_type: classification.asset_type.clone(),
                    include_in_china: false,
                    operator_family: classification.operator_family.clone(),
                    observed_immediate_upstream_asn: Vec::new(),
                    immediate_upstream_evidence_complete: false,
                    observed_final_upstream_asn: Vec::new(),
                    whois_org: record.whois_org.clone(),
                    org_id: record.org_id.clone(),
                    maintainer: record.maintainers.clone(),
                    netname: record.netname.clone(),
                    rir: record.rir.clone(),
                    country: record.country.clone(),
                    geo_location: geo_location.cloned(),
                    match_rule: classification.match_rule.clone(),
                    match_source: classification.match_source.clone(),
                    confidence_score: classification.confidence_score,
                    last_seen: 0,
                },
                PrefixAsnMetadata {
                    prefix,
                    origin_asn: Vec::new(),
                    observed_origin_asn: Vec::new(),
                    origin_asn_family: Vec::new(),
                    peer_asn: Vec::new(),
                    collectors: Vec::new(),
                    last_seen: 0,
                },
                PrefixPathMetadata {
                    prefix,
                    origin_asn: Vec::new(),
                    asn_path: Vec::new(),
                    transit_asn: Vec::new(),
                    observed_immediate_upstream_asn: Vec::new(),
                    immediate_upstream_evidence_complete: false,
                    observed_final_upstream_asn: Vec::new(),
                    peer_asn: Vec::new(),
                    collectors: Vec::new(),
                    last_seen: 0,
                },
            ));
        }
    }
    classified.sort_by_key(|(owner, _, _)| owner.prefix);
    write_all(&options.output_dir, &config, &classified, &families)?;

    Ok(PipelineSummary {
        announced_prefixes: observations.len(),
        classified_prefixes: classified.len(),
        rejected_without_whois,
        rejected_unclassified,
        asn_family_members: families.len(),
        per_asset: classified.iter().fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.0.asset.clone()).or_default() += 1;
            counts
        }),
    })
}

#[derive(Debug, serde::Serialize)]
pub struct PipelineSummary {
    pub announced_prefixes: usize,
    pub classified_prefixes: usize,
    pub rejected_without_whois: usize,
    pub rejected_unclassified: usize,
    pub asn_family_members: usize,
    pub per_asset: BTreeMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn china_config() -> Config {
        let yaml = r#"
version: 1
settings:
  china:
    assets: [configured]
    final_upstream_asn: [4134, 4809, 4837, 9929, 9808]
assets:
  configured:
    type: carrier
    owner: Configured Carrier
    priority: 2
    match:
      origin_asn: [64500]
  other:
    type: enterprise
    owner: Other Network
    priority: 1
    match:
      origin_asn: [56040]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
        config
    }

    fn observation(paths: impl IntoIterator<Item = Vec<u32>>) -> crate::model::BgpObservation {
        let observed_asn_paths: BTreeSet<_> = paths.into_iter().collect();
        let asn_path = observed_asn_paths.first().cloned().unwrap_or_default();
        crate::model::BgpObservation {
            prefix: "203.0.113.0/24".parse().unwrap(),
            origin_asns: BTreeSet::from([56040]),
            observed_origin_asns: BTreeSet::from([56040]),
            asn_path,
            observed_asn_paths,
            transit_asns: BTreeSet::new(),
            upstream_evidence: BTreeMap::new(),
            peer_asns: BTreeSet::new(),
            collectors: BTreeSet::new(),
            last_seen: 1,
        }
    }

    #[test]
    fn configured_asset_is_included_in_china() {
        assert!(is_configured_china_asset(&china_config(), "configured"));
        assert!(!is_configured_china_asset(&china_config(), "other"));
    }

    #[test]
    fn recursive_final_upstream_is_included_in_china() {
        let observation = observation([vec![4134, 134773, 56040]]);
        assert_eq!(
            final_upstream_asns(&china_config(), &observation),
            vec![4134]
        );
    }

    #[test]
    fn multiple_allowed_final_upstreams_are_included_in_china() {
        let observation = observation([vec![4134, 134773, 56040], vec![9808, 56040]]);
        assert_eq!(
            final_upstream_asns(&china_config(), &observation),
            vec![4134, 9808]
        );
    }

    #[test]
    fn anycast_prefix_is_included_when_one_origin_has_an_allowed_path() {
        let observation = observation([vec![4134, 134773, 56040], vec![3356, 56041]]);
        assert_eq!(
            final_upstream_asns(&china_config(), &observation),
            vec![4134]
        );
    }

    #[test]
    fn non_allowlisted_final_upstreams_exclude_prefix_from_china() {
        let observation = observation([vec![3356, 56040], vec![1299, 56041]]);
        assert!(final_upstream_asns(&china_config(), &observation).is_empty());
    }

    #[test]
    fn unannounced_fragments_remove_announced_subprefixes_only() {
        let index = AnnouncedPrefixIndex::from_prefixes([
            "161.248.0.0/16".parse().unwrap(),
            "161.248.137.0/24".parse().unwrap(),
        ]);
        assert_eq!(
            index.unannounced_fragments("161.248.136.0/23".parse().unwrap()),
            vec!["161.248.136.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn unannounced_fragments_remove_ipv6_subprefixes_only() {
        let index = AnnouncedPrefixIndex::from_prefixes([
            "2001:df4::/32".parse().unwrap(),
            "2001:df4:e141::/48".parse().unwrap(),
        ]);
        assert_eq!(
            index.unannounced_fragments("2001:df4:e140::/46".parse().unwrap()),
            vec![
                "2001:df4:e140::/48".parse().unwrap(),
                "2001:df4:e142::/47".parse().unwrap(),
            ]
        );
    }
}
