use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use anyhow::{Context, Result};
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
    shard::{
        BgpShardArtifact, BgpSource, SCHEMA_VERSION, read_artifact, sha256_file, write_artifact,
    },
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

fn final_upstream_asns(observation: &crate::model::BgpObservation) -> Vec<u32> {
    observation
        .observed_final_upstream_asns
        .iter()
        .copied()
        .collect()
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
    pub whois_files: Vec<PathBuf>,
    pub geo_file: Option<PathBuf>,
    pub output_dir: PathBuf,
}

pub struct ExtractBgpOptions {
    pub rule_file: PathBuf,
    pub mrt_files: Vec<PathBuf>,
    pub shard: (u32, u32),
    pub source_group: (u32, u32),
    pub artifact_path: PathBuf,
}

pub fn run(mrt_files: &[PathBuf], options: PipelineOptions) -> Result<PipelineSummary> {
    let config = Config::load(&options.rule_file)?;
    let allowed_final_upstream_asns = config
        .settings
        .china
        .as_ref()
        .map(|china| china.final_upstream_asn.iter().copied().collect())
        .unwrap_or_default();
    let (observations, announced_prefixes) = load_ribs(
        mrt_files,
        &allowed_final_upstream_asns,
        config.settings.min_bgp_peers,
        None,
        true,
    )?;
    generate(&config, &options, observations, announced_prefixes)
}

pub fn extract_bgp(options: ExtractBgpOptions) -> Result<()> {
    let config = Config::load(&options.rule_file)?;
    let allowed_final_upstream_asns = config
        .settings
        .china
        .as_ref()
        .map(|china| china.final_upstream_asn.iter().copied().collect())
        .unwrap_or_default();
    let (observations, announced_prefixes) = load_ribs(
        &options.mrt_files,
        &allowed_final_upstream_asns,
        0,
        Some(options.shard),
        options.shard.0 == 0,
    )?;
    write_artifact(
        &options.artifact_path,
        &BgpShardArtifact {
            schema_version: SCHEMA_VERSION,
            rules_sha256: sha256_file(&options.rule_file)?,
            sources: bgp_sources(&options.mrt_files)?,
            shard_index: options.shard.0,
            shard_count: options.shard.1,
            source_group_index: options.source_group.0,
            source_group_count: options.source_group.1,
            observations,
            announced_prefixes: (options.shard.0 == 0).then_some(announced_prefixes),
        },
    )
}

#[derive(Debug)]
struct MergedBgpArtifacts {
    observations: BTreeMap<IpNet, crate::model::BgpObservation>,
    announced_prefixes: BTreeSet<IpNet>,
}

pub fn merge_generate(
    options: PipelineOptions,
    artifact_paths: &[PathBuf],
) -> Result<PipelineSummary> {
    let config = Config::load(&options.rule_file)?;
    let artifacts = merge_bgp_artifacts(
        artifact_paths,
        &sha256_file(&options.rule_file)?,
        config.settings.min_bgp_peers,
    )?;
    generate(
        &config,
        &options,
        artifacts.observations,
        artifacts.announced_prefixes,
    )
}

fn merge_bgp_artifacts(
    artifact_paths: &[PathBuf],
    rules_sha256: &str,
    min_bgp_peers: usize,
) -> Result<MergedBgpArtifacts> {
    if artifact_paths.is_empty() {
        anyhow::bail!("at least one BGP shard artifact is required");
    }

    let mut expected_shard_count = None;
    let mut expected_source_group_count = None;
    let mut source_groups: BTreeMap<Vec<String>, BTreeSet<u32>> = BTreeMap::new();
    let mut source_checksums = BTreeMap::new();
    let mut announcement_groups = BTreeSet::new();
    let mut announced_prefixes = BTreeSet::new();
    let mut observations = BTreeMap::new();

    for artifact_path in artifact_paths {
        let artifact = read_artifact(artifact_path)?;
        if artifact.schema_version != SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported BGP shard artifact schema in {}",
                artifact_path.display()
            );
        }
        if artifact.rules_sha256 != rules_sha256 {
            anyhow::bail!("rules checksum mismatch in {}", artifact_path.display());
        }
        if artifact.sources.is_empty() {
            anyhow::bail!("missing BGP sources in {}", artifact_path.display());
        }
        if artifact.shard_count == 0 || artifact.shard_index >= artifact.shard_count {
            anyhow::bail!(
                "invalid BGP shard coordinates in {}",
                artifact_path.display()
            );
        }
        if artifact.source_group_count == 0
            || artifact.source_group_index >= artifact.source_group_count
        {
            anyhow::bail!(
                "invalid BGP source group coordinates in {}",
                artifact_path.display()
            );
        }
        if expected_shard_count.is_some_and(|count| count != artifact.shard_count) {
            anyhow::bail!("inconsistent BGP shard counts");
        }
        expected_shard_count.get_or_insert(artifact.shard_count);
        if expected_source_group_count.is_some_and(|count| count != artifact.source_group_count) {
            anyhow::bail!("inconsistent BGP source group counts");
        }
        expected_source_group_count.get_or_insert(artifact.source_group_count);

        let source_group: Vec<_> = artifact
            .sources
            .iter()
            .map(|source| source.filename.clone())
            .collect();
        if source_group.windows(2).any(|pair| pair[0] >= pair[1]) {
            anyhow::bail!("BGP source group is unsorted or duplicated");
        }
        if !source_groups
            .entry(source_group.clone())
            .or_default()
            .insert(artifact.shard_index)
        {
            anyhow::bail!("duplicate BGP source group shard");
        }
        for source in artifact.sources {
            if let Some(existing) = source_checksums.get(&source.filename) {
                if existing != &source.sha256 {
                    anyhow::bail!("BGP source checksum mismatch");
                }
            } else {
                source_checksums.insert(source.filename, source.sha256);
            }
        }
        if artifact.shard_index == 0 {
            let prefixes = artifact.announced_prefixes.with_context(|| {
                format!("missing announcement index in {}", artifact_path.display())
            })?;
            announced_prefixes.extend(prefixes);
            announcement_groups.insert(artifact.source_group_index);
        } else if artifact.announced_prefixes.is_some() {
            anyhow::bail!("only Prefix shard zero may contain the announcement index");
        }

        for (prefix, observation) in artifact.observations {
            if prefix != observation.prefix
                || !crate::bgp::belongs_to_shard(
                    prefix,
                    Some((artifact.shard_index, artifact.shard_count)),
                )
            {
                anyhow::bail!("misassigned Prefix in {}", artifact_path.display());
            }
            if let Some(existing) = observations.get_mut(&prefix) {
                merge_observations(existing, observation);
            } else {
                observations.insert(prefix, observation);
            }
        }
    }

    let shard_count = expected_shard_count.context("missing BGP shard count")?;
    let source_group_count =
        expected_source_group_count.context("missing BGP source group count")?;
    if source_groups.len() != source_group_count as usize {
        anyhow::bail!("BGP source groups are incomplete");
    }
    let expected_shards: BTreeSet<_> = (0..shard_count).collect();
    if source_groups
        .values()
        .any(|shards| shards != &expected_shards)
    {
        anyhow::bail!("BGP source group shards are incomplete");
    }
    let expected_source_groups: BTreeSet<_> = (0..source_group_count).collect();
    if announcement_groups != expected_source_groups {
        anyhow::bail!("BGP announcement indexes are incomplete");
    }

    announced_prefixes.retain(|prefix| {
        observations
            .get(prefix)
            .is_some_and(|observation| observation.peer_asns.len() >= min_bgp_peers)
    });
    observations.retain(|_, observation| observation.peer_asns.len() >= min_bgp_peers);
    Ok(MergedBgpArtifacts {
        observations,
        announced_prefixes,
    })
}

fn merge_observations(
    left: &mut crate::model::BgpObservation,
    right: crate::model::BgpObservation,
) {
    let prefer_right =
        (right.asn_path.len(), &right.asn_path) < (left.asn_path.len(), &left.asn_path);
    if prefer_right {
        left.origin_asns = right.origin_asns.clone();
        left.asn_path = right.asn_path.clone();
        left.transit_asns = right.transit_asns.clone();
    }
    left.observed_origin_asns.extend(right.observed_origin_asns);
    left.observed_final_upstream_asns
        .extend(right.observed_final_upstream_asns);
    left.peer_asns.extend(right.peer_asns);
    left.collectors.extend(right.collectors);
    left.last_seen = left.last_seen.max(right.last_seen);
    for (origin, evidence) in right.upstream_evidence {
        if let Some(merged) = left.upstream_evidence.get_mut(&origin) {
            merged
                .immediate_upstream_asns
                .extend(evidence.immediate_upstream_asns);
            merged.complete &= evidence.complete;
        } else {
            left.upstream_evidence.insert(origin, evidence);
        }
    }
}

fn bgp_sources(paths: &[PathBuf]) -> Result<Vec<BgpSource>> {
    let mut sources = paths
        .iter()
        .map(|path| {
            Ok(BgpSource {
                filename: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("BGP source filename is not valid UTF-8")?
                    .to_string(),
                sha256: sha256_file(path)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    sources.sort_by(|left, right| left.filename.cmp(&right.filename));
    if sources
        .windows(2)
        .any(|pair| pair[0].filename == pair[1].filename)
    {
        anyhow::bail!("BGP source filenames must be unique");
    }
    Ok(sources)
}

fn generate(
    config: &Config,
    options: &PipelineOptions,
    observations: BTreeMap<IpNet, crate::model::BgpObservation>,
    announced_prefixes: BTreeSet<IpNet>,
) -> Result<PipelineSummary> {
    let announced_prefixes = AnnouncedPrefixIndex::from_prefixes(announced_prefixes);
    if observations.is_empty() {
        anyhow::bail!("no announced origin prefixes found in the supplied MRT files");
    }
    let whois = WhoisIndex::load(&options.whois_files)?;
    if whois.is_empty() {
        anyhow::bail!("no RIR WHOIS inetnum/inet6num records were loaded");
    }
    let geo = GeoIndex::load_optional(options.geo_file.as_deref())?;
    let families = infer_families(config, &observations, whois.asns());
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
            config,
            Some(observation),
            Some(owner_record),
            whois.asns(),
            &families,
            geo_location,
        ) else {
            rejected_unclassified += 1;
            continue;
        };
        let observed_final_upstream_asn = final_upstream_asns(observation);
        let include_in_china = is_configured_china_asset(config, &classification.asset)
            || !observed_final_upstream_asn.is_empty();
        let family_names: Vec<_> = observation
            .observed_origin_asns
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
            config,
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
    write_all(&options.output_dir, config, &classified, &families)?;

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
    use tempfile::tempdir;

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
        let paths: BTreeSet<_> = paths.into_iter().collect();
        let asn_path = paths.first().cloned().unwrap_or_default();
        let observed_origin_asns = paths
            .iter()
            .filter_map(|path| path.last().copied())
            .collect();
        let observed_final_upstream_asns = paths
            .iter()
            .filter_map(|path| {
                path.iter()
                    .rev()
                    .find(|asn| [4134, 4809, 4837, 9929, 9808].contains(asn))
                    .copied()
            })
            .collect();
        crate::model::BgpObservation {
            prefix: "203.0.113.0/24".parse().unwrap(),
            origin_asns: BTreeSet::from([56040]),
            observed_origin_asns,
            asn_path,
            observed_final_upstream_asns,
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
        assert_eq!(final_upstream_asns(&observation), vec![4134]);
    }

    #[test]
    fn multiple_allowed_final_upstreams_are_included_in_china() {
        let observation = observation([vec![9808, 56040], vec![4134, 56041]]);
        assert_eq!(final_upstream_asns(&observation), vec![4134, 9808]);
    }

    #[test]
    fn anycast_prefix_is_included_when_one_origin_has_an_allowed_path() {
        let observation = observation([vec![4134, 134773, 56040], vec![3356, 56041]]);
        assert_eq!(final_upstream_asns(&observation), vec![4134]);
    }

    #[test]
    fn non_allowlisted_final_upstreams_exclude_prefix_from_china() {
        let observation = observation([vec![3356, 56040], vec![1299, 56041]]);
        assert!(final_upstream_asns(&observation).is_empty());
    }

    #[test]
    fn merge_bgp_artifacts_unions_observations_from_source_groups() {
        let directory = tempdir().unwrap();
        let prefix = "240c:409f::/46".parse().unwrap();
        let mut first = observation([vec![4134, 134756]]);
        first.prefix = prefix;
        first.peer_asns = BTreeSet::from([100]);
        let mut second = observation([vec![46997, 38008, 10099, 4837, 38365]]);
        second.prefix = prefix;
        second.origin_asns = BTreeSet::from([38365]);
        second.peer_asns = BTreeSet::from([200]);
        second.collectors = BTreeSet::from(["rrc24".to_string()]);
        let paths = [
            ("group-zero.json", 0, "rib-rrc00.gz", first),
            ("group-one.json", 1, "rib-rrc24.gz", second),
        ];
        let mut artifacts = Vec::new();
        for (name, group, filename, observation) in paths {
            let path = directory.path().join(name);
            write_artifact(
                &path,
                &BgpShardArtifact {
                    schema_version: SCHEMA_VERSION,
                    rules_sha256: "rules".to_string(),
                    sources: vec![BgpSource {
                        filename: filename.to_string(),
                        sha256: "source".to_string(),
                    }],
                    source_group_index: group,
                    source_group_count: 2,
                    shard_index: 0,
                    shard_count: 1,
                    observations: BTreeMap::from([(prefix, observation)]),
                    announced_prefixes: Some(BTreeSet::from([prefix])),
                },
            )
            .unwrap();
            artifacts.push(path);
        }

        let merged = merge_bgp_artifacts(&artifacts, "rules", 2).unwrap();
        let merged_observation = merged.observations.get(&prefix).unwrap();
        assert_eq!(
            merged_observation.observed_origin_asns,
            BTreeSet::from([134756, 38365])
        );
        assert_eq!(merged_observation.peer_asns, BTreeSet::from([100, 200]));
        assert_eq!(merged.announced_prefixes, BTreeSet::from([prefix]));
    }

    #[test]
    fn merge_bgp_artifacts_preserves_all_shards_and_full_announcement_index() {
        let directory = tempdir().unwrap();
        let first_prefix = "203.0.113.0/24".parse().unwrap();
        let second_prefix = "203.0.113.1/32".parse().unwrap();
        assert!(crate::bgp::belongs_to_shard(first_prefix, Some((0, 2))));
        assert!(crate::bgp::belongs_to_shard(second_prefix, Some((1, 2))));

        let mut first = observation([vec![4134, 134773, 56040]]);
        first.prefix = first_prefix;
        let mut second = observation([vec![9808, 56041]]);
        second.prefix = second_prefix;
        let shard_zero = directory.path().join("shard-zero.json");
        let shard_one = directory.path().join("shard-one.json");
        write_artifact(
            &shard_zero,
            &BgpShardArtifact {
                schema_version: SCHEMA_VERSION,
                rules_sha256: "rules".to_string(),
                sources: vec![BgpSource {
                    filename: "rib-a.gz".to_string(),
                    sha256: "source".to_string(),
                }],
                source_group_index: 0,
                source_group_count: 1,
                shard_index: 0,
                shard_count: 2,
                observations: BTreeMap::from([(first_prefix, first)]),
                announced_prefixes: Some(BTreeSet::from([first_prefix, second_prefix])),
            },
        )
        .unwrap();
        write_artifact(
            &shard_one,
            &BgpShardArtifact {
                schema_version: SCHEMA_VERSION,
                rules_sha256: "rules".to_string(),
                sources: vec![BgpSource {
                    filename: "rib-a.gz".to_string(),
                    sha256: "source".to_string(),
                }],
                source_group_index: 0,
                source_group_count: 1,
                shard_index: 1,
                shard_count: 2,
                observations: BTreeMap::from([(second_prefix, second)]),
                announced_prefixes: None,
            },
        )
        .unwrap();

        let merged = merge_bgp_artifacts(&[shard_one, shard_zero], "rules", 0).unwrap();
        assert_eq!(merged.observations.len(), 2);
        assert_eq!(
            merged.announced_prefixes,
            BTreeSet::from([first_prefix, second_prefix])
        );
    }

    #[test]
    fn merge_bgp_artifacts_rejects_missing_shards() {
        let directory = tempdir().unwrap();
        let artifact_path = directory.path().join("shard-zero.json");
        write_artifact(
            &artifact_path,
            &BgpShardArtifact {
                schema_version: SCHEMA_VERSION,
                rules_sha256: "rules".to_string(),
                sources: vec![BgpSource {
                    filename: "rib-a.gz".to_string(),
                    sha256: "source".to_string(),
                }],
                source_group_index: 0,
                source_group_count: 1,
                shard_index: 0,
                shard_count: 2,
                observations: BTreeMap::new(),
                announced_prefixes: Some(BTreeSet::new()),
            },
        )
        .unwrap();

        assert!(
            merge_bgp_artifacts(&[artifact_path], "rules", 0)
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
    }

    #[test]
    fn merge_bgp_artifacts_rejects_misassigned_prefixes() {
        let directory = tempdir().unwrap();
        let prefix = "203.0.113.1/32".parse().unwrap();
        let mut observation = observation([vec![4134, 134773, 56040]]);
        observation.prefix = prefix;
        let shard_zero = directory.path().join("shard-zero.json");
        let shard_one = directory.path().join("shard-one.json");
        for (path, shard_index, observations, announced_prefixes) in [
            (
                &shard_zero,
                0,
                BTreeMap::from([(prefix, observation)]),
                Some(BTreeSet::from([prefix])),
            ),
            (&shard_one, 1, BTreeMap::new(), None),
        ] {
            write_artifact(
                path,
                &BgpShardArtifact {
                    schema_version: SCHEMA_VERSION,
                    rules_sha256: "rules".to_string(),
                    sources: vec![BgpSource {
                        filename: "rib-a.gz".to_string(),
                        sha256: "source".to_string(),
                    }],
                    source_group_index: 0,
                    source_group_count: 1,
                    shard_index,
                    shard_count: 2,
                    observations,
                    announced_prefixes,
                },
            )
            .unwrap();
        }

        assert!(
            merge_bgp_artifacts(&[shard_zero, shard_one], "rules", 0)
                .unwrap_err()
                .to_string()
                .contains("misassigned")
        );
    }

    #[test]
    fn merge_bgp_artifacts_rejects_source_mismatches() {
        let directory = tempdir().unwrap();
        let shard_zero = directory.path().join("shard-zero.json");
        let shard_one = directory.path().join("shard-one.json");
        for (path, shard_index, source) in [(&shard_zero, 0, "one"), (&shard_one, 1, "two")] {
            write_artifact(
                path,
                &BgpShardArtifact {
                    schema_version: SCHEMA_VERSION,
                    rules_sha256: "rules".to_string(),
                    sources: vec![BgpSource {
                        filename: "rib-a.gz".to_string(),
                        sha256: source.to_string(),
                    }],
                    source_group_index: 0,
                    source_group_count: 1,
                    shard_index,
                    shard_count: 2,
                    observations: BTreeMap::new(),
                    announced_prefixes: (shard_index == 0).then_some(BTreeSet::new()),
                },
            )
            .unwrap();
        }

        assert!(
            merge_bgp_artifacts(&[shard_zero, shard_one], "rules", 0)
                .unwrap_err()
                .to_string()
                .contains("source checksum mismatch")
        );
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
