use std::{collections::BTreeMap, path::PathBuf};

use anyhow::Result;

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
    if observations.is_empty() {
        anyhow::bail!("no announced origin prefixes found in the supplied MRT files");
    }
    let whois = WhoisIndex::load(&options.whois_files)?;
    if whois.is_empty() {
        anyhow::bail!("no RIR WHOIS inetnum/inet6num records were loaded");
    }
    let geo = GeoIndex::load_optional(options.geo_file.as_deref())?;
    let families = infer_families(&config, &observations, whois.asns());
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
            observation,
            Some(owner_record),
            whois.asns(),
            &families,
            geo_location,
        ) else {
            rejected_unclassified += 1;
            continue;
        };
        let include_in_china = config
            .assets
            .get(&classification.asset)
            .is_some_and(|rule| rule.include_in_china);
        let family_names: Vec<_> = observation
            .origin_asns
            .iter()
            .filter_map(|asn| families.get(asn).map(|family| family.family.clone()))
            .collect();
        classified.push((
            PrefixMetadata {
                prefix: observation.prefix,
                ip_version: if observation.prefix.addr().is_ipv4() {
                    4
                } else {
                    6
                },
                origin_asn: observation.origin_asns.iter().copied().collect(),
                asset: classification.asset,
                asn_path: observation.asn_path.clone(),
                owner: classification.owner,
                asset_type: classification.asset_type,
                include_in_china,
                operator_family: classification.operator_family,
                whois_org: owner_record.whois_org.clone(),
                org_id: owner_record.org_id.clone(),
                maintainer: owner_record.maintainers.clone(),
                netname: owner_record.netname.clone(),
                rir: owner_record.rir.clone(),
                country: owner_record.country.clone(),
                geo_location: geo_location.cloned(),
                match_rule: classification.match_rule,
                match_source: classification.match_source,
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
                peer_asn: observation.peer_asns.iter().copied().collect(),
                collectors: observation.collectors.iter().cloned().collect(),
                last_seen: observation.last_seen,
            },
        ));
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
