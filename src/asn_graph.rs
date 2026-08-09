use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::{
    config::{AssetType, Config},
    model::{AsnRecord, BgpObservation},
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FamilyMembership {
    pub asn: u32,
    pub family: String,
    pub asset: String,
    pub score: u16,
    pub depth: u8,
    pub evidence: Vec<String>,
}

pub fn infer_families(
    config: &Config,
    observations: &BTreeMap<ipnet::IpNet, BgpObservation>,
    asn_records: &BTreeMap<u32, AsnRecord>,
) -> BTreeMap<u32, FamilyMembership> {
    let observed_origins: BTreeSet<u32> = observations
        .values()
        .flat_map(|observation| observation.origin_asns.iter().copied())
        .collect();
    let adjacency = origin_side_adjacency(observations);
    let mut memberships: BTreeMap<u32, FamilyMembership> = BTreeMap::new();

    let mut carrier_rules: Vec<_> = config
        .assets
        .iter()
        .filter(|(_, rule)| rule.asset_type == AssetType::Carrier && !rule.roots.is_empty())
        .collect();
    carrier_rules.sort_by(|(left_id, left), (right_id, right)| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left_id.cmp(right_id))
    });

    for (asset, rule) in carrier_rules {
        let family = rule
            .operator_family
            .clone()
            .unwrap_or_else(|| asset.clone());
        let root_records: Vec<_> = rule
            .roots
            .iter()
            .filter_map(|root| asn_records.get(root))
            .collect();
        let mut family_members = BTreeSet::new();
        for root in &rule.roots {
            family_members.insert(*root);
            insert_best(
                &mut memberships,
                FamilyMembership {
                    asn: *root,
                    family: family.clone(),
                    asset: asset.clone(),
                    score: 100,
                    depth: 0,
                    evidence: vec!["configured-root".to_string()],
                },
            );
        }

        for depth in 1..=config.settings.max_asn_family_depth {
            let mut discovered = Vec::new();
            for asn in &observed_origins {
                if family_members.contains(asn) {
                    continue;
                }
                let record = asn_records.get(asn);
                let (score, evidence) = score_candidate(
                    *asn,
                    record,
                    &root_records,
                    &rule.compiled.asn_org,
                    &family_members,
                    &adjacency,
                    &config.settings.domestic_country,
                );
                if score >= config.settings.min_asn_family_score {
                    discovered.push((*asn, score, evidence));
                }
            }
            if discovered.is_empty() {
                break;
            }
            for (asn, score, evidence) in discovered {
                family_members.insert(asn);
                insert_best(
                    &mut memberships,
                    FamilyMembership {
                        asn,
                        family: family.clone(),
                        asset: asset.clone(),
                        score,
                        depth,
                        evidence,
                    },
                );
            }
        }
    }

    memberships
}

fn score_candidate(
    asn: u32,
    record: Option<&AsnRecord>,
    roots: &[&AsnRecord],
    patterns: &[regex::Regex],
    family: &BTreeSet<u32>,
    adjacency: &HashMap<u32, BTreeSet<u32>>,
    domestic_country: &str,
) -> (u16, Vec<String>) {
    let mut score = 0;
    let mut evidence = Vec::new();
    if let Some(record) = record {
        if record
            .country
            .as_deref()
            .is_some_and(|country| country.eq_ignore_ascii_case(domestic_country))
        {
            score += 10;
            evidence.push("domestic-asn-whois".to_string());
        }
        let text = record.searchable_text();
        if !patterns.is_empty() && patterns.iter().any(|pattern| pattern.is_match(&text)) {
            score += 70;
            evidence.push("asn-organisation-rule".to_string());
        }
        if record.org_id.is_some()
            && roots
                .iter()
                .any(|root| root.org_id.as_ref() == record.org_id.as_ref())
        {
            score += 100;
            evidence.push("shared-organisation-id".to_string());
        }
        if roots.iter().any(|root| {
            root.maintainers
                .iter()
                .any(|maintainer| record.maintainers.contains(maintainer))
        }) {
            score += 55;
            evidence.push("shared-maintainer".to_string());
        }
    }
    if adjacency
        .get(&asn)
        .is_some_and(|neighbors| neighbors.iter().any(|neighbor| family.contains(neighbor)))
    {
        score += 15;
        evidence.push("origin-side-bgp-adjacency".to_string());
    }
    (score.min(100), evidence)
}

fn origin_side_adjacency(
    observations: &BTreeMap<ipnet::IpNet, BgpObservation>,
) -> HashMap<u32, BTreeSet<u32>> {
    let mut adjacency: HashMap<u32, BTreeSet<u32>> = HashMap::new();
    for observation in observations.values() {
        let Some(origin) = observation.asn_path.last().copied() else {
            continue;
        };
        let Some(upstream) = observation
            .asn_path
            .iter()
            .rev()
            .copied()
            .find(|asn| *asn != origin)
        else {
            continue;
        };
        adjacency.entry(origin).or_default().insert(upstream);
        adjacency.entry(upstream).or_default().insert(origin);
    }
    adjacency
}

fn insert_best(memberships: &mut BTreeMap<u32, FamilyMembership>, candidate: FamilyMembership) {
    let replace = memberships.get(&candidate.asn).is_none_or(|current| {
        candidate.score > current.score
            || (candidate.score == current.score && candidate.asset < current.asset)
    });
    if replace {
        memberships.insert(candidate.asn, candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgp_adjacency_alone_cannot_create_a_family_member() {
        let adjacency = HashMap::from([(64500, BTreeSet::from([4134]))]);
        let (score, evidence) = score_candidate(
            64500,
            None,
            &[],
            &[],
            &BTreeSet::from([4134]),
            &adjacency,
            "CN",
        );
        assert_eq!(score, 15);
        assert_eq!(evidence, vec!["origin-side-bgp-adjacency"]);
    }

    #[test]
    fn organisation_and_domestic_evidence_clear_threshold() {
        let record = AsnRecord {
            asn: 64500,
            country: Some("CN".to_string()),
            as_name: Some("CHINANET-PROVINCE".to_string()),
            ..AsnRecord::default()
        };
        let patterns = vec![regex::Regex::new("(?i:chinanet)").unwrap()];
        let (score, _) = score_candidate(
            64500,
            Some(&record),
            &[],
            &patterns,
            &BTreeSet::new(),
            &HashMap::new(),
            "CN",
        );
        assert_eq!(score, 80);
    }
}
