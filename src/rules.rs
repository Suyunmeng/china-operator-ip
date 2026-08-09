use std::collections::{BTreeMap, BTreeSet};

use crate::{
    asn_graph::FamilyMembership,
    config::{AssetRule, Config},
    model::{AsnRecord, BgpObservation, Classification, GeoLocation, WhoisRecord},
};

#[derive(Debug)]
struct Candidate {
    classification: Classification,
    priority: i32,
    stage: u8,
    specificity: usize,
}

pub fn classify(
    config: &Config,
    observation: &BgpObservation,
    whois: Option<&WhoisRecord>,
    asn_records: &BTreeMap<u32, AsnRecord>,
    families: &BTreeMap<u32, FamilyMembership>,
    geo: Option<&GeoLocation>,
) -> Option<Classification> {
    if !is_domestic(config, whois, geo) {
        return None;
    }

    let mut candidates = Vec::new();
    for (asset, rule) in &config.assets {
        if matches_exclude(rule, observation, whois, asn_records, geo) {
            continue;
        }
        if let Some(candidate) = owner_candidate(asset, rule, observation, whois, geo) {
            candidates.push(candidate);
            continue;
        }
        if rule.require_domestic && !is_domestic(config, whois, geo) {
            continue;
        }
        if let Some(candidate) =
            family_candidate(asset, rule, observation, whois, asn_records, families)
        {
            candidates.push(candidate);
            continue;
        }
        if let Some(candidate) = origin_candidate(asset, rule, observation, whois, asn_records, geo)
        {
            candidates.push(candidate);
            continue;
        }
        if let Some(candidate) = fallback_candidate(asset, rule, whois) {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|left, right| {
        right
            .stage
            .cmp(&left.stage)
            .then_with(|| right.priority.cmp(&left.priority))
            .then_with(|| right.specificity.cmp(&left.specificity))
            .then_with(|| left.classification.asset.cmp(&right.classification.asset))
    });
    candidates
        .into_iter()
        .next()
        .map(|candidate| candidate.classification)
}

fn owner_candidate(
    asset: &str,
    rule: &AssetRule,
    observation: &BgpObservation,
    whois: Option<&WhoisRecord>,
    geo: Option<&GeoLocation>,
) -> Option<Candidate> {
    let whois = whois?;
    let mut matched = Vec::new();
    if matches_regex_field(&rule.compiled.whois_org, whois.whois_org.as_deref()) {
        matched.push("whois_org");
    }
    if matches_regex_field(&rule.compiled.org_id, whois.org_id.as_deref()) {
        matched.push("org_id");
    }
    if matches_regex_values(&rule.compiled.maintainer, &whois.maintainers) {
        matched.push("maintainer");
    }
    if matches_regex_field(&rule.compiled.netname, whois.netname.as_deref()) {
        matched.push("netname");
    }
    if !rule.match_.country.is_empty()
        && !whois.country.as_ref().is_some_and(|country| {
            rule.match_
                .country
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(country))
        })
    {
        return None;
    }
    if !rule.compiled.geo.is_empty() && !matches_geo(&rule.compiled.geo, geo) {
        return None;
    }
    if matched.is_empty() || !owner_constraints_match(rule, observation) {
        return None;
    }
    Some(Candidate {
        classification: classification(
            asset,
            rule,
            &format!("{}:owner", asset),
            "whois-owner",
            (92 + matched.len() as u8 * 2).min(99),
            whois,
        ),
        priority: rule.priority,
        stage: 4,
        specificity: matched.len(),
    })
}

fn family_candidate(
    asset: &str,
    rule: &AssetRule,
    observation: &BgpObservation,
    whois: Option<&WhoisRecord>,
    asn_records: &BTreeMap<u32, AsnRecord>,
    families: &BTreeMap<u32, FamilyMembership>,
) -> Option<Candidate> {
    if whois_conflicts_with_rule(rule, whois, observation, asn_records) {
        return None;
    }
    let membership = observation
        .origin_asns
        .iter()
        .filter_map(|asn| families.get(asn))
        .find(|membership| membership.asset == asset)?;
    Some(Candidate {
        classification: Classification {
            asset: asset.to_string(),
            owner: rule.owner.clone(),
            asset_type: rule.asset_type.as_str().to_string(),
            operator_family: rule
                .operator_family
                .clone()
                .or_else(|| Some(membership.family.clone())),
            match_rule: format!("{}:asn-family", asset),
            match_source: "asn-family".to_string(),
            confidence_score: (75 + membership.score / 4).min(95) as u8,
        },
        priority: rule.priority,
        stage: 3,
        specificity: membership.evidence.len(),
    })
}

fn origin_candidate(
    asset: &str,
    rule: &AssetRule,
    observation: &BgpObservation,
    whois: Option<&WhoisRecord>,
    asn_records: &BTreeMap<u32, AsnRecord>,
    geo: Option<&GeoLocation>,
) -> Option<Candidate> {
    if whois_conflicts_with_rule(rule, whois, observation, asn_records) {
        return None;
    }
    let origin_match = rule
        .match_
        .origin_asn
        .iter()
        .any(|asn| observation.origin_asns.contains(asn));
    let asn_org_match = observation.origin_asns.iter().any(|asn| {
        asn_records.get(asn).is_some_and(|record| {
            matches_regex_text(&rule.compiled.asn_org, &record.searchable_text())
        })
    });
    let geo_matches = rule.compiled.geo.is_empty() || matches_geo(&rule.compiled.geo, geo);
    if (!origin_match && !asn_org_match) || !geo_matches {
        return None;
    }
    let specificity = usize::from(origin_match)
        + usize::from(asn_org_match)
        + usize::from(!rule.compiled.geo.is_empty());
    Some(Candidate {
        classification: Classification {
            asset: asset.to_string(),
            owner: rule.owner.clone(),
            asset_type: rule.asset_type.as_str().to_string(),
            operator_family: rule.operator_family.clone(),
            match_rule: format!("{}:origin", asset),
            match_source: if asn_org_match {
                "asn-whois"
            } else {
                "origin-asn"
            }
            .to_string(),
            confidence_score: if asn_org_match && origin_match {
                88
            } else {
                80
            },
        },
        priority: rule.priority,
        stage: 2,
        specificity,
    })
}

fn whois_conflicts_with_rule(
    rule: &AssetRule,
    whois: Option<&WhoisRecord>,
    observation: &BgpObservation,
    asn_records: &BTreeMap<u32, AsnRecord>,
) -> bool {
    let Some(whois) = whois else {
        return true;
    };
    let prefix_owner = whois.searchable_owner_text();
    let owner_matches = matches_regex_text(&rule.compiled.whois_org, &prefix_owner)
        || matches_regex_text(&rule.compiled.org_id, &prefix_owner)
        || matches_regex_text(&rule.compiled.maintainer, &prefix_owner)
        || matches_regex_text(&rule.compiled.netname, &prefix_owner);
    if owner_matches {
        return false;
    }
    let owner_present = whois.whois_org.is_some()
        || whois.org_id.is_some()
        || whois.netname.is_some()
        || !whois.maintainers.is_empty();
    let asn_owner_matches = observation.origin_asns.iter().any(|asn| {
        asn_records.get(asn).is_some_and(|record| {
            matches_regex_text(&rule.compiled.asn_org, &record.searchable_text())
        })
    });
    owner_present && !asn_owner_matches
}

fn fallback_candidate(
    asset: &str,
    rule: &AssetRule,
    whois: Option<&WhoisRecord>,
) -> Option<Candidate> {
    let whois = whois?;
    if !rule.fallback {
        return None;
    }
    Some(Candidate {
        classification: Classification {
            asset: asset.to_string(),
            owner: whois
                .whois_org
                .clone()
                .or_else(|| whois.netname.clone())
                .unwrap_or_else(|| rule.owner.clone()),
            asset_type: rule.asset_type.as_str().to_string(),
            operator_family: rule.operator_family.clone(),
            match_rule: format!("{}:fallback", asset),
            match_source: "domestic-whois-fallback".to_string(),
            confidence_score: 65,
        },
        priority: rule.priority,
        stage: 1,
        specificity: usize::from(whois.whois_org.is_some()),
    })
}

fn owner_constraints_match(rule: &AssetRule, observation: &BgpObservation) -> bool {
    rule.match_.transit_asn.is_empty()
        || rule
            .match_
            .transit_asn
            .iter()
            .any(|asn| observation.transit_asns.contains(asn))
}

fn matches_exclude(
    rule: &AssetRule,
    observation: &BgpObservation,
    whois: Option<&WhoisRecord>,
    asn_records: &BTreeMap<u32, AsnRecord>,
    geo: Option<&GeoLocation>,
) -> bool {
    let conditions = &rule.exclude;
    if conditions.is_empty() {
        return false;
    }
    conditions
        .origin_asn
        .iter()
        .any(|asn| observation.origin_asns.contains(asn))
        || conditions
            .transit_asn
            .iter()
            .any(|asn| observation.transit_asns.contains(asn))
        || whois.is_some_and(|record| {
            matches_regex_field(
                &rule.compiled.exclude_whois_org,
                record.whois_org.as_deref(),
            ) || matches_regex_field(&rule.compiled.exclude_org_id, record.org_id.as_deref())
                || matches_regex_values(&rule.compiled.exclude_maintainer, &record.maintainers)
                || matches_regex_field(&rule.compiled.exclude_netname, record.netname.as_deref())
                || matches_country(&conditions.country, record.country.as_deref())
        })
        || observation.origin_asns.iter().any(|asn| {
            asn_records.get(asn).is_some_and(|record| {
                matches_regex_text(&rule.compiled.exclude_asn_org, &record.searchable_text())
            })
        })
        || matches_geo(&rule.compiled.exclude_geo, geo)
}

fn is_domestic(config: &Config, whois: Option<&WhoisRecord>, geo: Option<&GeoLocation>) -> bool {
    let expected = &config.settings.domestic_country;
    if geo
        .and_then(|value| value.country.as_deref())
        .is_some_and(|country| !country.eq_ignore_ascii_case(expected))
    {
        return false;
    }
    whois
        .and_then(|record| record.country.as_deref())
        .is_some_and(|country| country.eq_ignore_ascii_case(expected))
}

fn classification(
    asset: &str,
    rule: &AssetRule,
    match_rule: &str,
    source: &str,
    confidence_score: u8,
    _whois: &WhoisRecord,
) -> Classification {
    Classification {
        asset: asset.to_string(),
        owner: rule.owner.clone(),
        asset_type: rule.asset_type.as_str().to_string(),
        operator_family: rule.operator_family.clone(),
        match_rule: match_rule.to_string(),
        match_source: source.to_string(),
        confidence_score,
    }
}

fn matches_regex_field(patterns: &[regex::Regex], value: Option<&str>) -> bool {
    value.is_some_and(|value| matches_regex_text(patterns, value))
}

fn matches_regex_values(patterns: &[regex::Regex], values: &[String]) -> bool {
    !patterns.is_empty()
        && values
            .iter()
            .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

fn matches_regex_text(patterns: &[regex::Regex], value: &str) -> bool {
    !patterns.is_empty() && patterns.iter().any(|pattern| pattern.is_match(value))
}

fn matches_country(countries: &[String], country: Option<&str>) -> bool {
    !countries.is_empty()
        && country.is_some_and(|country| {
            countries
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(country))
        })
}

fn matches_geo(patterns: &[regex::Regex], geo: Option<&GeoLocation>) -> bool {
    let Some(geo) = geo else {
        return false;
    };
    let values: BTreeSet<_> = [
        geo.country.as_deref(),
        geo.subdivision.as_deref(),
        geo.city.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    !patterns.is_empty()
        && values
            .iter()
            .any(|value| patterns.iter().any(|pattern| pattern.is_match(value)))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::IpNet;

    use super::*;
    use crate::{
        config::Config,
        model::{BgpObservation, WhoisRecord},
    };

    fn config() -> Config {
        let yaml = r#"
version: 1
assets:
  chinanet:
    type: carrier
    owner: China Telecom
    operator_family: chinanet
    priority: 100
    roots: [4134]
    match:
      origin_asn: [4134]
      whois_org: ["china telecom"]
  shixp:
    type: ixp
    owner: SHIXP
    priority: 300
    match:
      whois_org: ["SHIXP"]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
        config
    }

    fn observation() -> BgpObservation {
        BgpObservation {
            prefix: IpNet::from_str("203.0.113.0/24").unwrap(),
            origin_asns: BTreeSet::from([4134]),
            asn_path: vec![64500, 4134],
            transit_asns: BTreeSet::from([64500]),
            peer_asns: BTreeSet::new(),
            collectors: BTreeSet::new(),
            last_seen: 1,
        }
    }

    #[test]
    fn high_priority_whois_owner_overrides_carrier_origin() {
        let whois = WhoisRecord {
            country: Some("CN".to_string()),
            whois_org: Some("National SHIXP".to_string()),
            ..WhoisRecord::default()
        };
        let result = classify(
            &config(),
            &observation(),
            Some(&whois),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.asset, "shixp");
        assert_eq!(result.match_source, "whois-owner");
    }

    #[test]
    fn foreign_whois_country_excludes_carrier_origin() {
        let whois = WhoisRecord {
            country: Some("US".to_string()),
            whois_org: Some("China Telecom Americas".to_string()),
            ..WhoisRecord::default()
        };
        assert_eq!(
            classify(
                &config(),
                &observation(),
                Some(&whois),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
            ),
            None
        );
    }

    #[test]
    fn carrier_origin_does_not_override_unrelated_prefix_owner() {
        let whois = WhoisRecord {
            country: Some("CN".to_string()),
            whois_org: Some("Independent IDC".to_string()),
            org_id: Some("ORG-INDEPENDENT".to_string()),
            netname: Some("INDEPENDENT-IDC".to_string()),
            ..WhoisRecord::default()
        };
        assert_eq!(
            classify(
                &config(),
                &observation(),
                Some(&whois),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
            ),
            None
        );
    }

    #[test]
    fn owner_rule_can_override_mismatching_carrier_origin() {
        let mut observation = observation();
        observation.origin_asns = BTreeSet::from([64501]);
        observation.asn_path = vec![4134, 64501];
        observation.transit_asns = BTreeSet::from([4134]);
        let whois = WhoisRecord {
            country: Some("CN".to_string()),
            whois_org: Some("National SHIXP".to_string()),
            ..WhoisRecord::default()
        };
        let result = classify(
            &config(),
            &observation,
            Some(&whois),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.asset, "shixp");
    }

    #[test]
    fn geo_rule_cannot_classify_without_owner_or_origin_evidence() {
        let yaml = r#"
version: 1
assets:
  geo_only:
    type: enterprise
    owner: Geo Only
    priority: 100
    match:
      geo: ["Beijing"]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
        let whois = WhoisRecord {
            country: Some("CN".to_string()),
            whois_org: Some("Unrelated Enterprise".to_string()),
            ..WhoisRecord::default()
        };
        let geo = GeoLocation {
            country: Some("CN".to_string()),
            subdivision: Some("Beijing".to_string()),
            city: None,
        };
        assert_eq!(
            classify(
                &config,
                &observation(),
                Some(&whois),
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&geo),
            ),
            None
        );
    }

    #[test]
    fn root_asn_as_transit_does_not_match_origin_rule() {
        let mut observation = observation();
        observation.origin_asns = BTreeSet::from([64501]);
        observation.asn_path = vec![64500, 4134, 64501];
        observation.transit_asns = BTreeSet::from([64500, 4134]);
        let whois = WhoisRecord {
            country: Some("CN".to_string()),
            whois_org: Some("Unrelated Enterprise".to_string()),
            ..WhoisRecord::default()
        };
        assert_eq!(
            classify(
                &config(),
                &observation,
                Some(&whois),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
            ),
            None
        );
    }
}
