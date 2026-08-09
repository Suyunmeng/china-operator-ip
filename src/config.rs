use std::{collections::BTreeMap, fs::File, path::Path};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub settings: Settings,
    pub assets: BTreeMap<String, AssetRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub domestic_country: String,
    pub min_asn_family_score: u16,
    pub max_asn_family_depth: u8,
    pub metadata_files: MetadataFiles,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            domestic_country: "CN".to_string(),
            min_asn_family_score: 70,
            max_asn_family_depth: 2,
            metadata_files: MetadataFiles::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetadataFiles {
    pub owner: String,
    pub asn: String,
    pub path: String,
    pub family: String,
}

impl Default for MetadataFiles {
    fn default() -> Self {
        Self {
            owner: "prefix-owner.jsonl".to_string(),
            asn: "prefix-asn.jsonl".to_string(),
            path: "prefix-path.jsonl".to_string(),
            family: "asn-family.json".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetRule {
    #[serde(rename = "type")]
    pub asset_type: AssetType,
    pub owner: String,
    #[serde(default)]
    pub operator_family: Option<String>,
    pub priority: i32,
    #[serde(default)]
    pub roots: Vec<u32>,
    #[serde(default)]
    pub routing: Option<RoutingConditions>,
    #[serde(default, rename = "match")]
    pub match_: MatchConditions,
    #[serde(default)]
    pub exclude: MatchConditions,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default = "default_true")]
    pub include_in_china: bool,
    #[serde(default = "default_true")]
    pub require_domestic: bool,
    #[serde(default = "default_true")]
    pub require_announced: bool,
    #[serde(default)]
    pub fallback: bool,
    #[serde(skip)]
    pub compiled: CompiledRule,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Carrier,
    Cloud,
    Cdn,
    Ixp,
    Idc,
    Enterprise,
    Education,
    Research,
    Other,
}

impl AssetType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Carrier => "carrier",
            Self::Cloud => "cloud",
            Self::Cdn => "cdn",
            Self::Ixp => "ixp",
            Self::Idc => "idc",
            Self::Enterprise => "enterprise",
            Self::Education => "education",
            Self::Research => "research",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConditions {
    pub direct_origin_asn: Vec<u32>,
    pub exclusive_immediate_upstream_asn: Vec<u32>,
}

impl RoutingConditions {
    fn is_empty(&self) -> bool {
        self.direct_origin_asn.is_empty() && self.exclusive_immediate_upstream_asn.is_empty()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MatchConditions {
    pub origin_asn: Vec<u32>,
    pub transit_asn: Vec<u32>,
    pub whois_org: Vec<String>,
    pub org_id: Vec<String>,
    pub maintainer: Vec<String>,
    pub netname: Vec<String>,
    pub country: Vec<String>,
    pub geo: Vec<String>,
    pub asn_org: Vec<String>,
}

impl MatchConditions {
    pub fn is_empty(&self) -> bool {
        self.origin_asn.is_empty()
            && self.transit_asn.is_empty()
            && self.whois_org.is_empty()
            && self.org_id.is_empty()
            && self.maintainer.is_empty()
            && self.netname.is_empty()
            && self.country.is_empty()
            && self.geo.is_empty()
            && self.asn_org.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledRule {
    pub whois_org: Vec<Regex>,
    pub org_id: Vec<Regex>,
    pub maintainer: Vec<Regex>,
    pub netname: Vec<Regex>,
    pub geo: Vec<Regex>,
    pub asn_org: Vec<Regex>,
    pub exclude_whois_org: Vec<Regex>,
    pub exclude_org_id: Vec<Regex>,
    pub exclude_maintainer: Vec<Regex>,
    pub exclude_netname: Vec<Regex>,
    pub exclude_geo: Vec<Regex>,
    pub exclude_asn_org: Vec<Regex>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open rule configuration {}", path.display()))?;
        let mut config: Self = serde_yaml::from_reader(file)
            .with_context(|| format!("failed to parse rule configuration {}", path.display()))?;
        config.validate_and_compile()?;
        Ok(config)
    }

    pub fn validate_and_compile(&mut self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported rules version {}; expected 1", self.version);
        }
        if self.settings.domestic_country.len() != 2 {
            bail!("settings.domestic_country must be an ISO alpha-2 code");
        }
        self.settings.domestic_country.make_ascii_uppercase();
        let fallback_count = self.assets.values().filter(|rule| rule.fallback).count();
        if fallback_count > 1 {
            bail!("only one fallback asset is allowed");
        }
        let metadata = &self.settings.metadata_files;
        for path in [
            &metadata.owner,
            &metadata.asn,
            &metadata.path,
            &metadata.family,
        ] {
            if path.is_empty()
                || path == "."
                || path.contains('/')
                || path.contains('\\')
                || path.contains("..")
            {
                bail!("metadata output path {path:?} is not a safe basename");
            }
        }

        for (id, rule) in &mut self.assets {
            if !rule.require_domestic {
                if rule.routing.is_none() {
                    bail!("asset {id} disables the domestic gate without routing conditions");
                }
                if !rule.match_.is_empty() || !rule.roots.is_empty() || rule.fallback {
                    bail!("asset {id} disables the domestic gate but is not a routing-only rule");
                }
            }
            if !rule.require_announced {
                let owner_conditions = !rule.match_.whois_org.is_empty()
                    || !rule.match_.org_id.is_empty()
                    || !rule.match_.maintainer.is_empty()
                    || !rule.match_.netname.is_empty();
                let has_unsupported_match = !rule.match_.transit_asn.is_empty()
                    || !rule.match_.origin_asn.is_empty()
                    || !rule.match_.geo.is_empty()
                    || !rule.match_.asn_org.is_empty();
                if !owner_conditions
                    || rule.match_.country.is_empty()
                    || !rule.exclude.is_empty()
                    || rule.routing.is_some()
                    || !rule.roots.is_empty()
                    || rule.fallback
                    || has_unsupported_match
                {
                    bail!(
                        "asset {id} disables the announced-prefix gate but is not a WHOIS owner-and-country-only rule"
                    );
                }
            }
            if rule.owner.trim().is_empty() {
                bail!("asset {id} has an empty owner");
            }
            if rule.outputs.iter().any(|output| {
                output.is_empty()
                    || output == "."
                    || output.contains('/')
                    || output.contains('\\')
                    || output.contains("..")
            }) {
                bail!("asset {id} contains an unsafe output basename");
            }
            if rule.match_.is_empty()
                && rule
                    .routing
                    .as_ref()
                    .is_none_or(RoutingConditions::is_empty)
                && !rule.fallback
            {
                bail!("asset {id} has neither match/routing conditions nor fallback: true");
            }
            validate_routing(id, rule)?;
            if !rule.match_.geo.is_empty() {
                bail!(
                    "asset {id} uses match.geo, but Geo may only enrich metadata or exclude locations"
                );
            }
            if !rule.match_.transit_asn.is_empty()
                && rule.match_.whois_org.is_empty()
                && rule.match_.org_id.is_empty()
                && rule.match_.maintainer.is_empty()
                && rule.match_.netname.is_empty()
            {
                bail!(
                    "asset {id} uses match.transit_asn without a WHOIS owner condition; transit ASN may only constrain an owner match"
                );
            }
            rule.match_.country = normalize_countries(&rule.match_.country, id)?;
            rule.exclude.country = normalize_countries(&rule.exclude.country, id)?;
            rule.compiled = compile_rule(id, &rule.match_, &rule.exclude)?;
        }
        validate_output_names(&self.assets, metadata)?;
        validate_root_ownership(&self.assets)?;
        Ok(())
    }
}

fn validate_routing(id: &str, rule: &AssetRule) -> Result<()> {
    let Some(routing) = &rule.routing else {
        return Ok(());
    };
    if routing.is_empty() {
        bail!("asset {id} contains an empty routing condition");
    }
    if rule.fallback {
        bail!("fallback asset {id} cannot use routing conditions");
    }
    for (field, asns) in [
        ("direct_origin_asn", &routing.direct_origin_asn),
        (
            "exclusive_immediate_upstream_asn",
            &routing.exclusive_immediate_upstream_asn,
        ),
    ] {
        if asns.contains(&0) {
            bail!("asset {id} routing.{field} contains invalid AS0");
        }
        let unique: std::collections::BTreeSet<_> = asns.iter().collect();
        if unique.len() != asns.len() {
            bail!("asset {id} routing.{field} contains duplicate ASNs");
        }
    }
    if !routing.exclusive_immediate_upstream_asn.is_empty() && routing.direct_origin_asn.is_empty()
    {
        bail!(
            "asset {id} uses routing.exclusive_immediate_upstream_asn without routing.direct_origin_asn"
        );
    }
    let direct: std::collections::BTreeSet<_> = routing.direct_origin_asn.iter().collect();
    let upstreams: std::collections::BTreeSet<_> =
        routing.exclusive_immediate_upstream_asn.iter().collect();
    if !upstreams.is_empty() && direct != upstreams {
        bail!(
            "asset {id} routing direct origins and exclusive immediate upstreams must contain the same ASNs"
        );
    }
    Ok(())
}

fn validate_output_names(
    assets: &BTreeMap<String, AssetRule>,
    metadata: &MetadataFiles,
) -> Result<()> {
    let mut reserved = BTreeMap::new();
    for (filename, owner) in [
        (metadata.owner.as_str(), "metadata.owner"),
        (metadata.asn.as_str(), "metadata.asn"),
        (metadata.path.as_str(), "metadata.path"),
        (metadata.family.as_str(), "metadata.family"),
        ("manifest.json", "manifest"),
        ("china.txt", "aggregate china IPv4"),
        ("china6.txt", "aggregate china IPv6"),
        ("china46.txt", "aggregate china dual-stack"),
    ] {
        if let Some(previous) = reserved.insert(filename.to_string(), owner.to_string()) {
            bail!("{owner} collides with {previous} at generated file {filename}");
        }
    }
    let mut output_families: BTreeMap<String, String> = BTreeMap::new();
    for (asset, rule) in assets {
        let basenames: Vec<_> = rule.outputs.iter().map(String::as_str).collect();
        let mut seen = BTreeMap::new();
        for basename in basenames {
            if seen.insert(basename, ()).is_some() {
                bail!("asset {asset} repeats output basename {basename}");
            }
            for filename in [
                format!("{basename}.txt"),
                format!("{basename}6.txt"),
                format!("{basename}46.txt"),
            ] {
                if let Some(previous) = reserved.get(&filename) {
                    bail!(
                        "asset {asset} output collides with {previous} at generated file {filename}"
                    );
                }
                if let Some(previous_basename) = output_families.get(&filename)
                    && previous_basename != basename
                {
                    bail!(
                        "asset {asset} output basename {basename} collides with output basename {previous_basename} at generated file {filename}"
                    );
                }
                output_families.insert(filename, basename.to_string());
            }
        }
    }
    Ok(())
}

fn validate_root_ownership(assets: &BTreeMap<String, AssetRule>) -> Result<()> {
    let mut roots = BTreeMap::new();
    for (asset, rule) in assets {
        for root in &rule.roots {
            if let Some(previous) = roots.insert(*root, asset) {
                bail!("ASN family root AS{root} is shared by assets {previous} and {asset}");
            }
        }
    }
    Ok(())
}

fn normalize_countries(values: &[String], id: &str) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            let value = value.to_ascii_uppercase();
            if value.len() != 2 {
                bail!("asset {id} contains invalid country code {value:?}");
            }
            Ok(value)
        })
        .collect()
}

fn compile_rule(
    id: &str,
    matched: &MatchConditions,
    excluded: &MatchConditions,
) -> Result<CompiledRule> {
    Ok(CompiledRule {
        whois_org: compile_patterns(id, "match.whois_org", &matched.whois_org)?,
        org_id: compile_patterns(id, "match.org_id", &matched.org_id)?,
        maintainer: compile_patterns(id, "match.maintainer", &matched.maintainer)?,
        netname: compile_patterns(id, "match.netname", &matched.netname)?,
        geo: compile_patterns(id, "match.geo", &matched.geo)?,
        asn_org: compile_patterns(id, "match.asn_org", &matched.asn_org)?,
        exclude_whois_org: compile_patterns(id, "exclude.whois_org", &excluded.whois_org)?,
        exclude_org_id: compile_patterns(id, "exclude.org_id", &excluded.org_id)?,
        exclude_maintainer: compile_patterns(id, "exclude.maintainer", &excluded.maintainer)?,
        exclude_netname: compile_patterns(id, "exclude.netname", &excluded.netname)?,
        exclude_geo: compile_patterns(id, "exclude.geo", &excluded.geo)?,
        exclude_asn_org: compile_patterns(id, "exclude.asn_org", &excluded.asn_org)?,
    })
}

fn compile_patterns(id: &str, field: &str, values: &[String]) -> Result<Vec<Regex>> {
    values
        .iter()
        .map(|value| {
            Regex::new(&format!("(?i:{value})"))
                .with_context(|| format!("asset {id} contains invalid regex in {field}: {value}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_announced_owner_only_rule_is_allowed() {
        let yaml = r#"
version: 1
assets:
  cloud:
    type: cloud
    owner: Example Cloud
    priority: 1
    require_announced: false
    match:
      whois_org: ["Example Cloud"]
      country: [CN]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
    }
    #[test]
    fn non_announced_rule_requires_whois_owner_condition() {
        let yaml = r#"
version: 1
assets:
  cloud:
    type: cloud
    owner: Example Cloud
    priority: 1
    require_announced: false
    match:
      country: [CN]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn non_announced_rule_rejects_bgp_condition() {
        let yaml = r#"
version: 1
assets:
  cloud:
    type: cloud
    owner: Example Cloud
    priority: 1
    require_announced: false
    match:
      whois_org: [Example]
      origin_asn: [64500]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn non_announced_rule_rejects_non_owner_exclude_condition() {
        let yaml = r#"
version: 1
assets:
  cloud:
    type: cloud
    owner: Example Cloud
    priority: 1
    require_announced: false
    match:
      whois_org: [Example]
      country: [CN]
    exclude:
      geo: [overseas]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }
    #[test]
    fn routing_conditions_are_validated() {
        let yaml = r#"
version: 1
assets:
  cloudflare:
    type: cdn
    owner: Cloudflare
    priority: 1
    routing:
      direct_origin_asn: [13335]
      exclusive_immediate_upstream_asn: [13335]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
    }

    #[test]
    fn routing_conditions_reject_conflicting_asn_sets() {
        let yaml = r#"
version: 1
assets:
  unsafe:
    type: cdn
    owner: Unsafe
    priority: 1
    routing:
      direct_origin_asn: [13335]
      exclusive_immediate_upstream_asn: [13335, 64500]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn empty_routing_is_rejected() {
        let yaml = r#"
version: 1
assets:
  unsafe:
    type: cdn
    owner: Unsafe
    priority: 1
    routing: {}
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }
    #[test]
    fn transit_rules_require_whois_owner_evidence() {
        let yaml = r#"
version: 1
assets:
  unsafe:
    type: carrier
    owner: Unsafe
    priority: 1
    match:
      transit_asn: [4134]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn non_domestic_rules_are_rejected() {
        let yaml = r#"
version: 1
assets:
  overseas:
    type: enterprise
    owner: Overseas
    priority: 1
    require_domestic: false
    match:
      origin_asn: [64500]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn routing_only_non_domestic_rule_is_allowed() {
        let yaml = r#"
version: 1
assets:
  cloudflare:
    type: cdn
    owner: Cloudflare
    priority: 1
    require_domestic: false
    routing:
      direct_origin_asn: [13335]
      exclusive_immediate_upstream_asn: [13335]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
    }

    #[test]
    fn positive_geo_matches_are_rejected() {
        let yaml = r#"
version: 1
assets:
  geo_owned:
    type: enterprise
    owner: Geo Owned
    priority: 1
    match:
      whois_org: ["Example"]
      geo: ["Beijing"]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn shared_output_basename_is_allowed() {
        let yaml = r#"
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
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate_and_compile().unwrap();
    }

    #[test]
    fn colliding_generated_output_names_are_rejected() {
        let yaml = r#"
version: 1
assets:
  first:
    type: enterprise
    owner: First
    priority: 2
    match:
      origin_asn: [64500]
    outputs: [example]
  second:
    type: enterprise
    owner: Second
    priority: 1
    match:
      origin_asn: [64501]
    outputs: [example6]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn shared_family_roots_are_rejected() {
        let yaml = r#"
version: 1
assets:
  first:
    type: education
    owner: First
    priority: 2
    roots: [64500]
    match:
      origin_asn: [64500]
  second:
    type: research
    owner: Second
    priority: 1
    roots: [64500]
    match:
      origin_asn: [64501]
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_and_compile().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = r#"
version: 1
assets:
  typo:
    type: carrier
    owner: Typo
    priority: 1
    prioirty: 2
"#;
        assert!(serde_yaml::from_str::<Config>(yaml).is_err());
    }
}
