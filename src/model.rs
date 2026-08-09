use std::collections::BTreeSet;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BgpObservation {
    pub prefix: IpNet,
    pub origin_asns: BTreeSet<u32>,
    pub observed_origin_asns: BTreeSet<u32>,
    pub asn_path: Vec<u32>,
    pub transit_asns: BTreeSet<u32>,
    pub peer_asns: BTreeSet<u32>,
    pub collectors: BTreeSet<String>,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WhoisRecord {
    pub prefix: Option<IpNet>,
    pub rir: String,
    pub source: String,
    pub country: Option<String>,
    pub netname: Option<String>,
    pub org_id: Option<String>,
    pub whois_org: Option<String>,
    pub maintainers: Vec<String>,
    pub descr: Vec<String>,
}

impl WhoisRecord {
    pub fn searchable_owner_text(&self) -> String {
        let mut values = Vec::new();
        values.extend(self.whois_org.iter().cloned());
        values.extend(self.netname.iter().cloned());
        values.extend(self.org_id.iter().cloned());
        values.extend(self.maintainers.iter().cloned());
        values.extend(self.descr.iter().cloned());
        values.join(" ")
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AsnRecord {
    pub asn: u32,
    pub rir: String,
    pub source: String,
    pub country: Option<String>,
    pub as_name: Option<String>,
    pub org_id: Option<String>,
    pub organisation: Option<String>,
    pub maintainers: Vec<String>,
    pub descr: Vec<String>,
}

impl AsnRecord {
    pub fn searchable_text(&self) -> String {
        let mut values = Vec::new();
        values.extend(self.as_name.iter().cloned());
        values.extend(self.org_id.iter().cloned());
        values.extend(self.organisation.iter().cloned());
        values.extend(self.maintainers.iter().cloned());
        values.extend(self.descr.iter().cloned());
        values.join(" ")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub subdivision: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub asset: String,
    pub owner: String,
    pub asset_type: String,
    pub operator_family: Option<String>,
    pub match_rule: String,
    pub match_source: String,
    pub confidence_score: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrefixMetadata {
    pub prefix: IpNet,
    pub ip_version: u8,
    pub asset: String,
    pub origin_asn: Vec<u32>,
    pub asn_path: Vec<u32>,
    pub owner: String,
    pub asset_type: String,
    pub include_in_china: bool,
    pub operator_family: Option<String>,
    pub whois_org: Option<String>,
    pub org_id: Option<String>,
    pub maintainer: Vec<String>,
    pub netname: Option<String>,
    pub rir: String,
    pub country: Option<String>,
    pub geo_location: Option<GeoLocation>,
    pub match_rule: String,
    pub match_source: String,
    pub confidence_score: u8,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrefixAsnMetadata {
    pub prefix: IpNet,
    pub origin_asn: Vec<u32>,
    pub observed_origin_asn: Vec<u32>,
    pub origin_asn_family: Vec<String>,
    pub peer_asn: Vec<u32>,
    pub collectors: Vec<String>,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrefixPathMetadata {
    pub prefix: IpNet,
    pub origin_asn: Vec<u32>,
    pub asn_path: Vec<u32>,
    pub transit_asn: Vec<u32>,
    pub peer_asn: Vec<u32>,
    pub collectors: Vec<String>,
    pub last_seen: i64,
}
