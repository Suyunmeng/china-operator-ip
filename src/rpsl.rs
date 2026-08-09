use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::model::{AsnRecord, WhoisRecord};

#[derive(Debug, Clone)]
pub struct WhoisIndex {
    v4: Vec<HashMap<Ipv4Net, WhoisRecord>>,
    v6: Vec<HashMap<Ipv6Net, WhoisRecord>>,
    asns: BTreeMap<u32, AsnRecord>,
}

impl WhoisIndex {
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut organisations = HashMap::new();
        for path in paths {
            let rir = rir_from_path(path);
            for_each_object(path, |object| {
                if let Some((id, name)) = parse_organisation(object) {
                    organisations.insert((rir.clone(), id.to_ascii_uppercase()), name);
                }
                Ok(())
            })?;
        }

        let mut index = Self {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
            asns: BTreeMap::new(),
        };
        for path in paths {
            let rir = rir_from_path(path);
            let source = source_from_path(path);
            for_each_object(path, |object| {
                let prefixes = parse_prefixes(object);
                if !prefixes.is_empty() {
                    let org_id = parse_org_id(object);
                    let whois_org = org_id
                        .as_ref()
                        .and_then(|id| organisations.get(&(rir.clone(), id.to_ascii_uppercase())))
                        .cloned()
                        .or_else(|| organisation_name(object))
                        .or_else(|| first(object, "owner"))
                        .or_else(|| first(object, "descr"));
                    for prefix in prefixes {
                        index.insert_prefix(WhoisRecord {
                            prefix: Some(prefix),
                            rir: rir.clone(),
                            source: source.clone(),
                            country: first(object, "country").map(normalize_country),
                            netname: first(object, "netname"),
                            org_id: org_id.clone(),
                            whois_org: whois_org.clone(),
                            maintainers: all(
                                object,
                                &["mnt-by", "mnt-lower", "mnt-routes", "tech-c", "admin-c"],
                            ),
                            descr: descriptions(object),
                        });
                    }
                } else if let Some(asn) = parse_asn(object) {
                    let org_id = parse_org_id(object);
                    let organisation = org_id
                        .as_ref()
                        .and_then(|id| organisations.get(&(rir.clone(), id.to_ascii_uppercase())))
                        .cloned()
                        .or_else(|| organisation_name(object))
                        .or_else(|| first(object, "owner"));
                    let candidate = AsnRecord {
                        asn,
                        rir: rir.clone(),
                        source: source.clone(),
                        country: first(object, "country").map(normalize_country),
                        as_name: first(object, "as-name")
                            .or_else(|| first(object, "asname"))
                            .or_else(|| first(object, "aut-num")),
                        org_id,
                        organisation,
                        maintainers: all(
                            object,
                            &["mnt-by", "mnt-lower", "mnt-routes", "tech-c", "admin-c"],
                        ),
                        descr: descriptions(object),
                    };
                    insert_richer(&mut index.asns, asn, candidate, asn_record_score);
                }
                Ok(())
            })?;
        }
        Ok(index)
    }

    pub fn lookup(&self, prefix: IpNet) -> Option<&WhoisRecord> {
        match prefix {
            IpNet::V4(prefix) => (0..=prefix.prefix_len()).rev().find_map(|length| {
                let candidate = Ipv4Net::new(prefix.network(), length).ok()?.trunc();
                self.v4[length as usize].get(&candidate)
            }),
            IpNet::V6(prefix) => (0..=prefix.prefix_len()).rev().find_map(|length| {
                let candidate = Ipv6Net::new(prefix.network(), length).ok()?.trunc();
                self.v6[length as usize].get(&candidate)
            }),
        }
    }

    pub fn prefixes(&self) -> impl Iterator<Item = &WhoisRecord> {
        self.v4
            .iter()
            .flat_map(|records| records.values())
            .chain(self.v6.iter().flat_map(|records| records.values()))
    }

    pub fn asns(&self) -> &BTreeMap<u32, AsnRecord> {
        &self.asns
    }

    pub fn is_empty(&self) -> bool {
        self.v4.iter().all(HashMap::is_empty) && self.v6.iter().all(HashMap::is_empty)
    }

    fn insert_prefix(&mut self, record: WhoisRecord) {
        match record.prefix.expect("prefix record must contain a prefix") {
            IpNet::V4(prefix) => insert_richer(
                &mut self.v4[prefix.prefix_len() as usize],
                prefix,
                record,
                whois_record_score,
            ),
            IpNet::V6(prefix) => insert_richer(
                &mut self.v6[prefix.prefix_len() as usize],
                prefix,
                record,
                whois_record_score,
            ),
        }
    }
}

type Object = HashMap<String, Vec<String>>;

fn for_each_object(path: &Path, mut callback: impl FnMut(&Object) -> Result<()>) -> Result<()> {
    let reader = open_reader(path)?;
    let mut object = Object::new();
    let mut last_key: Option<String> = None;

    let mut reader = BufReader::new(reader);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .with_context(|| format!("failed reading {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buffer);
        let line = line.trim_end();
        if line.is_empty() {
            if !object.is_empty() {
                callback(&object)?;
                object.clear();
            }
            last_key = None;
            continue;
        }
        if line.starts_with('#') || line.starts_with('%') {
            continue;
        }
        if line.starts_with(char::is_whitespace) || line.starts_with('+') {
            if let Some(key) = &last_key
                && let Some(value) = object.get_mut(key).and_then(|values| values.last_mut())
            {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        object
            .entry(key.clone())
            .or_default()
            .push(value.trim().to_string());
        last_key = Some(key);
    }
    if !object.is_empty() {
        callback(&object)?;
    }
    Ok(())
}

fn open_reader(path: &Path) -> Result<Box<dyn Read>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
    {
        Ok(Box::new(GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}

fn parse_prefixes(object: &Object) -> Vec<IpNet> {
    if let Some(value) = first(object, "inet6num") {
        return parse_network_or_range(&value);
    }
    if let Some(value) = first(object, "inetnum") {
        return parse_network_or_range(&value);
    }
    if let Some(value) = first(object, "cidr") {
        return value
            .split(',')
            .filter_map(|item| IpNet::from_str(item.trim()).ok())
            .collect();
    }
    if let Some(value) = first(object, "netrange") {
        return parse_network_or_range(&value);
    }
    Vec::new()
}

fn parse_network_or_range(value: &str) -> Vec<IpNet> {
    if let Ok(network) = IpNet::from_str(value.trim()) {
        return vec![network.trunc()];
    }
    let Some((start, end)) = value.split_once('-') else {
        return Vec::new();
    };
    let (Ok(start), Ok(end)) = (start.trim().parse(), end.trim().parse()) else {
        return Vec::new();
    };
    summarize_range(start, end)
}

fn summarize_range(start: IpAddr, end: IpAddr) -> Vec<IpNet> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => summarize_v4(start, end),
        (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => summarize_v6(start, end),
        _ => Vec::new(),
    }
}

fn summarize_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpNet> {
    let mut current = u32::from(start) as u128;
    let end = u32::from(end) as u128;
    let mut prefixes = Vec::new();
    while current <= end {
        let host_bits = largest_host_bits(current, end, 32);
        prefixes.push(IpNet::V4(
            Ipv4Net::new(Ipv4Addr::from(current as u32), (32 - host_bits) as u8).unwrap(),
        ));
        let block_size = 1u128 << host_bits;
        if current + block_size > end {
            break;
        }
        current += block_size;
    }
    prefixes
}

fn summarize_v6(start: Ipv6Addr, end: Ipv6Addr) -> Vec<IpNet> {
    let mut current = u128::from(start);
    let end = u128::from(end);
    let mut prefixes = Vec::new();
    while current <= end {
        let host_bits = largest_host_bits(current, end, 128);
        prefixes.push(IpNet::V6(
            Ipv6Net::new(Ipv6Addr::from(current), (128 - host_bits) as u8).unwrap(),
        ));
        if host_bits == 128 {
            break;
        }
        let block_size = 1u128 << host_bits;
        let Some(next) = current.checked_add(block_size) else {
            break;
        };
        if next > end {
            break;
        }
        current = next;
    }
    prefixes
}

fn largest_host_bits(start: u128, end: u128, bits: u32) -> u32 {
    let aligned = if start == 0 {
        bits
    } else {
        start.trailing_zeros().min(bits)
    };
    let count = end
        .checked_sub(start)
        .and_then(|value| value.checked_add(1));
    let fitting = count.map_or(bits, |count| count.ilog2().min(bits));
    aligned.min(fitting).min(bits)
}

fn parse_asn(object: &Object) -> Option<u32> {
    let value = first(object, "aut-num").or_else(|| first(object, "asnumber"))?;
    value
        .trim()
        .trim_start_matches(|character: char| character.eq_ignore_ascii_case(&'a'))
        .trim_start_matches(|character: char| character.eq_ignore_ascii_case(&'s'))
        .parse()
        .ok()
}

fn parse_organisation(object: &Object) -> Option<(String, String)> {
    if let Some(id) = first(object, "organisation") {
        let name = first(object, "org-name")
            .or_else(|| first(object, "descr"))
            .unwrap_or_else(|| id.clone());
        return Some((id, name));
    }
    let id = first(object, "orgid")?;
    let name = first(object, "orgname").unwrap_or_else(|| id.clone());
    Some((id, name))
}

fn parse_org_id(object: &Object) -> Option<String> {
    first(object, "org")
        .or_else(|| first(object, "orgid"))
        .or_else(|| {
            first(object, "organization").and_then(|value| {
                value
                    .rsplit_once('(')
                    .and_then(|(_, suffix)| suffix.strip_suffix(')'))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
        })
        .or_else(|| first(object, "ownerid"))
}

fn organisation_name(object: &Object) -> Option<String> {
    first(object, "org-name")
        .or_else(|| first(object, "orgname"))
        .or_else(|| {
            first(object, "organization").map(|value| {
                value
                    .rsplit_once('(')
                    .map_or(value.as_str(), |(name, _)| name)
                    .trim()
                    .to_string()
            })
        })
}

fn descriptions(object: &Object) -> Vec<String> {
    let mut values = all(object, &["descr", "remarks"]);
    if let Some(value) = first(object, "customer") {
        values.push(value);
    }
    values.sort();
    values.dedup();
    values
}

fn first(object: &Object, key: &str) -> Option<String> {
    object.get(key).and_then(|values| values.first()).cloned()
}

fn all(object: &Object, keys: &[&str]) -> Vec<String> {
    let mut values: Vec<_> = keys
        .iter()
        .flat_map(|key| object.get(*key).into_iter().flatten().cloned())
        .collect();
    values.sort();
    values.dedup();
    values
}

fn normalize_country(value: String) -> String {
    value.trim().to_ascii_uppercase()
}

fn rir_from_path(path: &Path) -> String {
    let name = source_from_path(path).to_ascii_lowercase();
    ["apnic", "ripe", "arin", "lacnic", "afrinic"]
        .into_iter()
        .find(|rir| name.contains(rir))
        .unwrap_or("unknown")
        .to_ascii_uppercase()
}

fn source_from_path(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn whois_record_score(record: &WhoisRecord) -> usize {
    usize::from(record.country.is_some())
        + usize::from(record.netname.is_some())
        + usize::from(record.org_id.is_some()) * 2
        + usize::from(record.whois_org.is_some()) * 2
        + record.maintainers.len()
        + record.descr.len()
}

fn asn_record_score(record: &AsnRecord) -> usize {
    usize::from(record.country.is_some())
        + usize::from(record.as_name.is_some())
        + usize::from(record.org_id.is_some()) * 2
        + usize::from(record.organisation.is_some()) * 2
        + record.maintainers.len()
        + record.descr.len()
}

fn insert_richer<K: std::cmp::Ord, V>(
    map: &mut impl RichMap<K, V>,
    key: K,
    candidate: V,
    score: fn(&V) -> usize,
) {
    if map
        .get_value(&key)
        .is_none_or(|current| score(&candidate) > score(current))
    {
        map.insert_value(key, candidate);
    }
}

trait RichMap<K, V> {
    fn get_value(&self, key: &K) -> Option<&V>;
    fn insert_value(&mut self, key: K, value: V);
}

impl<K: std::cmp::Ord, V> RichMap<K, V> for BTreeMap<K, V> {
    fn get_value(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    fn insert_value(&mut self, key: K, value: V) {
        self.insert(key, value);
    }
}

impl<K: std::cmp::Eq + std::hash::Hash, V> RichMap<K, V> for HashMap<K, V> {
    fn get_value(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    fn insert_value(&mut self, key: K, value: V) {
        self.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn parses_rpsl_and_prefers_longest_prefix() {
        let mut file = tempfile::Builder::new()
            .suffix("-apnic.db")
            .tempfile()
            .unwrap();
        writeln!(
            file,
            "organisation: ORG-EXAMPLE\norg-name: Example Cloud\n\ninetnum: 203.0.113.0 - 203.0.113.255\nnetname: EXAMPLE\ncountry: CN\norg: ORG-EXAMPLE\nmnt-by: MAINT-EXAMPLE\n\ninetnum: 203.0.113.0 - 203.0.113.127\nnetname: EXAMPLE-SPECIFIC\ncountry: CN\norg: ORG-EXAMPLE\n\naut-num: AS64500\nas-name: EXAMPLE-AS\ncountry: CN\norg: ORG-EXAMPLE\n"
        )
        .unwrap();
        let index = WhoisIndex::load(&[file.path().to_path_buf()]).unwrap();
        let record = index.lookup("203.0.113.0/25".parse().unwrap()).unwrap();
        assert_eq!(record.netname.as_deref(), Some("EXAMPLE-SPECIFIC"));
        assert_eq!(record.whois_org.as_deref(), Some("Example Cloud"));
        assert_eq!(record.rir, "APNIC");
        assert_eq!(
            index.asns().get(&64500).unwrap().as_name.as_deref(),
            Some("EXAMPLE-AS")
        );
    }

    #[test]
    fn unaligned_ranges_are_exactly_summarized() {
        let object = HashMap::from([(
            "inetnum".to_string(),
            vec!["203.0.113.1 - 203.0.113.254".to_string()],
        )]);
        let prefixes = parse_prefixes(&object);
        assert_eq!(prefixes.first().unwrap().to_string(), "203.0.113.1/32");
        assert_eq!(prefixes.last().unwrap().to_string(), "203.0.113.254/32");
        assert!(prefixes.iter().all(|prefix| {
            prefix.network() >= "203.0.113.1".parse::<IpAddr>().unwrap()
                && prefix.broadcast() <= "203.0.113.254".parse::<IpAddr>().unwrap()
        }));
    }

    #[test]
    fn lookup_finds_less_specific_parent_prefix() {
        let mut index = WhoisIndex {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
            asns: BTreeMap::new(),
        };
        index.insert_prefix(WhoisRecord {
            prefix: Some("203.0.112.0/23".parse().unwrap()),
            rir: "APNIC".to_string(),
            source: "test".to_string(),
            country: Some("CN".to_string()),
            netname: Some("PARENT".to_string()),
            ..WhoisRecord::default()
        });
        assert_eq!(
            index
                .lookup("203.0.113.0/24".parse().unwrap())
                .unwrap()
                .netname
                .as_deref(),
            Some("PARENT")
        );
    }

    #[test]
    fn full_ipv6_range_summarizes_to_default_route() {
        assert_eq!(
            summarize_range(
                "::".parse::<IpAddr>().unwrap(),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                    .parse::<IpAddr>()
                    .unwrap(),
            ),
            vec!["::/0".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn non_utf8_whois_text_is_decoded_lossily() {
        let mut file = tempfile::Builder::new()
            .suffix("-lacnic.db")
            .tempfile()
            .unwrap();
        file.write_all(
            b"inetnum: 200.0.0.0 - 200.0.0.255\nowner: Example \xff Network\ncountry: CN\n\n",
        )
        .unwrap();
        let index = WhoisIndex::load(&[file.path().to_path_buf()]).unwrap();
        let record = index.lookup("200.0.0.0/24".parse().unwrap()).unwrap();
        assert_eq!(record.country.as_deref(), Some("CN"));
        assert!(record.whois_org.as_deref().unwrap().contains("Example"));
    }

    #[test]
    fn arin_multiple_cidrs_and_organisation_are_supported() {
        let object = HashMap::from([
            (
                "cidr".to_string(),
                vec!["198.51.100.0/25, 198.51.100.128/25".to_string()],
            ),
            (
                "organization".to_string(),
                vec!["Example Incorporated (EXAMPLE-1)".to_string()],
            ),
        ]);
        assert_eq!(parse_prefixes(&object).len(), 2);
        assert_eq!(parse_org_id(&object).as_deref(), Some("EXAMPLE-1"));
        assert_eq!(
            organisation_name(&object).as_deref(),
            Some("Example Incorporated")
        );
    }
}
