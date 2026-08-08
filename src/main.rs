use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use bgpkit_parser::BgpkitParser;
use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Parser)]
struct Args {
    #[arg(long = "mrt-file", required = true)]
    mrt_files: Vec<PathBuf>,
    #[arg(long = "network-file")]
    network_file: PathBuf,
    #[arg(long = "exclude-asn")]
    exclude_asns: Vec<u32>,
}

#[derive(Clone, Copy)]
struct Range {
    start: u128,
    end: u128,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let exclude_asns: HashSet<u32> = args.exclude_asns.into_iter().collect();
    let registered = read_networks(&args.network_file)?;
    let mut registered_v4 = Vec::new();
    let mut registered_v6 = Vec::new();
    for network in registered {
        match network {
            IpNet::V4(network) => registered_v4.push(range_v4(network)),
            IpNet::V6(network) => registered_v6.push(range_v6(network)),
        }
    }

    let mut announced_v4 = Vec::new();
    let mut announced_v6 = Vec::new();
    for mrt_file in args.mrt_files {
        let mrt_file = mrt_file.to_string_lossy();
        for elem in BgpkitParser::new(&mrt_file)?.into_elem_iter() {
            if !elem.is_announcement()
                || has_excluded_origin(elem.origin_asns.as_deref(), &exclude_asns)
            {
                continue;
            }
            match elem.prefix.prefix {
                IpNet::V4(network) => announced_v4.push(range_v4(network)),
                IpNet::V6(network) => announced_v6.push(range_v6(network)),
            }
        }
    }

    for network in summarize(
        intersect(merge(registered_v4), merge(announced_v4)),
        32,
        false,
    ) {
        println!("{network}");
    }
    for network in summarize(
        intersect(merge(registered_v6), merge(announced_v6)),
        128,
        true,
    ) {
        println!("{network}");
    }
    Ok(())
}

fn has_excluded_origin(
    origins: Option<&[bgpkit_parser::models::Asn]>,
    excluded: &HashSet<u32>,
) -> bool {
    origins.is_some_and(|origins| origins.iter().any(|asn| excluded.contains(&u32::from(asn))))
}

fn read_networks(path: &PathBuf) -> Result<Vec<IpNet>, Box<dyn std::error::Error>> {
    BufReader::new(File::open(path)?)
        .lines()
        .filter(|line| !line.as_ref().is_ok_and(|line| line.trim().is_empty()))
        .map(|line| Ok(line?.trim().parse()?))
        .collect()
}

fn range_v4(network: Ipv4Net) -> Range {
    Range {
        start: u32::from(network.network()) as u128,
        end: u32::from(network.broadcast()) as u128,
    }
}

fn range_v6(network: Ipv6Net) -> Range {
    let host_bits = 128 - network.prefix_len();
    let host_mask = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    Range {
        start: u128::from(network.network()),
        end: u128::from(network.network()) | host_mask,
    }
}

fn merge(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn intersect(left: Vec<Range>, right: Vec<Range>) -> Vec<Range> {
    let mut intersections = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        let a = left[i];
        let b = right[j];
        if a.end < b.start {
            i += 1;
        } else if b.end < a.start {
            j += 1;
        } else {
            intersections.push(Range {
                start: a.start.max(b.start),
                end: a.end.min(b.end),
            });
            if a.end < b.end {
                i += 1;
            } else {
                j += 1;
            }
        }
    }
    intersections
}

fn summarize(ranges: Vec<Range>, bits: u32, ipv6: bool) -> Vec<IpNet> {
    let mut networks = Vec::new();
    for range in merge(ranges) {
        let mut start = range.start;
        while start <= range.end {
            let host_bits = largest_block(start, range.end, bits);
            let prefix_len = (bits - host_bits) as u8;
            let network = if ipv6 {
                IpNet::V6(Ipv6Net::new(Ipv6Addr::from(start), prefix_len).unwrap())
            } else {
                IpNet::V4(Ipv4Net::new(Ipv4Addr::from(start as u32), prefix_len).unwrap())
            };
            networks.push(network);
            if host_bits == bits {
                break;
            }
            start += 1u128 << host_bits;
        }
    }
    networks
}

fn largest_block(start: u128, end: u128, bits: u32) -> u32 {
    let aligned_bits = if start == 0 {
        bits
    } else {
        start.trailing_zeros().min(bits)
    };
    let mut host_bits = 0;
    while host_bits < aligned_bits {
        let next = host_bits + 1;
        if next == bits {
            if start == 0 && end == u128::MAX {
                host_bits = next;
            }
            break;
        }
        let block_size = (1u128 << next) - 1;
        if block_size <= end - start {
            host_bits = next;
        } else {
            break;
        }
    }
    host_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn ipv4_intersection_keeps_only_announced_addresses() {
        let registered = vec![range_v4(Ipv4Net::from_str("192.0.2.0/24").unwrap())];
        let announced = vec![range_v4(Ipv4Net::from_str("192.0.2.0/25").unwrap())];
        let result = summarize(intersect(registered, announced), 32, false);
        assert_eq!(result, vec![IpNet::from_str("192.0.2.0/25").unwrap()]);
    }

    #[test]
    fn ipv6_intersection_keeps_only_announced_addresses() {
        let registered = vec![range_v6(Ipv6Net::from_str("2001:db8::/32").unwrap())];
        let announced = vec![range_v6(Ipv6Net::from_str("2001:db8:1::/48").unwrap())];
        let result = summarize(intersect(registered, announced), 128, true);
        assert_eq!(result, vec![IpNet::from_str("2001:db8:1::/48").unwrap()]);
    }

    #[test]
    fn excluded_origin_is_filtered() {
        let excluded = HashSet::from([64500]);
        let origins = vec![bgpkit_parser::models::Asn::new_32bit(64500)];
        assert!(has_excluded_origin(Some(&origins), &excluded));
    }

    #[test]
    fn other_origin_is_kept() {
        let excluded = HashSet::from([64500]);
        let origins = vec![bgpkit_parser::models::Asn::new_32bit(64501)];
        assert!(!has_excluded_origin(Some(&origins), &excluded));
    }

    #[test]
    fn adjacent_announcements_are_recombined_without_leaving_registered_range() {
        let registered = vec![range_v4(Ipv4Net::from_str("198.51.100.0/24").unwrap())];
        let announced = vec![
            range_v4(Ipv4Net::from_str("198.51.100.0/25").unwrap()),
            range_v4(Ipv4Net::from_str("198.51.100.128/25").unwrap()),
        ];
        let result = summarize(intersect(registered, announced), 32, false);
        assert_eq!(result, vec![IpNet::from_str("198.51.100.0/24").unwrap()]);
    }
}
