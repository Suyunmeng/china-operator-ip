use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
};

use bgpkit_parser::{
    BgpkitParser,
    models::{AsPath, Asn},
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long = "mrt-file", required = true)]
    mrt_files: Vec<PathBuf>,
    #[arg(long = "root-asn", required = true)]
    root_asns: Vec<u32>,
    #[arg(long = "exclude-asn")]
    exclude_asns: Vec<u32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let root_asns = args.root_asns.into_iter().collect();
    let exclude_asns = args.exclude_asns.into_iter().collect();
    let mut prefixes = BTreeSet::new();

    for mrt_file in args.mrt_files {
        let mrt_file = mrt_file.to_string_lossy();
        for elem in BgpkitParser::new(&mrt_file)?.into_elem_iter() {
            if !elem.is_announcement()
                || has_excluded_origin(elem.origin_asns.as_deref(), &exclude_asns)
                || !has_root_or_descendant_origin(elem.as_path.as_ref(), &root_asns)
            {
                continue;
            }
            prefixes.insert(elem.prefix.prefix);
        }
    }

    for prefix in prefixes {
        println!("{prefix}");
    }
    Ok(())
}

fn has_excluded_origin(origins: Option<&[Asn]>, excluded: &HashSet<u32>) -> bool {
    origins.is_some_and(|origins| origins.iter().any(|asn| excluded.contains(&u32::from(asn))))
}

fn has_root_or_descendant_origin(path: Option<&AsPath>, roots: &HashSet<u32>) -> bool {
    path.is_some_and(|path| {
        path.iter_routes::<Vec<Asn>>()
            .any(|route| route.iter().any(|asn| roots.contains(&u32::from(*asn))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_origin_is_filtered() {
        let origins = vec![Asn::new_32bit(23764)];
        assert!(has_excluded_origin(Some(&origins), &HashSet::from([23764])));
    }

    #[test]
    fn matches_the_root_origin() {
        let path = AsPath::from_sequence([4134]);
        assert!(has_root_or_descendant_origin(
            Some(&path),
            &HashSet::from([4134])
        ));
    }

    #[test]
    fn matches_an_arbitrarily_deep_downstream_origin() {
        let path = AsPath::from_sequence([64500, 4134, 65001, 65002]);
        assert!(has_root_or_descendant_origin(
            Some(&path),
            &HashSet::from([4134])
        ));
    }

    #[test]
    fn rejects_a_path_without_a_root() {
        let path = AsPath::from_sequence([64500, 65001]);
        assert!(!has_root_or_descendant_origin(
            Some(&path),
            &HashSet::from([4134])
        ));
    }
}
