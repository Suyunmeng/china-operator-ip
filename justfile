set unstable

collectors := "rrc00 rrc01 rrc03 rrc04 rrc05 rrc06 rrc07 rrc10 rrc11 rrc12 rrc13 rrc14 rrc15 rrc16 rrc18 rrc19 rrc20 rrc21 rrc22 rrc23 rrc24 rrc25 rrc26 route-views2 route-views6"

whois_urls := "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz https://ftp.arin.net/pub/rr/arin.db.gz https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz https://ftp.afrinic.net/dbase/afrinic.db.gz"

default: generate stat

# Compile the classifier without installing input-download tooling.
build:
  cargo build --locked --release

# Install the BGP broker used only while preparing inputs.
dependency: build
  #!/usr/bin/env bash
  set -euo pipefail
  if ! bgpkit-broker --version >/dev/null 2>&1; then
    cargo binstall --secure --no-confirm bgpkit-broker@0.7.0
  fi
  bgpkit-broker --version

# Download the latest RIB snapshot for one RouteViews/RIPE RIS collector.
prepare_rib collector:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p data/bgp
  url="$(bgpkit-broker latest -c "{{collector}}" --json \
    | jq -r '.[] | select(.data_type | contains("rib")) | .url' \
    | head -n 1)"
  test -n "${url}" || { echo "No RIB URL for {{collector}}" >&2; exit 1; }
  case "${url}" in
    *.gz) suffix=.gz ;;
    *.bz2) suffix=.bz2 ;;
    *) echo "Unsupported RIB archive: ${url}" >&2; exit 1 ;;
  esac
  output="data/bgp/rib-{{collector}}${suffix}"
  temporary="${output}.part"
  rm -f "${temporary}"
  curl --fail --location --retry 3 --continue-at - --output "${temporary}" "${url}"
  test -s "${temporary}"
  mv "${temporary}" "${output}"
  printf '%s\n' "${url}" > "${output}.source"

# Download all configured BGP snapshots.
[parallel]
prepare_ribs: (prepare_rib "rrc00") (prepare_rib "rrc01") (prepare_rib "rrc03") (prepare_rib "rrc04") (prepare_rib "rrc05") (prepare_rib "rrc06") (prepare_rib "rrc07") (prepare_rib "rrc10") (prepare_rib "rrc11") (prepare_rib "rrc12") (prepare_rib "rrc13") (prepare_rib "rrc14") (prepare_rib "rrc15") (prepare_rib "rrc16") (prepare_rib "rrc18") (prepare_rib "rrc19") (prepare_rib "rrc20") (prepare_rib "rrc21") (prepare_rib "rrc22") (prepare_rib "rrc23") (prepare_rib "rrc24") (prepare_rib "rrc25") (prepare_rib "rrc26") (prepare_rib "route-views2") (prepare_rib "route-views6")

# Download one authoritative RIR WHOIS bulk snapshot.
prepare_whois_file url:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p data/whois
  url="{{url}}"
  name="${url##*/}"
  case "${url}" in
    *apnic*) name="apnic-${name}" ;;
    *ripe*) name="ripe-${name}" ;;
    *arin*) name="arin-${name}" ;;
    *lacnic*) name="lacnic-${name}" ;;
    *afrinic*) name="afrinic-${name}" ;;
  esac
  output="data/whois/${name}"
  temporary="${output}.part"
  rm -f "${temporary}"
  curl --fail --location --retry 3 --output "${temporary}" "{{url}}"
  test -s "${temporary}"
  gzip -t "${temporary}"
  mv "${temporary}" "${output}"

# Download APNIC, RIPE NCC, ARIN, LACNIC and AFRINIC WHOIS snapshots.
prepare_whois:
  #!/usr/bin/env bash
  set -euo pipefail
  urls=( {{whois_urls}} )
  pids=()
  for url in "${urls[@]}"; do
    just prepare_whois_file "${url}" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "${pid}"
  done

# Prepare all authoritative inputs. Optional Geo CSV is not downloaded automatically.
[parallel]
prepare: prepare_ribs prepare_whois

# Run the complete unsharded pipeline locally.
generate: dependency prepare
  #!/usr/bin/env bash
  set -euo pipefail
  shopt -s nullglob
  ribs=(data/bgp/rib-*.gz data/bgp/rib-*.bz2)
  whois=(data/whois/*.gz)
  ((${#ribs[@]} > 0)) || { echo "No BGP RIB files" >&2; exit 1; }
  ((${#whois[@]} > 0)) || { echo "No RIR WHOIS files" >&2; exit 1; }
  args=(generate --rules operators.yaml --output result)
  for file in "${ribs[@]}"; do args+=(--mrt-file "${file}"); done
  for file in "${whois[@]}"; do args+=(--whois-file "${file}"); done
  if [[ -n "${GEO_FILE:-}" ]]; then
    args+=(--geo-file "${GEO_FILE}")
  fi
  target/release/china-asset-pipeline "${args[@]}"

# Aggregate one deterministic Prefix shard from one configured BGP input group.
extract_bgp shard_index shard_count: build
  #!/usr/bin/env bash
  set -euo pipefail
  shopt -s nullglob
  ribs=()
  if [[ -n "${BGP_COLLECTORS:-}" ]]; then
    for collector in ${BGP_COLLECTORS}; do
      matches=()
      for suffix in gz bz2; do
        file="data/bgp/rib-${collector}.${suffix}"
        [[ -f "${file}" ]] && matches+=("${file}")
      done
      ((${#matches[@]} > 0)) || { echo "No BGP RIB file for ${collector}" >&2; exit 1; }
      ribs+=("${matches[@]}")
    done
  else
    ribs=(data/bgp/rib-*.gz data/bgp/rib-*.bz2)
  fi
  ((${#ribs[@]} > 0)) || { echo "No BGP RIB files" >&2; exit 1; }
  mkdir -p artifacts
  group_name="${BGP_GROUP_NAME:-all}"
  source_group_index="${BGP_SOURCE_GROUP_INDEX:-0}"
  source_group_count="${BGP_SOURCE_GROUP_COUNT:-1}"
  args=(extract-bgp --rules operators.yaml --shard-index "{{shard_index}}" --shard-count "{{shard_count}}" --source-group-index "${source_group_index}" --source-group-count "${source_group_count}" --artifact "artifacts/bgp-shard-${group_name}-{{shard_index}}.json")
  for file in "${ribs[@]}"; do args+=(--mrt-file "${file}"); done
  target/release/china-asset-pipeline "${args[@]}"

# Merge every verified BGP shard, infer families globally, and classify once.
merge_generate: build
  #!/usr/bin/env bash
  set -euo pipefail
  shopt -s nullglob
  artifacts=(artifacts/*.json)
  whois=(data/whois/*.gz)
  ((${#artifacts[@]} > 0)) || { echo "No BGP shard artifacts" >&2; exit 1; }
  ((${#whois[@]} > 0)) || { echo "No RIR WHOIS files" >&2; exit 1; }
  args=(merge-generate --rules operators.yaml --output result)
  for file in "${artifacts[@]}"; do args+=(--artifact "${file}"); done
  for file in "${whois[@]}"; do args+=(--whois-file "${file}"); done
  if [[ -n "${GEO_FILE:-}" ]]; then
    args+=(--geo-file "${GEO_FILE}")
  fi
  target/release/china-asset-pipeline "${args[@]}"

# Verify outputs, including the BGP-only china aggregate and WHOIS-only exceptions.
guard:
  #!/usr/bin/env python3
  import ipaddress
  import json
  from pathlib import Path
  import yaml

  result = Path("result")
  config = yaml.safe_load(Path("operators.yaml").read_text(encoding="utf-8"))
  metadata_files = config.get("settings", {}).get("metadata_files", {})
  china = config.get("settings", {}).get("china", {})
  china_assets = set(china.get("assets", []))
  china_final_upstreams = set(china.get("final_upstream_asn", []))
  if not china_assets or not china_final_upstreams:
      raise SystemExit("settings.china must configure assets and final_upstream_asn")
  owner_file = metadata_files.get("owner", "prefix-owner.jsonl")
  asn_file = metadata_files.get("asn", "prefix-asn.jsonl")
  path_file = metadata_files.get("path", "prefix-path.jsonl")
  family_file = metadata_files.get("family", "asn-family.json")
  required = [
      owner_file, asn_file, path_file,
      family_file, "manifest.json",
      "china.txt", "china6.txt", "china46.txt",
  ]
  for rule in config["assets"].values():
      for basename in rule.get("outputs", []):
          required.extend([
              f"{basename}.txt",
              f"{basename}6.txt",
              f"{basename}46.txt",
          ])
  missing = sorted({name for name in required if not (result / name).is_file()})
  if missing:
      raise SystemExit(f"missing outputs: {', '.join(missing)}")

  announced = set()
  china_v4 = set()
  china_v6 = set()
  metadata = {}
  asn_metadata = {}
  with (result / asn_file).open(encoding="utf-8") as stream:
      for line_number, line in enumerate(stream, 1):
          row = json.loads(line)
          prefix = str(ipaddress.ip_network(row["prefix"], strict=True))
          if prefix in asn_metadata:
              raise SystemExit(f"duplicate ASN metadata prefix: {prefix}")
          asn_metadata[prefix] = row
  with (result / owner_file).open(encoding="utf-8") as stream:
      for line_number, line in enumerate(stream, 1):
          row = json.loads(line)
          prefix = str(ipaddress.ip_network(row["prefix"], strict=True))
          if prefix in metadata:
              raise SystemExit(f"duplicate metadata prefix: {prefix}")
          if row["ip_version"] != ipaddress.ip_network(prefix).version:
              raise SystemExit(f"wrong ip_version at line {line_number}: {prefix}")
          if row.get("announced", True) is not True:
              if config["assets"].get(row["asset"], {}).get("require_announced", True):
                  raise SystemExit(f"non-announced prefix classified by announced-only asset: {prefix}")
          if row.get("announced", True) and config["assets"].get(row["asset"], {}).get("exclude_announced", False):
              raise SystemExit(f"announced prefix classified by unannounced-only asset: {prefix}")
          if not row.get("origin_asn") and row.get("announced", True):
              raise SystemExit(f"missing origin ASN: {prefix}")
          if not row.get("whois_org") and not row.get("netname") and not row.get("org_id") and not row.get("maintainer"):
              if row.get("match_source") not in {"routing-origin-asn", "exclusive-immediate-upstream-asn"}:
                  raise SystemExit(f"missing WHOIS owner evidence: {prefix}")
          upstreams = row.get("observed_immediate_upstream_asn")
          if not isinstance(upstreams, list) or any(not isinstance(asn, int) or asn <= 0 for asn in upstreams):
              raise SystemExit(f"invalid immediate upstream ASN evidence: {prefix}")
          if upstreams != sorted(set(upstreams)):
              raise SystemExit(f"unsorted or duplicate immediate upstream ASN evidence: {prefix}")
          complete = row.get("immediate_upstream_evidence_complete")
          if not isinstance(complete, bool):
              raise SystemExit(f"missing immediate upstream evidence completeness: {prefix}")
          final_upstreams = row.get("observed_final_upstream_asn")
          if not isinstance(final_upstreams, list) or any(not isinstance(asn, int) or asn <= 0 for asn in final_upstreams):
              raise SystemExit(f"invalid final upstream ASN evidence: {prefix}")
          if final_upstreams != sorted(set(final_upstreams)):
              raise SystemExit(f"unsorted or duplicate final upstream ASN evidence: {prefix}")
          if not set(final_upstreams).issubset(china_final_upstreams):
              raise SystemExit(f"final upstream outside configured China roots: {prefix}")
          expected_china_membership = row.get("announced", True) and (
              row["asset"] in china_assets or bool(final_upstreams)
          )
          if row.get("include_in_china") != expected_china_membership:
              raise SystemExit(f"China aggregate provenance mismatch: {prefix}")
          rule = config["assets"].get(row["asset"], {})
          routing = rule.get("routing", {}) or {}
          source = row.get("match_source")
          if source == "routing-origin-asn":
              direct = set(routing.get("direct_origin_asn", []))
              observed_origins = set(asn_metadata.get(prefix, {}).get("observed_origin_asn", []))
              if not direct.intersection(observed_origins):
                  raise SystemExit(f"routing origin provenance mismatch: {prefix}")
          elif source == "exclusive-immediate-upstream-asn":
              expected = sorted(set(routing.get("exclusive_immediate_upstream_asn", [])))
              if not complete or upstreams != expected:
                  raise SystemExit(f"exclusive upstream provenance mismatch: {prefix}")
          elif not row.get("whois_org") and not row.get("netname") and not row.get("org_id") and not row.get("maintainer"):
              raise SystemExit(f"missing WHOIS owner evidence: {prefix}")
          metadata[prefix] = row
          if row.get("announced", True) is not True:
              if config["assets"].get(row["asset"], {}).get("require_announced", True):
                  raise SystemExit(f"non-announced prefix classified by announced-only asset: {prefix}")
          else:
              announced.add(prefix)
          if row.get("announced", True) and row.get("include_in_china", True):
              if row["ip_version"] == 4:
                  china_v4.add(prefix)
              else:
                  china_v6.add(prefix)
  if not metadata:
      raise SystemExit(f"{owner_file} is empty")

  path_metadata = {}
  with (result / path_file).open(encoding="utf-8") as stream:
      for line_number, line in enumerate(stream, 1):
          row = json.loads(line)
          prefix = str(ipaddress.ip_network(row["prefix"], strict=True))
          if prefix in path_metadata:
              raise SystemExit(f"duplicate path metadata prefix: {prefix}")
          if prefix not in metadata:
              raise SystemExit(f"path metadata has unknown prefix: {prefix}")
          upstreams = row.get("observed_immediate_upstream_asn")
          if not isinstance(upstreams, list) or upstreams != sorted(set(upstreams)):
              raise SystemExit(f"invalid path immediate upstream evidence: {prefix}")
          if upstreams != metadata[prefix]["observed_immediate_upstream_asn"]:
              raise SystemExit(f"owner/path upstream evidence mismatch: {prefix}")
          if row.get("immediate_upstream_evidence_complete") != metadata[prefix]["immediate_upstream_evidence_complete"]:
              raise SystemExit(f"owner/path evidence completeness mismatch: {prefix}")
          if row.get("observed_final_upstream_asn") != metadata[prefix]["observed_final_upstream_asn"]:
              raise SystemExit(f"owner/path final-upstream evidence mismatch: {prefix}")
          path_metadata[prefix] = row
  if set(path_metadata) != set(metadata):
      raise SystemExit(f"{path_file} does not cover exactly the owner metadata prefixes")

  expected_china = {
      "china.txt": china_v4,
      "china6.txt": china_v6,
      "china46.txt": china_v4 | china_v6,
  }
  expected_outputs = {}
  for asset, rule in config["assets"].items():
      basenames = rule.get("outputs", [])
      prefixes = {
          prefix for prefix, row in metadata.items() if row["asset"] == asset
      }
      versions = {
          4: {prefix for prefix in prefixes if metadata[prefix]["ip_version"] == 4},
          6: {prefix for prefix in prefixes if metadata[prefix]["ip_version"] == 6},
      }
      for basename in basenames:
          expected_outputs.setdefault(f"{basename}.txt", set()).update(versions[4])
          expected_outputs.setdefault(f"{basename}6.txt", set()).update(versions[6])
          expected_outputs.setdefault(f"{basename}46.txt", set()).update(prefixes)
  expected_outputs.update(expected_china)

  for name, expected in expected_outputs.items():
      path = result / name
      if not path.is_file():
          raise SystemExit(f"missing configured output: {name}")
      actual = {
          str(ipaddress.ip_network(line, strict=True))
          for line in path.read_text(encoding="utf-8").splitlines()
          if line
      }
      if actual != expected:
          raise SystemExit(
              f"{name} differs from classified metadata: "
              f"missing={len(expected - actual)} extra={len(actual - expected)}"
          )

  for path in result.glob("*.txt"):
      if path.name.startswith('.'):
          continue
      for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
          prefix = str(ipaddress.ip_network(line, strict=True))
          if prefix not in metadata:
              raise SystemExit(f"{path}:{line_number}: not present in classified metadata: {prefix}")
  print(f"guard passed: {len(metadata)} classified BGP prefixes")

# Summarize prefix counts and IPv4/IPv6 address space by list.
stat:
  #!/usr/bin/env python3
  import ipaddress
  from pathlib import Path

  result = Path("result")
  lines = []
  for path in sorted(result.glob("*.txt")):
      if path.name.endswith("46.txt") or path.name.startswith('.'):
          continue
      networks = [ipaddress.ip_network(line) for line in path.read_text().splitlines() if line]
      lines.extend((path.stem, f"prefixes={len(networks)} addresses={sum(item.num_addresses for item in networks)}", ""))
  report = "\n".join(lines)
  print(report)
  (result / "stat").write_text(report + "\n", encoding="utf-8")

# Run deterministic local validation without downloading daily data.
check:
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-targets

# Publish a complete staged result only after validation succeeds.
upload: guard
  #!/usr/bin/env bash
  set -euo pipefail
  test -d ip-lists/.git || { echo "ip-lists worktree is missing" >&2; exit 1; }
  staging="$(mktemp -d)"
  trap 'rm -rf "${staging}"' EXIT
  cp -a result/. "${staging}/"
  cd ip-lists
  find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -a "${staging}/." .
  git config user.name "GitHub Actions"
  git config user.email noreply@github.com
  git add --all
  if git diff --cached --quiet; then
    echo "No generated changes"
    exit 0
  fi
  git commit -m "update $(date -u +%Y-%m-%d)"
  git push --atomic origin HEAD:ip-lists

# Refresh jsDelivr cache after a successful publish.
refresh_jsdelivr repository:
  #!/usr/bin/env ruby
  require "net/http"
  Dir.children("ip-lists").sort.each do |file|
    warn "INFO> purging CDN cache for #{file}"
    puts Net::HTTP.get_response(URI("https://purge.jsdelivr.net/gh/{{repository}}@ip-lists/#{file}")).inspect
  end
