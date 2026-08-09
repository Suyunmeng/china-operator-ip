set unstable

collectors := "rrc00 rrc12 rrc21 route-views2 route-views6"

whois_urls := "https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz https://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz https://ftp.arin.net/pub/rr/arin.db.gz https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz https://ftp.afrinic.net/dbase/afrinic.db.gz"

default: generate stat

# Install the BGP broker and compile the classifier.
dependency:
  #!/usr/bin/env bash
  set -euo pipefail
  if ! bgpkit-broker --version >/dev/null 2>&1; then
    cargo binstall --secure --no-confirm bgpkit-broker@0.7.0
  fi
  cargo build --locked --release
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
prepare_ribs: (prepare_rib "rrc00") (prepare_rib "rrc12") (prepare_rib "rrc21") (prepare_rib "route-views2") (prepare_rib "route-views6")

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

# Run the BGP-first asset classification pipeline.
generate: dependency prepare
  #!/usr/bin/env bash
  set -euo pipefail
  shopt -s nullglob
  ribs=(data/bgp/rib-*.gz data/bgp/rib-*.bz2)
  whois=(data/whois/*.gz)
  ((${#ribs[@]} > 0)) || { echo "No BGP RIB files" >&2; exit 1; }
  ((${#whois[@]} > 0)) || { echo "No RIR WHOIS files" >&2; exit 1; }
  args=(--rules operators.yaml --output result)
  for file in "${ribs[@]}"; do args+=(--mrt-file "${file}"); done
  for file in "${whois[@]}"; do args+=(--whois-file "${file}"); done
  if [[ -n "${GEO_FILE:-}" ]]; then
    args+=(--geo-file "${GEO_FILE}")
  fi
  target/release/china-asset-pipeline "${args[@]}"

# Verify outputs and the invariant that every emitted CIDR is an exact observed BGP prefix.
guard:
  #!/usr/bin/env python3
  import ipaddress
  import json
  from pathlib import Path
  import yaml

  result = Path("result")
  config = yaml.safe_load(Path("operators.yaml").read_text(encoding="utf-8"))
  metadata_files = config.get("settings", {}).get("metadata_files", {})
  owner_file = metadata_files.get("owner", "prefix-owner.jsonl")
  asn_file = metadata_files.get("asn", "prefix-asn.jsonl")
  path_file = metadata_files.get("path", "prefix-path.jsonl")
  family_file = metadata_files.get("family", "asn-family.json")
  required = [
      "china.txt", "china6.txt", "china46.txt",
      "chinanet.txt", "chinanet6.txt", "chinanet46.txt",
      "telecom.txt", "cmcc.txt", "unicom.txt", "cernet.txt", "cstnet.txt",
      "cloudflare.txt", "aliyun.txt", "tencent.txt", "ucloud.txt", "ixp.txt",
      owner_file, asn_file, path_file,
      family_file, "manifest.json",
  ]
  missing = [name for name in required if not (result / name).is_file()]
  if missing:
      raise SystemExit(f"missing outputs: {', '.join(missing)}")

  announced = set()
  china_v4 = set()
  china_v6 = set()
  metadata = {}
  with (result / owner_file).open(encoding="utf-8") as stream:
      for line_number, line in enumerate(stream, 1):
          row = json.loads(line)
          prefix = str(ipaddress.ip_network(row["prefix"], strict=True))
          if prefix in metadata:
              raise SystemExit(f"duplicate metadata prefix: {prefix}")
          if row["ip_version"] != ipaddress.ip_network(prefix).version:
              raise SystemExit(f"wrong ip_version at line {line_number}: {prefix}")
          if not row.get("origin_asn"):
              raise SystemExit(f"missing origin ASN: {prefix}")
          if not row.get("whois_org") and not row.get("netname") and not row.get("org_id") and not row.get("maintainer"):
              raise SystemExit(f"missing WHOIS owner evidence: {prefix}")
          metadata[prefix] = row
          announced.add(prefix)
          if row.get("include_in_china", True):
              if row["ip_version"] == 4:
                  china_v4.add(prefix)
              else:
                  china_v6.add(prefix)
  if not metadata:
      raise SystemExit(f"{owner_file} is empty")

  expected_china = {
      "china.txt": china_v4,
      "china6.txt": china_v6,
      "china46.txt": china_v4 | china_v6,
  }
  expected_outputs = {}
  for asset, rule in config["assets"].items():
      basenames = rule.get("outputs") or [asset]
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
          if prefix not in announced:
              raise SystemExit(f"{path}:{line_number}: not present in BGP metadata: {prefix}")
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
upload: guard stat
  #!/usr/bin/env bash
  set -euo pipefail
  test -d ip-lists/.git || { echo "ip-lists worktree is missing" >&2; exit 1; }
  staging="$(mktemp -d)"
  trap 'rm -rf "${staging}"' EXIT
  cp -a result/. "${staging}/"
  cd ip-lists
  find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -a "${staging}/." .
  tree -H . -P "*.txt|*.json|*.jsonl|stat" -T "China Network Asset Database" > index.html
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
