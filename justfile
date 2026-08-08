set unstable
bgptools_version := "0.3.2"

default: prepare all stat

# Install or update bgp tooling dependencies
dependency:
  #!/usr/bin/env bash
  set -euo pipefail

  if ! bgptools --version 2>/dev/null | grep -F "{{bgptools_version}}" >/dev/null; then
    cargo install --force --version "{{bgptools_version}}" bgptools
  fi

  if ! bgpkit-broker --version >/dev/null 2>&1; then
    cargo binstall --secure --no-confirm bgpkit-broker@0.7.0
  fi

  cargo build --release

  bgptools --version
  bgpkit-broker --version

# Download and normalize latest autnums list
prepare_autnums:
  #!/usr/bin/env bash
  set -euo pipefail

  urls=(
    "https://bgp.potaroo.net/cidr/autnums.html"
    "https://www.cidr-report.org/as2.0/autnums.html"
  )

  rm -f autnums.html asnames.txt
  ok=0
  for url in "${urls[@]}"; do
    echo "INFO> fetching autnums from ${url}" >&2
    if aria2c -s 4 -x 4 -q -o autnums.html --allow-overwrite=true "${url}" \
      && awk -F'[<>]' '{print $3,$5}' autnums.html | grep '^AS' > asnames.txt \
      && [[ -s asnames.txt ]]; then
      ok=1
      break
    fi
  done

  if [[ "${ok}" != "1" ]]; then
    echo "Failed to fetch or parse autnums from all known sources" >&2
    exit 3
  fi

  rm -f autnums.html
  echo "INFO> asnames.txt updated ($(wc -l < asnames.txt) entries)" >&2

# Download the latest RIB snapshot for a collector
prepare_rib collector:
  #!/usr/bin/env bash
  set -euo pipefail

  url="$(bgpkit-broker latest -c "{{collector}}" --json \
    | jq -r '.[] | select(.data_type | contains("rib")) | .url' \
    | head -n 1)"

  if [[ -z "${url}" ]]; then
    echo "Unable to determine {{collector}} RIB download url" >&2
    exit 1
  fi

  if [[ "${url}" =~ (\.gz|\.bz2)$ ]]; then
    suffix="${BASH_REMATCH[1]}"
  else
    echo "Unsupported archive format for {{collector}}: ${url}" >&2
    exit 1
  fi

  outfile="rib-{{collector}}${suffix}"

  rm -f "${outfile}"
  aria2c -s 4 -x 4 -q -o "${outfile}" "${url}"
  stat "${outfile}"
  echo "INFO> ${outfile} ready for bgptools" >&2

# Download the latest RIB snapshots (rrc21, rrc12, route-views6)
[parallel]
prepare_ribs: (prepare_rib "rrc00") (prepare_rib "rrc21") (prepare_rib "rrc12") (prepare_rib "route-views6")

# Prepare data for generation
[parallel]
prepare: prepare_autnums prepare_ribs prepare_ip2proxy

# Download the IP2Proxy LITE PX7 BIN database used for per-prefix country and ISP filtering
prepare_ip2proxy:
  #!/usr/bin/env bash
  set -euo pipefail

  : "${IP2LOCATION_DOWNLOAD_TOKEN:?IP2LOCATION_DOWNLOAD_TOKEN is required}"
  archive="IP2PROXY-LITE-PX7.BIN.ZIP"
  database="IP2PROXY-LITE-PX7.BIN"
  rm -f "${archive}" "${database}"
  curl --fail --location --retry 3 --output "${archive}" \
    "https://www.ip2location.com/download?token=${IP2LOCATION_DOWNLOAD_TOKEN}&file=PX7LITEBIN"
  member="$(unzip -Z1 "${archive}" | grep -Eim1 '\.bin$')"
  test -n "${member}"
  unzip -p "${archive}" "${member}" > "${database}"
  rm -f "${archive}"
  test -s "${database}"

# Print raw ASN candidates for OPERATOR based on operators.yaml
get_asn_candidates_raw operator:
  #!/usr/bin/env ruby
  require "yaml"

  cfg, asnames = "operators.yaml", "asnames.txt"
  abort("Missing config: #{cfg}") unless File.file?(cfg)
  abort("Missing asnames.txt. Run 'just prepare_autnums' first.") unless File.file?(asnames) && File.size?(asnames)

  op = YAML.load_file(cfg).fetch("operators").fetch("{{operator}}")
  country = op.fetch("country")
  pattern_re = Regexp.new(op["pattern"].to_s, Regexp::IGNORECASE)
  exclude_re = Regexp.new(op.fetch("exclude", "^$"), Regexp::IGNORECASE)

  File.foreach(asnames) do |line|
    line.chomp!
    match = line.match(/^AS(\d+)\b.*,\s*([A-Z]{2})$/)
    asn, line_country = match&.captures
    next unless country.empty? || line_country == country
    next unless pattern_re.match?(line)
    next if exclude_re.match?(line)
    puts asn
  end

# Print static ASN candidates for OPERATOR based on operators.yaml
get_asn_candidates operator:
  #!/usr/bin/env ruby
  require "set"
  require "yaml"

  operator = "{{operator}}"
  cfg = YAML.load_file("operators.yaml").fetch("operators").fetch(operator)
  exclude_asn = cfg.fetch("exclude_asn", []).map(&:to_s).to_set

  candidate_asns = IO.popen(["just", "get_asn_candidates_raw", operator], &:read).split
  abort("Failed to get raw ASN candidates for #{operator}") unless $?.success?

  candidate_asns.each do |asn|
    puts asn unless exclude_asn.include?(asn)
  end

# Print ASN list for OPERATOR based on operators.yaml
get_asn operator:
  #!/usr/bin/env ruby
  require "fileutils"
  require "set"
  require "yaml"

  operator = "{{operator}}"
  cfg = YAML.load_file("operators.yaml").fetch("operators").fetch(operator)
  candidate_asns = IO.popen(["just", "get_asn_candidates", operator], &:read).split
  abort("Failed to get ASN candidates for #{operator}") unless $?.success?
  exclude_asn = Set.new

  if cfg.fetch("exclude_foreign_upstream_only", false) && !candidate_asns.empty?
    auto_exclude_path = "result/.#{operator}.auto-exclude.txt"

    if File.file?(auto_exclude_path)
      exclude_asn.merge(File.read(auto_exclude_path).split)
    else
      dynamic_exclude_asn = IO.popen(["just", "foreign_upstream_only_asn", operator], &:read)
      abort("Failed to compute foreign-upstream-only ASN list for #{operator}") unless $?.success?
      FileUtils.mkdir_p("result")
      File.write(auto_exclude_path, dynamic_exclude_asn)
      exclude_asn.merge(dynamic_exclude_asn.split)
    end
  end

  candidate_asns.each do |asn|
    puts asn unless exclude_asn.include?(asn)
  end

# Print dynamically excluded ASNs whose direct upstreams are all foreign
foreign_upstream_only_asn operator:
  #!/usr/bin/env ruby
  require "yaml"

  operator = "{{operator}}"
  cfg = YAML.load_file("operators.yaml").fetch("operators").fetch(operator)
  abort("foreign_upstream_only_asn is disabled for #{operator}") unless cfg.fetch("exclude_foreign_upstream_only", false)

  candidate_asns = IO.popen(["just", "get_asn_candidates", operator], &:read).split
  abort("Failed to get ASN candidates for #{operator}") unless $?.success?
  exit 0 if candidate_asns.empty?

  ribs = Dir["rib-*.{gz,bz2}"].sort
  abort("No rib-*.gz or rib-*.bz2 files found. Run 'just prepare_ribs' first.") if ribs.empty?
  bgptools = [
    "bgptools",
    "--ignore-private-asn",
    "--cache",
    "--origin-only",
    "--exclude-foreign-upstream-only",
    cfg.fetch("country"),
    "--asn-country-file",
    "asnames.txt",
    "--debug-print-foreign-upstream-only-asns",
  ]
  bgptools += ribs.flat_map { |rib| ["--mrt-file", rib] }
  output = IO.popen(bgptools + candidate_asns, &:read)
  abort("Failed to compute foreign-upstream-only ASN list for #{operator}") unless $?.success?
  print output

# Save dynamically excluded ASNs to a hidden file under result/
save_foreign_upstream_only_asn operator:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p result
  just foreign_upstream_only_asn "{{operator}}" > "result/.{{operator}}.auto-exclude.txt"

# Fetch registered NetworksDB CIDRs for an operator, limited to its configured country
networksdb_networks operator:
  #!/usr/bin/env ruby
  require "json"
  require "net/http"
  require "uri"
  require "yaml"

  operator = "{{operator}}"
  cfg = YAML.load_file("operators.yaml").fetch("operators").fetch(operator)
  abort("networksdb is disabled for #{operator}") unless cfg.fetch("networksdb", false)
  country = cfg.fetch("country")
  abort("country must be a two-letter country code for #{operator}") unless country.match?(/\A[A-Z]{2}\z/)
  orgid = cfg.fetch("orgid")
  abort("orgid must be non-empty for #{operator}") if orgid.empty?
  token = ENV.fetch("NETWORKSDB_TOKEN") { abort("NETWORKSDB_TOKEN is required for #{operator}") }

  [false, true].each do |ipv6|
    page = 1
    loop do
      uri = URI("https://networksdb.io/api/org-networks")
      params = {id: orgid, page: page}
      params[:ipv6] = "true" if ipv6
      uri.query = URI.encode_www_form(params)
      request = Net::HTTP::Get.new(uri)
      request["X-Api-Key"] = token
      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(request) }
      abort("NetworksDB request failed for #{operator}: HTTP #{response.code}") unless response.is_a?(Net::HTTPSuccess)
      body = JSON.parse(response.body)
      results = body.fetch("results")
      results.each do |network|
        puts network.fetch("cidr") if network.fetch("countrycode").casecmp?(country)
      end
      break if results.empty? || page * 1000 >= body.fetch("total")
      page += 1
    end
  end

# Save country-filtered NetworksDB CIDRs to a hidden file under result/
save_networksdb_networks operator:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p result
  just networksdb_networks "{{operator}}" > "result/.{{operator}}.networksdb.txt"

# Generate IP lists for a single operator
gen operator:
  #!/usr/bin/env ruby
  require "fileutils"
  require "yaml"

  operator = "{{operator}}"
  FileUtils.mkdir_p("result")
  out, v4, v6 = %W[result/#{operator}46.txt result/#{operator}.txt result/#{operator}6.txt]
  raw_out = "result/.#{operator}.raw.txt"
  cfg = YAML.load_file("operators.yaml").fetch("operators").fetch(operator)
  origin_only = cfg.fetch("origin_only", false)
  ip_country = cfg.fetch("ip_country", "")
  isp_pattern = cfg.fetch("isp_pattern", "")
  ip_filter_enabled = !ip_country.empty? || !isp_pattern.empty?
  abort("ip_country must be a two-letter country code for #{operator}") unless ip_country.empty? || ip_country.match?(/\A[A-Z]{2}\z/)
  abort("ip_country and isp_pattern must be configured together for #{operator}") unless ip_country.empty? == isp_pattern.empty?

  ribs = Dir["rib-*.{gz,bz2}"].sort
  abort("No rib-*.gz or rib-*.bz2 files found. Run 'just prepare_ribs' first.") if ribs.empty?
  bgptools = ["bgptools", "--ignore-private-asn", "--cache"]
  bgptools << "--origin-only" if origin_only
  bgptools += ribs.flat_map { |r| ["--mrt-file", r] }

  warn "INFO> #{operator} start"
  if cfg.fetch("networksdb", false)
    country = cfg.fetch("country")
    abort("country must be a two-letter country code for #{operator}") unless country.match?(/\A[A-Z]{2}\z/)
    orgid = cfg.fetch("orgid")
    abort("orgid must be non-empty for #{operator}") if orgid.empty?
    abort("Failed to save NetworksDB networks for #{operator}") unless system("just", "save_networksdb_networks", operator)
    network_file = "result/.#{operator}.networksdb.txt"
    filter = ["target/release/networksdb-filter", "--network-file", network_file]
    filter += cfg.fetch("exclude_asn", []).map { |asn| ["--exclude-asn", asn.to_s] }.flatten
    filter += ribs.flat_map { |rib| ["--mrt-file", rib] }
    abort("Failed to filter NetworksDB networks against BGP data for #{operator}") unless system(*filter, out: raw_out)
  elsif cfg.fetch("downstream_asn", []).any?
    filter = ["target/release/downstream-filter", "--root-asn"]
    filter += cfg.fetch("downstream_asn").map(&:to_s)
    filter += ["--exclude-asn"]
    filter += cfg.fetch("exclude_asn", []).map(&:to_s)
    filter += ribs.flat_map { |rib| ["--mrt-file", rib] }
    abort("Failed to collect downstream ASN networks for #{operator}") unless system(*filter, out: raw_out)
  else
    if cfg.fetch("exclude_foreign_upstream_only", false)
      abort("Failed to save foreign-upstream-only ASN list for #{operator}") unless system("just", "save_foreign_upstream_only_asn", operator)
    end
    asns = IO.popen(["just", "get_asn", operator], &:read)
    abort("Failed to get ASN list for #{operator}") unless $?.success?
    abort("Failed to run bgptools for #{operator}") unless system(*bgptools, *asns.split, out: raw_out)
  end

  if ip_filter_enabled
    filter = ["python3", "scripts/filter_ip2proxy.py", "--database", "IP2PROXY-LITE-PX7.BIN", "--network-file", raw_out]
    filter += ["--country", ip_country, "--isp-pattern", isp_pattern]
    abort("Failed to filter #{operator} networks with IP2Proxy") unless system(*filter, out: out)
  else
    FileUtils.mv(raw_out, out, force: true)
  end

  v6_lines, v4_lines = File.readlines(out).partition { |line| line.include?(":") }
  File.write(v4, v4_lines.join)
  File.write(v6, v6_lines.join)
  warn "INFO> #{operator} done (v4=#{v4_lines.length} v6=#{v6_lines.length})"

# Generate IP lists for all operators sequentially
all:
  #!/usr/bin/env ruby
  require "yaml"

  ops = YAML.load_file("operators.yaml").fetch("operators").keys.sort
  ops.each do |op|
    status = system("just", "gen", op)
    exit($?.exitstatus || 1) unless status
  end

guard:
  #!/usr/bin/env ruby
  {"china.txt" => 3000, "china6.txt" => 1000}.each do |f, min|
    next if File.foreach("result/#{f}").count >= min
    warn "#{f} too small"
    exit 1
  end
  warn "INFO> guard checks passed"

# Summarize total IPv4/IPv6 address space per operator
stat:
  #!/usr/bin/env ruby
  require "yaml"

  dir = "result"
  files = Dir.exist?(dir) ? Dir.glob("#{dir}/*.txt").sort : []
  files.reject! { |p| p.end_with?("46.txt") }
  abort("result/*.txt files missing") if files.empty?

  ops = YAML.load_file("operators.yaml").fetch("operators")
  ops.each do |operator, cfg|
    next unless cfg.fetch("exclude_foreign_upstream_only", false)
    next if File.file?("result/.#{operator}.auto-exclude.txt")
    abort("Failed to save foreign-upstream-only ASN list for #{operator}") unless system("just", "save_foreign_upstream_only_asn", operator)
  end

  report = files.map do |p|
    base = p.end_with?("6.txt") ? 48 : 32
    total = File.foreach(p).sum do |line|
      match = %r{/(\d+)}.match(line)
      next 0 unless match
      prefix_len = match[1].to_i
      prefix_len <= base ? (1 << (base - prefix_len)) : 0
    end
    "#{File.basename(p, ".txt")}\n#{total}"
  end.join("\n\n") + "\n"

  print report
  File.write("#{dir}/stat", report)

# Publish generated results into the ip-lists branch
upload: guard
  #!/usr/bin/env bash
  set -euo pipefail
  rm -f ip-lists/{.,}*.txt
  mv result/{*,.*.txt} ip-lists
  cd ip-lists
  tree -H . -P "*.txt|stat" -T "China Operator IP - prebuild results" > index.html
  git config user.name "GitHub Actions"
  git config user.email noreply@github.com
  git add .
  git commit -m "update $(date +%Y-%m-%d)"
  git push -q

# Refresh CDN cache for all files in ip-lists directory
refresh_jsdelivr repository:
  #!/usr/bin/env ruby
  require "net/http"

  dir = "ip-lists"
  abort("#{dir} directory not found") unless Dir.exist?(dir)

  Dir.children(dir).sort.each do |file|
    warn "INFO> purging CDN cache for #{file}"
    puts Net::HTTP.get_response(URI("https://purge.jsdelivr.net/gh/{{repository}}@#{dir}/#{file}")).inspect
  end
