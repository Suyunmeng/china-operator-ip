<!-- Keep these links. Translations will automatically update with the README. -->
[中文](https://zdoc.app/zh/gaoyifan/china-operator-ip) |
[Deutsch](https://zdoc.app/de/gaoyifan/china-operator-ip) |
[English](https://zdoc.app/en/gaoyifan/china-operator-ip) |
[Español](https://zdoc.app/es/gaoyifan/china-operator-ip) |
[français](https://zdoc.app/fr/gaoyifan/china-operator-ip) |
[日本語](https://zdoc.app/ja/gaoyifan/china-operator-ip) |
[한국어](https://zdoc.app/ko/gaoyifan/china-operator-ip) |
[Português](https://zdoc.app/pt/gaoyifan/china-operator-ip) |
[Русский](https://zdoc.app/ru/gaoyifan/china-operator-ip)

# 中国网络资产识别数据库

基于真实 BGP 广播、全球 RIR WHOIS、ASN 关系图和动态规则的中国网络资产数据库。

项目不再把「经过某运营商网络」等同于「属于该运营商」，也不再以第三方 IP 归属数据库作为所有权判定依据。普通资产列表和 `china*` 聚合列表只包含在所采集的 RouteViews/RIPE RIS RIB 中实际出现的 Prefix；`bgpgdcn`、`ytnetcn`、`halocloudcn`、`owocloudcn`、`heptaskycn`、`sparkvmcn` 六个明确配置的 WHOIS-only 云资产只输出未以相同或更具体 Prefix 边界在所采集 BGP RIB 中观测到的 RIR Prefix。

## 核心原则

生成管线按以下顺序工作：

1. **BGP 决定是否存在**：RouteViews 和 RIPE RIS RIB 提供当前可见 Prefix、Origin ASN、AS Path、Peer ASN、采集器和最后观测时间。
2. **WHOIS 决定资产是谁**：APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC 的权威注册数据提供 Organisation、Org ID、Maintainer、NetName、Descr 和注册国家。
3. **ASN Graph 决定网络关系**：程序只从少量运营商根 ASN 出发，结合 ASN WHOIS 组织证据和 Origin 侧 BGP 邻接发现网络家族；BGP 邻接本身分值不足，不能独立建立归属。
4. **规则决定分类**：`operators.yaml` 用优先级和所有者字段把资产分类为 carrier、cloud、cdn、ixp、idc、enterprise、education、research 等类型。
5. **高优先级 WHOIS Owner 覆盖运营商**：例如 SHIXP、CNIXP、Alibaba Cloud、Tencent Cloud、UCloud 的所有者规则优先于运营商 Origin/Family 规则。

特别地：

- AS4134、AS4809、AS9808、AS4837、AS9929 等出现在 AS Path 中间位置时仍不会使 Prefix 自动归属于对应运营商；它们仅可按 `settings.china.final_upstream_asn` 的单独聚合策略进入 `china*`，且必须存在符合最终上游限制的 Origin 路径。
- Cloudflare、Alibaba Cloud 和 Tencent Cloud 使用路由专用规则：Cloudflare 查询不限制 WHOIS 地区，也不限制 Organisation/Org ID/Maintainer/NetName；直接 Origin AS13335 的已广播 Prefix 可以归入 Cloudflare，其他 Origin 只有在所有可用观测都表明其即时上游 ASN 集合**恰好等于 `{13335}`** 时才归入 Cloudflare。Alibaba Cloud 对应 AS37963，Tencent Cloud 对应 AS45090：直接观测到该 Origin ASN 的 Anycast Prefix 会纳入相应资产，否则其即时上游 ASN 集合必须恰好等于对应 ASN。
- Cloudflare、Alibaba Cloud、Tencent Cloud 的路由归属仍然只处理已广播 Prefix，且路由归属和普通 WHOIS Owner 归属会在元数据中的 `match_source` 区分。其余资产继续受 Prefix WHOIS 必须为 `CN`、Geo 不得明确指向海外的门槛约束。
- `china*`、普通资产列表和路由资产列表只包含 BGP 已广播的精确 IPv4/IPv6 Prefix；六个 WHOIS-only 云资产的专属列表仅保留未以相同或更具体 Prefix 边界在所采集 BGP RIB 中观测到的 RIR Prefix。程序不会从 RIR `/29`、`/32` 等分配块展开未广播的 `/48` 或 `/64`。
- WHOIS Country 必须为 `CN`，且可选 Geo 辅助数据不能明确指向海外；否则 Prefix 不进入中国资产结果。
- Geo 只提供 `country/subdivision/city` 位置和海外排除信号，不能确定 IP Owner。

## 输出

预生成结果位于 [`ip-lists` 分支](https://github.com/Suyunmeng/china-operator-ip/tree/ip-lists)，由 GitHub Actions 每日更新。

```sh
git clone -b ip-lists https://github.com/Suyunmeng/china-operator-ip.git
```

### 兼容列表

每个资产通常生成三类文件：`name.txt`（IPv4）、`name6.txt`（IPv6）、`name46.txt`（IPv4 + IPv6）。现有用户可继续使用：

- `china*`
- `chinanet*` 和兼容别名 `telecom*`
- `cmcc*`
- `unicom*`
- `cernet*`
- `cstnet*`
- `drpeng*`
- `googlecn*`

新增资产分类包括：

- `aliyuncn*`
- `tencentcn*`
- `volcanoenginecn*`
- `ucloudcn*`
- `baiducn*`
- `shixp*`
- `cnixp*`
- `cloudflare*`（兼容保留）
- `bgpgdcn*`、`ytnetcn*`、`halocloudcn*`、`owocloudcn*`、`heptaskycn*`、`sparkvmcn*`：按 CN WHOIS Owner 查询；这些六个云资产仅保留未以相同或更具体 Prefix 边界在所采集 BGP RIB 中观测到的 RIR Prefix。

### Metadata

`ip-lists` 还包含以下可审计数据：

- `prefix-owner.jsonl`：每个已分类 Prefix 的资产、所有者、类型、WHOIS、规则、置信度和位置。
- `prefix-asn.jsonl`：分类使用的代表性 Origin ASN、所有采集器实际观测到的 `observed_origin_asn`、自动推导的 ASN Family、Peer 和采集器。
- `prefix-path.jsonl`：代表性 AS Path，并明确分离 Origin、Transit、Peer ASN；`observed_immediate_upstream_asn` 和 `immediate_upstream_evidence_complete` 记录即时上游特例所依据的完整观测证据，`observed_final_upstream_asn` 记录满足 China 聚合最终上游策略的全部根 ASN。
- `asn-family.json`：ASN Graph 自动发现结果、分数、深度和证据。
- `manifest.json`：Schema 版本和输出清单。

`prefix-owner.jsonl` 至少包含：

```json
{
  "prefix": "203.0.113.0/24",
  "ip_version": 4,
  "asset": "example",
  "origin_asn": [64500],
  "observed_origin_asn": [64500],
  "asn_path": [64496, 64500],
  "owner": "Example Network",
  "asset_type": "enterprise",
  "include_in_china": true,
  "operator_family": null,
  "observed_immediate_upstream_asn": [64496],
  "immediate_upstream_evidence_complete": true,
  "observed_final_upstream_asn": [4134],
  "whois_org": "Example Network",
  "org_id": "ORG-EXAMPLE",
  "maintainer": ["MAINT-EXAMPLE"],
  "netname": "EXAMPLE-NET",
  "rir": "APNIC",
  "country": "CN",
  "geo_location": null,
  "match_rule": "example:owner",
  "match_source": "whois-owner",
  "confidence_score": 96,
  "last_seen": 1786233600
}
```

## 规则引擎

新增资产只修改 `operators.yaml`，不修改 Rust 核心代码。规则支持：

- `type`、`owner`、`operator_family`、`priority`
- `roots`：少量 ASN Family 根节点
- `match.origin_asn`
- `routing.direct_origin_asn`：按已观测 Origin ASN 匹配路由特例
- `routing.exclusive_immediate_upstream_asn`：要求完整观测到的即时上游 ASN 集合与配置完全相等；不能单独使用，必须同时配置相同的 `direct_origin_asn`
- `match.transit_asn`（只能作为 WHOIS Owner 规则的附加约束，禁止单独使用）
- `match.whois_org`
- `match.org_id`
- `match.maintainer`
- `match.netname`
- `match.country`
- `exclude.geo`（仅用于位置排除；`match.geo` 会被配置校验拒绝）
- `match.asn_org`
- 对称的 `exclude` 条件
- `outputs`、`require_announced`、`exclude_announced`、`fallback`
- `settings.china.assets`：明确进入 `china.txt`、`china6.txt`、`china46.txt` 的资产 ID
- `settings.china.final_upstream_asn`：最终上游允许的 ASN 集合

默认 `require_announced: true`，所以普通资产仍只能输出已在全球 BGP 中出现的 Prefix。仅允许 WHOIS Owner + `country` 的规则将 `require_announced: false` 作为非广播例外；设置 `exclude_announced: true` 时，该资产会从 WHOIS 登记 Prefix 中剔除在所采集 BGP RIB 中观测到的相同或更具体 Prefix，但不会因仅覆盖该登记段的上级聚合路由而排除它，且只能与 `require_announced: false` 一起使用。当前这类仅未广播例外包括 `bgpgdcn`、`ytnetcn`、`halocloudcn`、`owocloudcn`、`heptaskycn` 和 `sparkvmcn`，并且仍要求 WHOIS Country 为 `CN`。

所有资产默认保持 `require_domestic: true`；Cloudflare 的路由特例可以显式设为 `require_domestic: false`，但必须是 routing-only 规则，不得混入 WHOIS/ASN Family/fallback 归属条件。

`china*` 是单独的 BGP 聚合策略，不会改变任何资产的归属或其专属输出。它由 `operators.yaml` 中的以下配置完全定义：

```yaml
settings:
  china:
    assets: [cernet, cstnet, shixp, cnixp, chinanet, unicom, cmcc, aliyuncn, tencentcn, volcanoenginecn, ucloudcn, baiducn, drpeng, googlecn]
    final_upstream_asn: [4134, 4809, 4837, 9929, 9808]
```

已分类为 `assets` 中任一资产的已广播 Prefix 会进入 `china*`。除此之外，程序将同一 Prefix 的有效 AS_PATH 按 Origin ASN 分组；对每个 Origin 的每条路径，从 Origin 向上回溯、穿过任意数量的下游 ASN，并寻找第一个 `final_upstream_asn`。只要任一 Origin 存在一条路径解析到允许集合中的最终上游，该 Prefix 就会额外进入 `china*`。因此同时由境内外 Origin 广播的 Anycast Prefix，只要存在符合条件的境内 Origin 路径，也会保留；`observed_final_upstream_asn` 会记录所有实际命中的允许根 ASN。这种路径结论不会写入 `chinanet*`、`cmcc*`、`unicom*` 或其他资产专属列表。

文本字段是大小写不敏感正则。配置启用 `deny_unknown_fields`，拼错字段会导致生成失败，而不是被静默忽略。

规则可以让多个资产共享聚合输出名，例如 SHIXP、CNIXP 同时写入 `ixp.txt`；同一规则内重复输出名仍会被拒绝。

示例：

```yaml
assets:
  example_ixp:
    type: ixp
    owner: Example IXP
    priority: 1000
    match:
      whois_org: ['Example IXP']
      org_id: ['EXAMPLE-IXP']
      maintainer: ['EXAMPLE-IXP']
      netname: ['EXAMPLE-IXP']
      country: [CN]
    exclude:
      country: [HK, US, SG]
    outputs: [exampleixp]
```

## ASN Graph

ASN Family 规则只维护少量根节点，例如：

- CHINANET：AS4134、AS4809
- CMCC：AS9808
- China Unicom：AS4837、AS9929
- CERNET：AS4538
- CSTNET：AS7497

自动发现候选 ASN 时，证据包括：

- 与根节点相同的 WHOIS Organisation ID；
- 与根节点共享 Maintainer；
- ASN WHOIS Organisation 命中规则；
- 注册国家为 CN；
- BGP Origin 侧邻接根节点或已确认家族成员。

仅有 Transit/邻接证据得分不足，因此「经过 AS4134」不会建立 CHINANET 归属。最终 Prefix 分类仍先看 Prefix WHOIS Owner，ASN Family 只在所有者特殊规则没有命中时参与分类。

## 从源码生成

### 依赖

- Rust stable（含 rustfmt、clippy）
- [just](https://github.com/casey/just)
- `bgpkit-broker`
- `curl`、`jq`、`gzip`、Python 3

### 命令

```sh
# 下载 BGP RIB 和五大 RIR WHOIS、编译并生成
just generate

# 检查普通列表和 china* 聚合只使用 BGP Prefix，同时检查 WHOIS-only 专属列表
just guard

# 格式化、Clippy、单元测试
just check
```

数据下载到被 Git 忽略的 `data/`：

- BGP：RIPE RIS `rrc00/rrc12/rrc21`、RouteViews `route-views2/route-views6`
- WHOIS：APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC bulk snapshots

可选 Geo CSV 通过环境变量传入：

```sh
GEO_FILE=/path/to/geo.csv just generate
```

格式为 `prefix,country,subdivision,city`。它仅填充 Location，不改变 WHOIS Owner。

## CI 与发布安全

GitHub Actions 分为两个阶段：

1. 所有 push/PR 都运行 fmt、Clippy、tests。
2. 仅 master 的定时或手动任务下载完整数据并生成到 staging 目录。

只有编译、生成、BGP-only guard 全部成功后，才会完整替换 `ip-lists` 工作树并推送。该分支只保留生成的 TXT、JSON、JSONL 数据；任何下载、解析、规则或 guard 失败都会在发布前终止，不会把半成品写入 `ip-lists` 分支。

## 归属数据说明

本项目不使用 NetworksDB、IP2Location DB Files 或 IP2Proxy 作为核心分类来源。仓库中的旧入口仅保留为明确失败的兼容 tombstone，防止旧自动化在不知情时继续产生错误数据。

## 社区关联项目

- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)
- [OneOhCloud/One-GeoIP](https://github.com/OneOhCloud/one-geoip)
- [fcshark-org/route-list](https://github.com/fcshark-org/route-list)
- [zxlhhyccc/smartdns-list-scripts](https://github.com/zxlhhyccc/smartdns-list-scripts)

## Acknowledgments

- [BGPKIT](https://bgpkit.com)
- [University of Oregon Route Views Archive Project](https://www.routeviews.org/)
- [RIPE Routing Information Service](https://ris.ripe.net/)
- APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC
- [Tencent EdgeOne](https://edgeone.ai/zh?from=github)

## License

[MIT License](LICENSE)
