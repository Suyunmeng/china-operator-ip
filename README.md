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

项目不再把「经过某运营商网络」等同于「属于该运营商」，也不再以第三方 IP 归属数据库作为所有权判定依据。最终列表只包含在所采集的 RouteViews/RIPE RIS RIB 中实际出现的 Prefix。

## 核心原则

生成管线按以下顺序工作：

1. **BGP 决定是否存在**：RouteViews 和 RIPE RIS RIB 提供当前可见 Prefix、Origin ASN、AS Path、Peer ASN、采集器和最后观测时间。
2. **WHOIS 决定资产是谁**：APNIC、RIPE NCC、ARIN、LACNIC、AFRINIC 的权威注册数据提供 Organisation、Org ID、Maintainer、NetName、Descr 和注册国家。
3. **ASN Graph 决定网络关系**：程序只从少量运营商根 ASN 出发，结合 ASN WHOIS 组织证据和 Origin 侧 BGP 邻接发现网络家族；BGP 邻接本身分值不足，不能独立建立归属。
4. **规则决定分类**：`operators.yaml` 用优先级和所有者字段把资产分类为 carrier、cloud、cdn、ixp、idc、enterprise、education、research 等类型。
5. **高优先级 WHOIS Owner 覆盖运营商**：例如 SHIXP、CNIXP、Alibaba Cloud、Tencent Cloud、UCloud 的所有者规则优先于运营商 Origin/Family 规则。

特别地：

- AS4134、AS4809、AS9808、AS4837 等出现在 AS Path 中间位置时只是 Transit ASN，**不会**使 Prefix 自动归属于对应运营商。
- 所有列表原样保留观测到的 IPv4/IPv6 BGP Prefix，不从 RIR `/29`、`/32` 等分配块展开未广播的 `/48` 或 `/64`。
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

- `aliyuncn*` / `aliyun*`
- `tencentcn*` / `tencent*`
- `volcanoenginecn*` / `volcanoengine*`
- `ucloudcn*` / `ucloud*`
- `baiducn*` / `baidu*`
- `shixpcn*` / `shixp*`
- `cnixp*`

### Metadata

`ip-lists` 还包含以下可审计数据：

- `prefix-owner.jsonl`：每个已分类 Prefix 的资产、所有者、类型、WHOIS、规则、置信度和位置。
- `prefix-asn.jsonl`：Origin ASN、自动推导的 ASN Family、Peer 和采集器。
- `prefix-path.jsonl`：代表性 AS Path，并明确分离 Origin、Transit、Peer ASN。
- `asn-family.json`：ASN Graph 自动发现结果、分数、深度和证据。
- `manifest.json`：Schema 版本和输出清单。

`prefix-owner.jsonl` 至少包含：

```json
{
  "prefix": "203.0.113.0/24",
  "ip_version": 4,
  "asset": "example",
  "origin_asn": [64500],
  "asn_path": [64496, 64500],
  "owner": "Example Network",
  "asset_type": "enterprise",
  "operator_family": null,
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
- `match.transit_asn`（只能作为 WHOIS Owner 规则的附加约束，禁止单独使用）
- `match.whois_org`
- `match.org_id`
- `match.maintainer`
- `match.netname`
- `match.country`
- `match.geo`
- `match.asn_org`
- 对称的 `exclude` 条件
- `outputs`、`include_in_china`、`require_domestic`、`fallback`

文本字段是大小写不敏感正则。配置启用 `deny_unknown_fields`，拼错字段会导致生成失败，而不是被静默忽略。

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

运营商规则只维护根节点，例如：

- CHINANET：AS4134、AS4809
- CMCC：AS9808
- China Unicom：AS4837、AS9929
- CERNET：AS4538、AS7497

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

# 检查所有 TXT 都来自 prefix-owner.jsonl 中的 BGP Prefix
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

只有编译、生成、BGP-only guard 全部成功后，才会完整替换 `ip-lists` 工作树并推送。任何下载、解析、规则或 guard 失败都会在发布前终止，不会把半成品写入 `ip-lists` 分支。

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
