#!/usr/bin/env python3
import argparse
import html
import shutil
from collections import defaultdict
from pathlib import Path

LABELS = {
    "china": "China Network",
    "chinanet": "China Telecom",
    "cmcc": "China Mobile",
    "unicom": "China Unicom",
    "cernet": "China Education and Research Network",
    "cstnet": "China Science and Technology Network",
    "drpeng": "Dr. Peng Group & regional ISPs",
    "googlecn": "Google China",
    "aliyuncn": "Alibaba Cloud",
    "tencentcn": "Tencent Cloud",
    "volcanoenginecn": "Volceno Engine",
    "ucloudcn": "UCloud",
    "baiducn": "Baidu AI Cloud",
    "cloudflare": "Cloudflare",
    "shixpcn": "National Shanghai New-Type Internet Exchange Point",
    "cnixpcn": "Shenzhen Qianhai New-Type Internet Exchange Point",
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def list_name(path: Path) -> tuple[str, str]:
    stem = path.stem
    if stem.endswith("46"):
        return stem[:-2], "IPv4 + IPv6"
    if stem.endswith("6"):
        return stem[:-1], "IPv6"
    return stem, "IPv4"


def render_card(name: str, files: dict[str, Path]) -> str:
    escaped_name = html.escape(name)
    display_name = html.escape(LABELS.get(name, name))
    links = []
    for variant in ("IPv4", "IPv6", "IPv4 + IPv6"):
        path = files.get(variant)
        if path:
            links.append(
                f'<a class="download" href="./{html.escape(path.name)}" download>'
                f'<span>{variant}</span><b>Download</b></a>'
            )
        else:
            links.append(f'<span class="download unavailable"><span>{variant}</span><b>—</b></span>')
    return f'''<article class="list-card" data-search="{escaped_name} {display_name}">
  <div class="card-heading"><h2>{display_name}</h2><code>{escaped_name}</code></div>
  <div class="downloads">{"".join(links)}</div>
</article>'''


def page(cards: str, count: int) -> str:
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="CIDR lists of Chinese network assets generated from BGP and RIR WHOIS data.">
  <title>China Operator IP Lists</title>
  <style>
    :root {{ color-scheme: dark; --bg:#08111f; --panel:#101d30; --line:#233b59; --text:#ecf4ff; --muted:#9bb2ce; --blue:#74b7ff; --accent:#40d6a2; --serif:Georgia,"Noto Serif SC",serif; --sans:Inter,"Noto Sans SC",system-ui,sans-serif; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(circle at 78% -10%,#153d68 0,transparent 31rem),var(--bg); color:var(--text); font-family:var(--sans); }}
    .shell {{ width:min(1100px,calc(100% - 40px)); margin:auto; }}
    header {{ padding:70px 0 46px; border-bottom:1px solid var(--line); }}
    .eyebrow {{ margin:0 0 16px; color:var(--accent); font-size:.76rem; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }}
    h1 {{ max-width:760px; margin:0; font:clamp(2.45rem,6vw,4.65rem)/1.03 var(--serif); letter-spacing:-.055em; }}
    .intro {{ max-width:630px; margin:24px 0 0; color:var(--muted); font-size:1.04rem; line-height:1.7; }}
    .commands {{ display:flex; flex-wrap:wrap; gap:12px; margin-top:30px; }}
    .command {{ padding:11px 13px; border:1px solid var(--line); border-radius:8px; background:#0b1727; color:#bdd3ed; font: .82rem ui-monospace,SFMono-Regular,Consolas,monospace; }}
    main {{ padding:32px 0 64px; }}
    .toolbar {{ display:flex; align-items:center; justify-content:space-between; gap:24px; margin-bottom:24px; }}
    .result-count {{ color:var(--muted); font-size:.9rem; }}
    input {{ width:min(350px,100%); border:1px solid var(--line); border-radius:8px; outline:none; background:#0b1727; color:var(--text); padding:12px 14px; font:inherit; }}
    input:focus {{ border-color:var(--blue); box-shadow:0 0 0 3px #74b7ff20; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }}
    .list-card {{ border:1px solid var(--line); border-radius:12px; background:linear-gradient(150deg,#14243a,#0d192a); padding:20px; transition:transform .15s ease,border-color .15s ease; }}
    .list-card:hover {{ transform:translateY(-2px); border-color:#46769f; }}
    .card-heading {{ min-height:67px; }}
    h2 {{ margin:0 0 8px; font-size:1.05rem; letter-spacing:-.02em; }}
    code {{ color:var(--muted); font-size:.78rem; }}
    .downloads {{ display:grid; gap:7px; }}
    .download {{ display:flex; align-items:center; justify-content:space-between; padding:9px 10px; border:1px solid #284563; border-radius:7px; color:#bcd7f1; text-decoration:none; font-size:.82rem; }}
    a.download:hover {{ background:#193353; border-color:var(--blue); color:white; }}
    .download b {{ color:var(--accent); font-size:.75rem; }}
    .unavailable {{ opacity:.35; }}
    .empty {{ grid-column:1/-1; display:none; padding:42px; border:1px dashed var(--line); border-radius:12px; color:var(--muted); text-align:center; }}
    footer {{ border-top:1px solid var(--line); padding:24px 0 44px; color:var(--muted); font-size:.82rem; line-height:1.6; }}
    footer a {{ color:var(--blue); }}
    @media (max-width:620px) {{ .shell {{ width:min(100% - 28px,1100px); }} header {{ padding-top:45px; }} .toolbar {{ align-items:stretch; flex-direction:column; gap:12px; }} input {{ width:100%; }} }}
  </style>
</head>
<body>
  <header><div class="shell">
    <p class="eyebrow">BGP-observed network assets</p>
    <h1>China Network Asset<br>IP Lists</h1>
    <p class="intro">CIDR lists generated from observed BGP announcements and authoritative RIR WHOIS data. Use them directly in routing, ACL, DNS, or proxy rules.</p>
    <div class="commands"><span class="command" id="curl-command"></span></div>
  </div></header>
  <main class="shell">
    <div class="toolbar"><span class="result-count" id="count">{count} network lists</span><input id="search" type="search" placeholder="Search networks or filenames" autocomplete="off"></div>
    <section class="grid" id="lists">{cards}<p class="empty" id="empty">No matching IP lists.</p></section>
  </main>
  <footer><div class="shell">Generated from observed BGP prefixes, global RIR WHOIS records, and the rules engine.</div></footer>
  <script>
    const cards = [...document.querySelectorAll('.list-card')];
    document.querySelector('#curl-command').textContent = `curl -fsSLO ${{window.location.origin}}/china.txt`;
    const search = document.querySelector('#search');
    const count = document.querySelector('#count');
    const empty = document.querySelector('#empty');
    search.addEventListener('input', () => {{
      const term = search.value.trim().toLocaleLowerCase();
      const shown = cards.filter(card => {{ const match = card.dataset.search.toLocaleLowerCase().includes(term); card.hidden = !match; return match; }}).length;
      count.textContent = `${{shown}} network lists`;
      empty.style.display = shown ? 'none' : 'block';
    }});
  </script>
</body>
</html>
'''


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    groups = defaultdict(dict)
    for path in sorted(args.source.glob("*.txt")):
        name, variant = list_name(path)
        groups[name][variant] = path
        shutil.copy2(path, args.output / path.name)
    cards = "\n".join(render_card(name, groups[name]) for name in sorted(groups, key=lambda item: (item != "china", LABELS.get(item, item))))
    (args.output / "index.html").write_text(page(cards, len(groups)), encoding="utf-8")


if __name__ == "__main__":
    main()
