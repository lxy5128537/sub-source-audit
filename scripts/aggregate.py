#!/usr/bin/env python3
"""汇总各源的审计结果：可用率 > 阈值的源，按订阅地址各出一个文件。

输出：
  results/<源地址 slug>.txt   仅通过真连接测试的节点（一行一个，保留原始 URI）
  results/summary.json        所有源的统计（含未达标的）
  SUMMARY.md                  人读的排行榜
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
from collections import Counter
from urllib.parse import urlparse


def slug_for(url: str) -> str:
    u = urlparse(url)
    base = f"{u.netloc}/{u.path}".strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:110] or "source"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--indir", default="artifacts")
    ap.add_argument("--outdir", default="results")
    ap.add_argument("--threshold", type=float, default=0.30)
    ap.add_argument("--min-sample", type=int, default=10,
                    help="采样数低于此值不判定，避免小样本偶发通过")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    # 清掉上一轮的 .txt，避免已不达标的源残留
    for stale in glob.glob(os.path.join(args.outdir, "*.txt")):
        os.remove(stale)
    reports = {}
    for path in glob.glob(os.path.join(args.indir, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(path))
        except Exception:
            continue
        url = d.get("source")
        if not url:
            continue
        prev = reports.get(url)
        if prev is None or (d.get("sampled", 0) > prev.get("sampled", 0)):
            reports[url] = d

    rows, written = [], 0
    for url, d in reports.items():
        rate = float(d.get("usable_rate") or 0)
        sampled = int(d.get("sampled") or 0)
        ok = int(d.get("real_ok") or 0)
        qualified = rate > args.threshold and sampled >= args.min_sample
        row = {
            "source": url,
            "sampled": sampled,
            "parsed": int(d.get("parsed") or 0),
            "unique": int(d.get("unique") or 0),
            "delay_ok": int(d.get("delay_ok") or 0),
            "real_ok": ok,
            "usable_rate": round(rate, 4),
            "qualified": qualified,
            "error": d.get("error", ""),
            "file": "",
        }
        good = [n for n in d.get("nodes", []) if n.get("real_ok")]
        if qualified and good:
            fn = f"{slug_for(url)}.txt"
            lines = []
            for n in good:
                if n.get("uri"):
                    lines.append(n["uri"])
                else:
                    lines.append(json.dumps(
                        {"type": n["type"], "server": n["server"], "port": n["port"],
                         "country": n.get("country", ""), "egress_ip": n.get("egress_ip", "")},
                        ensure_ascii=False))
            header = (f"# source: {url}\n"
                      f"# tested_at: {d.get('tested_at','')}\n"
                      f"# sampled: {sampled}  delay_ok: {d.get('delay_ok',0)}  real_ok: {ok}"
                      f"  usable_rate: {rate:.1%}\n")
            with open(os.path.join(args.outdir, fn), "w") as f:
                f.write(header + "\n".join(lines) + "\n")
            row["file"] = fn
            written += 1
        rows.append(row)

    rows.sort(key=lambda r: (-r["usable_rate"], -r["real_ok"]))
    json.dump(rows, open(os.path.join(args.outdir, "summary.json"), "w"),
              ensure_ascii=False, indent=1)

    qual = [r for r in rows if r["qualified"]]
    prot = Counter()
    for r in qual:
        pass
    md = ["# 订阅源审计结果", "",
          f"- 参与审计的源：**{len(rows)}**",
          f"- 可用率 > {args.threshold:.0%} 且采样 ≥ {args.min_sample} 的源：**{len(qual)}**",
          f"- 已生成节点文件：**{written}** 个（`results/` 下按源地址命名）",
          "", "## 达标源", "",
          "| 可用率 | 真连成功/采样 | 解析 | 源 |", "|---|---|---|---|"]
    for r in qual:
        md.append(f"| {r['usable_rate']:.1%} | {r['real_ok']}/{r['sampled']} | {r['parsed']} | [{slug_for(r['source'])}]({r['source']}) |")
    md += ["", "## 未达标（含失败原因）", "",
           "| 可用率 | 真连成功/采样 | 源 | 备注 |", "|---|---|---|---|"]
    for r in rows:
        if r["qualified"]:
            continue
        md.append(f"| {r['usable_rate']:.1%} | {r['real_ok']}/{r['sampled']} | {slug_for(r['source'])} | {r['error'][:48]} |")
    open("SUMMARY.md", "w").write("\n".join(md) + "\n")

    print(f"审计源 {len(rows)} 个；达标 {len(qual)} 个；写出文件 {written} 个")
    for r in qual[:20]:
        print(f"  {r['usable_rate']:>6.1%}  {r['real_ok']:>3}/{r['sampled']:<3}  {r['file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
