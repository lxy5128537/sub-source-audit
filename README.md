# sub-source-audit

公共订阅源集中仓库 + 全自动审计流水线。

**目标**：把大量公共订阅源集中到一处，用 [mihomo](https://github.com/MetaCubeX/mihomo) 对每个源里的节点做两级检测，最后只把**可用率达标**的源单独输出成文件（每个源一个文件，按源地址命名）。

## 两级检测

| 阶段 | 做法 | 说明 |
|---|---|---|
| ① 测活 | mihomo REST API `GET /proxies/{name}/delay` | 每个节点单独判定，`http://cp.cloudflare.com/generate_204`，超时 3s |
| ② 真连接 | 每个节点绑一个**专属 mixed 入口**（`listeners[].proxy`），经它真发一次 HTTPS 请求 | 目标 `https://www.cloudflare.com/cdn-cgi/trace`，能取回真实出口 IP 才算可用 |

只有 ① 通过的节点才进入 ②，「可用」的最终定义是 **② 成功拿到 trace 正文**。
容错细节：`/proxies/{name}/delay` 只证明链路能到上游，而真实请求能暴露 TLS 握手失败、协议参数错误、出口被封等只有实测才看得到的问题，所以二级缺一不可。

## 输出

- `results/<源地址 slug>.txt` — **仅对可用率 > 阈值的源**生成，内容是所有通过真连接测试的节点（保留原始分享链接，可直接导入客户端），文件头注释记录了源地址、采样数、通过数、可用率
- `results/summary.json` — 所有源的统计（含未达标者与失败原因）
- `SUMMARY.md` — 排行榜（达标源 / 未达标源两张表）

可用率定义：`真连接成功数 / 采样数`。默认阈值 30%，采样不足 10 个的源不做判定（避免小样本偶发通过）。

## 怎么跑

`Actions → source-audit → Run workflow`，可调三个参数：

- `limit` 每源最多抽多少节点来测（默认 300）
- `threshold` 可用率阈值（默认 0.30）
- `chunk` 每个矩阵任务处理多少个源（默认 5）

也可每天定时自动跑（`0 20 * * *` UTC = 04:00 北京时间），或修改 `sources.txt` 后自动触发。

## 结构

```
sources.txt                   订阅源清单（一行一个，改这个文件就增删源）
scripts/nodes.py              抓取/解析：Clash YAML、整段 base64、明文分享链接
scripts/audit.py              单源审计：起 mihomo → 批量测活 → 逐节点真连接
scripts/aggregate.py          汇总，按阈值输出每源文件 + 排行榜
.github/workflows/audit.yml   plan（切分）→ audit（矩阵并发）→ aggregate（提交结果）
```

工作流架构：`plan` 把源切成小组 → `audit` 矩阵并发（最多 40 组同时跑，每源独立 mihomo 实例、独立端口区）→ `aggregate` 汇总并自动提交结果。

## 支持协议

`vmess` / `vless`（含 reality、ws、grpc、h2）/ `trojan` / `ss` / `ssr` / `hysteria` / `hysteria2` / `tuic`，以及 Clash YAML 源（原样取用，保真度最高）。

私网地址、非法端口、重复节点（同协议+同服务器+同端口+同凭据）在解析阶段就剔除。

## 说明

- 本仓库只做**检测与输出**，不代理、不转发、不提供任何可用性担保
- 来源均为公开可获取的订阅地址；节点质量随时变化，结果带时间戳，仅供参考
- 审计会消耗运行时间：矩阵并发 + 每源采样上限就是为了把单次运行控制在合理时长内
