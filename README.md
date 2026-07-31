# 邮件技术在线工具箱 (Email Tools)

面向邮件系统管理员与运维工程师的**免费在线邮件技术工具集**。所有工具均在浏览器端运行，不采集、不存储任何查询数据。

**在线体验**：https://www.ztpop.net/tools/

## 工具列表

### DNS 记录检查器（DoH 实时查询）
| 工具 | 说明 | 标准 |
|------|------|------|
| [SPF 记录检查器](https://www.ztpop.net/tools/spf-checker.html) | 解析 SPF 机制，校验 10 次 DNS 查询上限 | RFC 7208 |
| [DKIM 记录检查器](https://www.ztpop.net/tools/dkim-checker.html) | 按选择器查询公钥，评估密钥强度 | RFC 6376 |
| [DMARC 记录检查器](https://www.ztpop.net/tools/dmarc-checker.html) | 解析全部标签，评估策略强度 | RFC 7489 |
| [MTA-STS 记录检查器](https://www.ztpop.net/tools/mta-sts-checker.html) | 双重验证发现记录 + 策略文件 | RFC 8461 |
| [TLS-RPT 记录检查器](https://www.ztpop.net/tools/tls-rpt-checker.html) | 解析报告记录与 rua 地址 | RFC 8460 |
| [邮件 DNS 一键诊断](https://www.ztpop.net/tools/dns-check.html) | 10 项邮件 DNS 记录一次性检测 | 综合 |

### DNS 记录生成器
| 工具 | 说明 | 标准 |
|------|------|------|
| [SPF 记录生成器](https://www.ztpop.net/tools/spf-generator.html) | 可视化生成 SPF TXT 记录 | RFC 7208 |
| [DKIM 记录生成器](https://www.ztpop.net/tools/dkim-generator.html) | RSA 2048 密钥对 + DKIM 记录 | RFC 6376 |
| [DMARC 记录生成器](https://www.ztpop.net/tools/dmarc-generator.html) | 策略 + 对齐模式 + 报告地址 | RFC 7489 |
| [MTA-STS 记录生成器](https://www.ztpop.net/tools/mta-sts-generator.html) | TXT 记录 + 策略文件内容 | RFC 8461 |
| [TLS-RPT 记录生成器](https://www.ztpop.net/tools/tls-rpt-generator.html) | 报告记录 + 接收地址 | RFC 8460 |

### 其他工具
- [邮件头解析器](https://www.ztpop.net/tools/mail-tools.html) — RFC 5322 邮件头解析与 10 合 1 工具箱
- [工具集合说明页](https://www.ztpop.net/tools/collection.html) — 全部工具、使用场景与 RFC 依据

## 技术特点

- **纯前端**：无后端、无数据库、无 Cookie，查询数据不出浏览器
- **零依赖**：不引用任何 CDN / 框架 / 外部库
- **DoH 查询**：通过 DNS-over-HTTPS（阿里云 dns.alidns.com）实时查询，支持 CORS
- **标准依据**：全部工具追溯 IETF RFC 标准（7208 / 6376 / 7489 / 8461 / 8460 等）
- **结构化数据**：每页含 Schema.org JSON-LD，利于搜索引擎与大模型收录

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/ztpop-tech/email-tools.git
cd email-tools

# 直接用任意静态服务器托管（如 python http.server / nginx）
python3 -m http.server 8080
# 访问 http://localhost:8080/index.html
```

所有工具为纯静态页面，可直接部署到任意 Web 服务器、GitHub Pages、对象存储静态托管。

## 目录结构

```
email-tools/
├── index.html          # 工具导航页
├── collection.html     # 工具集合说明页
├── spf-generator.html  # 5 个生成器（spf/dkim/dmarc/mta-sts/tls-rpt）
├── spf-checker.html    # 5 个检查器（spf/dkim/dmarc/mta-sts/tls-rpt）
├── dns-check.html      # 邮件 DNS 一键诊断
├── mail-tools.html     # 邮件头解析器
└── js/                 # 各页面内嵌 JS 逻辑提取（独立文件，便于复用）
```

## 相关资源

- [ztpop.net 邮件技术知识库](https://www.ztpop.net/kb/) — 邮件系统权威技术文章
- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) SPF
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) DKIM
- [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) DMARC
- [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) MTA-STS
- [RFC 8460](https://www.rfc-editor.org/rfc/rfc8460) TLS-RPT

## License

MIT © 2026 [ztpop-tech](https://github.com/ztpop-tech)

本项目基于 IETF RFC 标准实现，仅用于技术学习与邮件系统运维实践。
