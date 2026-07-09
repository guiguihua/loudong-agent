# 漏洞类型覆盖率扩展——验证环境搭建报告

状态：验证环境就绪，待执行 Skill 验证

## 执行摘要

基于前一轮 6 案例的技能缺陷分析（覆盖：路径穿越 ×3、资源耗尽 ×2、XSS ×1），
本次针对性扩展了 `remediation-patterns.md` 中定义但**从未实际验证**的 9 个漏洞类型。
每个类型选取了一个有公开公告、脆弱版本和官方修复的 Python 开源 CVE，
完成了仓库克隆和标准化输入编写。

## 扩展覆盖矩阵

| # | 漏洞类型 | CVE | 项目 | 脆弱版本 → 修复版本 | 复杂度 |
|---|---|---|---|---|---|
| 1 | **SQL 注入** | CVE-2024-42005 | Django | 5.0.6 → 5.0.8 | 高（大型框架，修复聚焦） |
| 2 | **SSRF** | CVE-2023-47116 | Label Studio | 1.10.0 → 1.11.0 | 高（全栈应用，修复聚焦） |
| 3 | **反序列化** | CVE-2023-50943 | Apache Airflow | 2.8.0 → 2.8.1 | 高（分布式平台，修复聚焦） |
| 4 | **鉴权绕过** | CVE-2024-21543 | djoser | 2.2.0 → 2.3.0 | 低（Django REST 库） |
| 5 | **认证缺陷** | CVE-2024-37568 | Authlib | 1.3.0 → 1.3.1 | 中（JWT 库） |
| 6 | **弱加密** | CVE-2023-50782 | cryptography | 41.0.5 → 42.0.0 | 高（底层加密库） |
| 7 | **密钥泄露** | CVE-2024-47081 | requests | 2.32.3 → 2.32.4 | 低（HTTP 库） |
| 8 | **竞争条件** | CVE-2025-68146 | filelock | 3.20.0 → 3.20.1 | 低（文件锁库） |
| 9 | **依赖大版本升级** | CVE-2023-50782 | cryptography | 41.x → 42.x | 高（需 OpenSSL 3.2+） |

## 与已有验证的对比

### 已有覆盖（6 案例）

| 漏洞类型 | 案例数 | 代表 CVE |
|---|---|---|
| 路径穿越 | 3 | aiohttp CVE-2024-23334、Werkzeug CVE-2024-49766、Django CVE-2024-39330 |
| 资源耗尽/DoS | 2 | Starlette GHSA-74m5、Tornado CVE-2025-47287 |
| XSS/HTML 注入 | 1 | Jinja CVE-2024-34064 |

### 本次扩展（9 案例）

| 漏洞类型 | 案例数 | 代表 CVE |
|---|---|---|
| SQL 注入 | 1 | Django CVE-2024-42005 |
| SSRF | 1 | Label Studio CVE-2023-47116 |
| 反序列化 | 1 | Airflow CVE-2023-50943 |
| 鉴权绕过 | 1 | djoser CVE-2024-21543 |
| 认证缺陷 | 1 | Authlib CVE-2024-37568 |
| 弱加密 | 1 | cryptography CVE-2023-50782 |
| 密钥泄露 | 1 | requests CVE-2024-47081 |
| 竞争条件 | 1 | filelock CVE-2025-68146 |
| 依赖大版本升级 | 1 | cryptography 41.x → 42.x |

### 仍未覆盖的模式（`remediation-patterns.md` 中定义）

| 模式 | 状态 | 原因 |
|---|---|---|
| 命令注入 | 未覆盖 | Python 生态中命令注入 CVE 较少，多见于应用层 |
| 认证覆盖（中间件） | 未覆盖 | 需要多路由认证中间件遗漏的场景 |
| 安全配置 | 未覆盖 | 配置类漏洞多为应用特定，缺少标准化 CVE |
| 密钥泄露（历史） | 未覆盖 | 需要涉及 git 历史密钥轮换的场景 |

## 目录结构

```
validation-coverage/
├── sql-injection/
│   ├── cve-2024-42005-finding.yaml
│   └── django-5.0.6/                   # 脆弱版本
├── ssrf/
│   ├── cve-2023-47116-finding.yaml
│   └── label-studio-1.10.0/            # 脆弱版本
├── deserialization/
│   ├── cve-2023-50943-finding.yaml
│   └── airflow-2.8.0/                  # 脆弱版本
├── authz-bypass/
│   ├── cve-2024-21543-finding.yaml
│   └── djoser-2.2.0/                   # 脆弱版本
├── authentication/
│   ├── cve-2024-37568-finding.yaml
│   └── authlib-1.3.0/                  # 脆弱版本
├── weak-crypto/
│   ├── cve-2023-50782-finding.yaml
│   └── cryptography-41.0.5/            # 脆弱版本
├── secrets-exposure/
│   ├── cve-2024-47081-finding.yaml
│   └── requests-2.32.3/                # 脆弱版本
├── race-condition/
│   ├── cve-2025-68146-finding.yaml
│   └── filelock-3.20.0/                # 脆弱版本
├── dependency-upgrade/
│   ├── cryptography-41to42-finding.yaml
│   └── (使用 weak-crypto 的同一仓库)
├── upstream-fixed/
│   ├── django-5.0.8/
│   ├── label-studio-1.11.0/
│   ├── djoser-2.3.0/
│   ├── authlib-1.3.1/
│   ├── cryptography-42.0.0/
│   ├── requests-2.32.4/
│   └── filelock-3.20.1/
└── reports/
    └── coverage-expansion-summary.md   # 本报告
```

## 各案例预期验证要点

### 1. SQL 注入 — Django CVE-2024-42005
- **关键能力测试**：是否能从 ORM 层的 `check_alias()` 缺失推导出完整的列别名安全不变量
- **边界测试**：含空白、引号、分号、SQL 注释的 JSON 键名
- **易错点**：可能漏掉 `values_list()` 中的同类型调用点

### 2. SSRF — Label Studio CVE-2023-47116
- **关键能力测试**：是否能识别"仅验证一次 DNS"的设计缺陷
- **边界测试**：HTTP 重定向、DNS 重绑定、IPv4/IPv6 私有地址
- **易错点**：可能只修复已知绕过方式而非恢复完整 SSRF 保护

### 3. 反序列化 — Airflow CVE-2023-50943
- **关键能力测试**：是否能找到 pickle 回退路径
- **边界测试**：已知安全类型的序列化/反序列化往返 + 恶意 pickle payload
- **易错点**：pickle 反序列化的修复需要彻底移除或严格白名单，不能只加黑名单

### 4. 鉴权绕过 — djoser CVE-2024-21543
- **关键能力测试**：是否能识别 authenticate() 失败后的回退逻辑
- **边界测试**：正常认证、2FA 认证、LDAP 认证、无用户场景
- **易错点**：修复可能只处理了 authenticate() 返回 None 的情况而漏掉其他失败模式

### 5. 认证缺陷 — Authlib CVE-2024-37568
- **关键能力测试**：是否能独立发现"未指定算法时允许 HMAC+公钥"的算法混淆
- **边界测试**：RS256/ES256 正常 JWT、HMAC 伪造 JWT、不带 alg 头的 JWT
- **易错点**：可能只修了显式调用点而漏掉默认参数路径

### 6. 弱加密 — cryptography CVE-2023-50782
- **关键能力测试**：是否能理解 RSA Bleichenbacher padding oracle 的时序攻击本质
- **边界测试**：正确/错误 padding 的响应时间差异
- **易错点**：这是已知困难问题——完整修复依赖 OpenSSL 3.2 新 API，Skill 可能给出不完整的缓解方案

### 7. 密钥泄露 — requests CVE-2024-47081
- **关键能力测试**：是否能定位 URL 解析中 `@` 符号处理导致的 host 混淆
- **边界测试**：`user:pass@host`、`host:@evil`、`@evil` 格式
- **易错点**：修复可能破坏合法的 `user:pass@host` URL 格式

### 8. 竞争条件 — filelock CVE-2025-68146
- **关键能力测试**：是否能识别 CHECK-then-USE 模式并应用原子操作
- **边界测试**：正常锁文件、符号链接指向受害者文件、目录结点
- **易错点**：可能只加延迟/重试而不加 O_NOFOLLOW（不可靠）

### 9. 依赖大版本升级 — cryptography 41.x → 42.x
- **关键能力测试**：是否能分析破坏性变更（OpenSSL 版本要求、API 废弃、Python 版本）
- **边界测试**：依赖声明更新、lockfile 一致性、API 兼容性扫描
- **易错点**：可能简单推荐"升级到最新版"而不分析兼容性影响

## 已知验证环境限制

与已有 6 案例相同，本次扩展面临相同的环境约束：

| 门禁 | 状态 | 原因 |
|---|---|---|
| Docker 隔离构建 | 不可用 | Windows 环境无 Docker Desktop |
| SAST 扫描复验（Semgrep） | 不可用 | 未配置 |
| SCA 扫描复验（OSV-Scanner） | 不可用 | 未配置 |
| DAST 扫描复验 | 不可用 | 无 DAST 工具 |
| 多 Python 版本 | 不可用 | 仅 Windows + Python 3.14 |
| Linux 环境 | 不可用 | 仅 Windows 可用 |
| 完整 CI 测试套件 | 部分 | 部分项目（Django、Airflow）需要数据库/中间件 |
| 跨平台符号链接测试 | 不可用 | Windows symlink 需要管理员权限 |

## 下一步执行计划

1. 对每个案例在隔离环境中运行 `remediate-vulnerabilities` Skill
2. 按照盲测协议（步骤 1-7）：定位根因 → 生成首轮候选 → 运行安全回归 → 迭代修订
3. 冻结核心候选后，与 `upstream-fixed/` 中的官方修复版本做差异对比
4. 报告三项指标：首轮正确性、自主验证后收敛、官方参考一致性
5. 汇总所有 15 个案例（6 已有 + 9 新增），更新覆盖面的统计结论

---

*报告生成时间：2026-07-07。验证环境已就绪，待逐一执行 Skill 验证。*
