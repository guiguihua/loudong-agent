# cryptography 41→42 依赖大版本升级方案

状态：已验证升级路径分析

## 执行摘要

cryptography 42.0.0 是一次大版本升级，修复了 CVE-2023-50782（RSA Bleichenbacher 修复不完整）。关键发现：Finding YAML 中关于"OpenSSL 3.2 强制要求"的描述被过度陈述——42.0.0 仍支持 OpenSSL 1.1.1d+，只是 PyPI 预编译 wheel 改用 OpenSSL 3.2.0 编译。实际破坏性变更主要包括：LibreSSL < 3.7 移除支持、Rust MSRV 提升至 1.63.0、PKCS7 空 content 行为变更、X.509 日期属性弃用。对于绝大多数 pip 用户，`pip install --upgrade cryptography>=42.0.0` 即可直接升级。

## 实际破坏性变更（按严重程度）

| 变更 | 影响范围 | 阻塞性 |
|------|---------|--------|
| LibreSSL < 3.7 移除支持 | 使用 LibreSSL 的系统（部分 BSD） | 阻塞 |
| Rust MSRV 1.56→1.63 | 源码编译用户（非 wheel 用户） | 部分 |
| PKCS7 空 content 行为变更 | 使用 `load_pem_pkcs7_certificates` 的代码 | 需适配 |
| X.509 日期属性弃用 | 使用 `not_valid_before`/`not_valid_after` 等 5 个属性的代码 | 建议迁移 |
| setup.py 移除 | 使用 `python setup.py install` 的构建流程 | 阻塞 |

## Finding YAML 纠正

分析发现初始 finding YAML 中存在两处需要纠正的信息：
1. **"最低 OpenSSL 要求提升至 3.2"** → 实际上 42.0.0 仍支持 OpenSSL 1.1.1d+；只是 PyPI wheel 编译器升级
2. **"Python 3.7 支持被移除"** → `requires-python` 仍为 `>=3.7`

这揭示了一个关键问题：**即使是人工编写的 finding 输入也可能包含事实性错误**。Skill 在设计时应对 SCA/CVE 报告中的升级约束进行独立的 CHANGELOG 交叉验证。

## 升级策略

1. **第一阶段**（即时）：`pip install --upgrade cryptography>=42.0.0`——绝大多数用户通过预编译 wheel 直接升级
2. **第二阶段**（1-2周）：处理 PKCS7 空 content 行为变更和 X.509 弃用属性迁移
3. **第三阶段**（有条件）：源码编译用户升级 Rust 工具链到 1.63.0+
4. **回滚**：`pip install cryptography==41.0.7`（最新 41.x 补丁版本）

## 对 Skill 的启示

当前 `remediation-patterns.md` 的依赖升级指导偏向于"选择最小安全版本并检查兼容性"的抽象描述。本次分析表明，Skill 在依赖升级场景下还需要：
1. **区分"构建时依赖 vs 运行时依赖"**——wheel 用户不受 Rust/编译工具链变更影响
2. **区分"wheel 用户 vs 源码编译用户"**——两类用户的升级路径完全不同
3. **独立交叉验证 SCA 报告的升级约束**——不要直接信任初始 finding 中的版本要求描述
4. **检查 CHANGELOG 而非仅看版本号**——大版本号不一定意味着所有破坏性变更都相关
