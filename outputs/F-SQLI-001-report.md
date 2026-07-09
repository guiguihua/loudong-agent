# 修复 SQL Injection（F-SQLI-001）

## 修改摘要
候选补丁 patch-F-SQLI-001-001 已针对 SQL Injection 完成修复，并通过构建、业务回归、安全回归、扫描复验和差异风险验证。

## 漏洞信息
- 漏洞 ID：F-SQLI-001
- 漏洞类型：SQL Injection
- 严重性：high
- 来源工具：SAST
- 受影响服务：customer-service

## 漏洞根因
**安全不变量**：任何最终进入 SQL 执行 API 的不可信输入，都必须作为绑定参数传入，不得参与 SQL 语句字符串拼接。

**守卫/缺失控制**：`parameterized_query` 是本路径必须执行的安全守卫。

**根因摘要**：search_users 的不可信数据未经 parameterized_query 到达 execute

**破坏机制**：

1. 入口：search_users 接收或保留不可信输入。
2. 传播：search_users 发生 propagates untrusted input without sanitization。
3. 缺失/失效安检：string concatenation，原因：user input concatenated into SQL bypasses parameterized query guard。
4. 危险汇点：数据最终进入 execute。
5. 触发条件：user input concatenated into SQL query。

**因果链路**：不可信输入来自 search_users → search_users: propagates untrusted input without sanitization → 数据进入危险操作 execute

**可利用性说明**：攻击者可通过构造 SQL 片段改变查询结构；修复应确保 payload 只作为参数值处理。

**修复约束**：
- 必须使用参数化查询或等价安全 API
- 不得仅使用 SQL 字符黑名单
- 必须保留原查询业务语义
- 必须新增 SQL Injection 安全回归测试

## 修复方案
**修复目标**：阻断不可信输入进入 SQL 拼接执行路径，同时保持原查询语义

**修改文件**：
- `src/user/search.py`：replace SQL string concatenation with parameterized query（原因：search_users 的不可信数据未经 parameterized_query 到达 execute）

**修改策略**：使用参数化查询或等价安全 ORM API 替换字符串拼接 SQL

**实施步骤**：
1. 保留原查询条件语义
2. 将用户输入作为绑定参数传入
3. 覆盖恶意 SQL payload 和正常查询用例

**需要新增/保留的测试**：
- business regression for API request：原有业务流程和接口契约保持不变
- SQL Injection security regression：影响面相关安全或业务假设得到验证
- sensitive data access regression：影响面相关安全或业务假设得到验证
- scanner rescan：原始漏洞规则或同类规则不再命中
- SQL Injection security regression：恶意 SQL payload 不会改变查询结构或执行额外语句

**替代方案取舍**：
- 不采用 `只对输入做 SQL 关键字黑名单过滤`：黑名单容易被编码、注释、大小写和数据库方言绕过

## 修改文件列表
- src/user/search.py
- tests/test_security_regression_f_sqli_001.py
- SECURITY_REMEDIATION.md

## 测试结果
- 构建验证：通过 - build validation passed
-   - build：通过（构建验证通过。）
- 业务回归验证：通过 - business_regression validation passed
-   - business regression：通过（业务回归测试通过。）

## 安全验证结果
- 安全回归验证：通过 - security_regression validation passed
-   - security regression：通过（安全回归测试通过。）
- 扫描复验：通过 - scanner_rescan validation passed
-   - scanner rescan：通过（扫描器复扫不再命中。）
- 差异风险验证：通过 - differential_risk validation passed
-   - diff risk：通过（补丁差异风险可接受。）

## 完整验证结果
- 构建验证：通过
-   - build：通过（构建验证通过。）
- 业务回归验证：通过
-   - business regression：通过（业务回归测试通过。）
- 安全回归验证：通过
-   - security regression：通过（安全回归测试通过。）
- 扫描复验：通过
-   - scanner rescan：通过（扫描器复扫不再命中。）
- 差异风险验证：通过
-   - diff risk：通过（补丁差异风险可接受。）

## 风险说明
- 修复可能改变输入处理、输出格式或错误返回行为
- 如果仅在局部位置修复，其他同类调用点仍可能残留风险

## 回滚方案
回滚本次代码和测试变更，恢复到修复前提交
- revert remediation commit
- 重新运行构建与核心回归测试
- 确认漏洞工单恢复为待修复状态

## 人工审查重点
- 确认补丁与修复目标一致，且没有绕过验证或削弱安全控制。
- 确认验证过程运行在授权的非生产环境中。
- 高危漏洞：需要重点审查根因说明和漏洞回归验证证据。
- 检查变更范围，确认未引入无关业务行为变化。
