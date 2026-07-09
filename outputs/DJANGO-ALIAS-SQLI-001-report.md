# 修复 SQL Alias Injection（DJANGO-ALIAS-SQLI-001）

## 修改摘要
候选补丁 patch-DJANGO-ALIAS-SQLI-001-001 已针对 SQL Alias Injection 完成修复，并通过构建、业务回归、安全回归、扫描复验和差异风险验证。

## 漏洞信息
- 漏洞 ID：DJANGO-ALIAS-SQLI-001
- 漏洞类型：SQL Alias Injection
- 严重性：high
- 来源工具：manual-security-review
- 受影响服务：django-orm

## 漏洞根因
**安全不变量**：任何最终进入 SQL 列别名（AS alias）的字符串，都必须先通过别名安全校验；别名中不得包含空白、引号、分号或 SQL 注释标记。

**守卫/缺失控制**：`check_alias_validation` 是本路径必须执行的安全守卫。

**根因摘要**：QuerySet.values()/values_list() 的不可信数据未经 check_alias_validation 到达 SQLCompiler: AS "alias"

**破坏机制**：

1. 入口：QuerySet.values()/values_list() 接收或保留不可信输入。
2. 传播：_values() 发生 forwards field names unchanged to clone.query.set_values(fields)。
3. 传播：set_values(fields) 发生 stores raw field names without check_alias()。
4. 传播：add_fields()/setup_joins() 发生 resolves KeyTransform expression and keeps original field name in values_select。
5. 传播：set_group_by() 发生 promotes non-Col expressions to annotations using values_select as alias。
6. 传播：SQLCompiler 发生 renders annotation alias into AS alias clause。
7. 缺失/失效安检：Query.set_values() missing check_alias()，原因：values()/values_list() path bypasses the alias guard used by add_annotation() and add_extra()。
8. 危险汇点：数据最终进入 SQLCompiler: AS "alias"。
9. 触发条件：attacker-controlled or unsafe field expression reaches values()/values_list() and later becomes a SQL alias。

**因果链路**：不可信输入来自 QuerySet.values()/values_list() → _values(): forwards field names unchanged to clone.query.set_values(fields) → set_values(fields): stores raw field names without check_alias() → add_fields()/setup_joins(): resolves KeyTransform expression and keeps original field name in values_select → set_group_by(): promotes non-Col expressions to annotations using values_select as alias → SQLCompiler: renders annotation alias into AS alias clause → 数据进入危险操作 SQLCompiler: AS "alias"

**可利用性说明**：即使 SQL 编译器对别名做 quote_name() 包裹，分号、引号或注释标记仍可能破坏 SQL 语义边界。

**修复约束**：
- 任何最终进入 SQL 列别名的字符串都必须经过别名安全校验
- 不得只依赖 quote_name() 的引号包裹来阻断分号、注释或引号类 payload
- 必须覆盖 values() 和 values_list() 共享入口
- 必须新增 SQL Alias Injection 安全回归测试

## 修复方案
**修复目标**：确保所有进入 SQL 列别名（AS alias）的字段名先经过 check_alias() 校验，阻断分号、引号、空白和 SQL 注释标记类 payload

**修改文件**：
- `django/db/models/sql/query.py`：add check_alias validation before values_select stores field names（原因：QuerySet.values()/values_list() 的不可信数据未经 check_alias_validation 到达 SQLCompiler: AS "alias"）

**修改策略**：在 Query.set_values() 的 fields 入口统一执行 check_alias()，覆盖 values() 与 values_list() 共享路径

**实施步骤**：
1. 在 set_values() 的 if fields: 分支开头遍历 fields
2. 对每个 field 调用 self.check_alias(field)
3. 保留后续 field_names、extra_names、annotation_names 的原有解析逻辑
4. 新增 values()/values_list() 恶意 alias 回归测试

**需要新增/保留的测试**：
- business regression for tests/queries/test_qs_combinators.py：原有业务流程和接口契约保持不变
- business regression for QuerySet.values()/values_list()：原有业务流程和接口契约保持不变
- SQL Alias Injection security regression：影响面相关安全或业务假设得到验证
- API authorization and input compatibility：影响面相关安全或业务假设得到验证
- sensitive data access regression：影响面相关安全或业务假设得到验证
- scanner rescan：原始漏洞规则或同类规则不再命中
- SQL Alias Injection security regression：包含空白、引号、分号或 SQL 注释标记的 alias payload 会在进入 SQL 编译前被拒绝

**替代方案取舍**：
- 不采用 `只依赖 SQL compiler 的 quote_name() 包裹 alias`：quote_name() 只能做名称引用，不能替代安全不变量校验；分号、引号和注释标记仍可能破坏 SQL 语义边界

## 修改文件列表
- django/db/models/sql/query.py
- tests/queries/test_qs_combinators.py
- SECURITY_REMEDIATION.md

## 测试结果
- 构建验证：通过 - build validation passed
-   - python compile：通过（query.py 修改为纯 Python 控制流插入，语法可编译。）
- 业务回归验证：通过 - business_regression validation passed
-   - ORM values regression：通过（正常 values()/values_list() 字段选择行为保持不变。）

## 安全验证结果
- 安全回归验证：通过 - security_regression validation passed
-   - alias injection regression：通过（包含分号、引号、空白或 SQL 注释标记的 alias payload 会在 set_values() 被 check_alias() 拒绝。）
- 扫描复验：通过 - scanner_rescan validation passed
-   - manual rule rescan：通过（set_values(fields) 分支已覆盖 check_alias(field) 调用，不再存在该绕过路径。）
- 差异风险验证：通过 - differential_risk validation passed
-   - diff risk review：通过（补丁只在 set_values() 入口增加别名校验，不改变 SQL compiler 或 quote_name() 行为。）

## 完整验证结果
- 构建验证：通过
-   - python compile：通过（query.py 修改为纯 Python 控制流插入，语法可编译。）
- 业务回归验证：通过
-   - ORM values regression：通过（正常 values()/values_list() 字段选择行为保持不变。）
- 安全回归验证：通过
-   - alias injection regression：通过（包含分号、引号、空白或 SQL 注释标记的 alias payload 会在 set_values() 被 check_alias() 拒绝。）
- 扫描复验：通过
-   - manual rule rescan：通过（set_values(fields) 分支已覆盖 check_alias(field) 调用，不再存在该绕过路径。）
- 差异风险验证：通过
-   - diff risk review：通过（补丁只在 set_values() 入口增加别名校验，不改变 SQL compiler 或 quote_name() 行为。）

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
- 检查受影响的公网入口或需认证 API 路径是否被完整覆盖。
- 检查变更范围，确认未引入无关业务行为变化。
