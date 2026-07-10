# 修复 SQL Injection（F-SQLI-003）

## 修改摘要
候选补丁 patch-F-SQLI-003-001 已针对 SQL Injection 完成修复，并通过构建、业务回归、安全回归、扫描复验和差异风险验证。

## 漏洞信息
- 漏洞 ID：F-SQLI-003
- 漏洞类型：SQL Injection
- 严重性：high
- 来源工具：SAST
- 受影响服务：customer-service

## 漏洞根因
**安全不变量**：所有用户可控数据在进入 SQL 查询时必须通过参数绑定（parameter binding）传递，不得参与 SQL 语句字符串的构造。SQL 结构（关键字、表名、列名）与数据值必须严格分离。

**守卫/缺失控制**：`cursor.execute 必须在第二个参数中接收用户数据，即 cursor.execute(sql_template, (param1, param2, ...))，其中 sql_template 使用 ? 占位符而非字符串拼接。` 是本路径必须执行的安全守卫。

**根因摘要**：用户输入 keyword 通过字符串拼接直接嵌入 SQL 查询，未使用参数化查询，导致 SQL 注入。

**破坏机制**：

1. 入口：request.args.get('q', '') 在 search() 第28行获取不可信输入
2. 传播：q 未经处理传入 search_users(q) 第29行，成为 keyword 形参
3. 缺失安检：第18行使用字符串拼接 '+' 将 keyword 嵌入 SQL 模板，未切换到参数化查询
4. 汇点：第19行 cursor.execute(sql) 执行被污染的 SQL 语句
5. 触发：攻击者构造 ?q=' OR '1'='1 即可闭合单引号并注入任意 SQL

**因果链路**：HTTP GET 请求到达 /users/search 端点 → search() 函数通过 request.args.get('q', '') 提取未经处理的用户输入 → 原始输入 q 直接传递给 search_users(q) → search_users 内部将 keyword 拼接到 SQL 字符串：'SELECT ... WHERE name LIKE '%' + keyword + '%'' → 拼接后的 sql 字符串直接传给 cursor.execute(sql) 执行 → 攻击者控制的 SQL 片段在数据库层被执行，导致数据泄露、篡改或删除

**可利用性说明**：高度可被利用。攻击者只需向公开的 /users/search 端点发送带载荷的 GET 请求。无需认证，无任何输入过滤，payload 直接闭合 LIKE 子句中的单引号即可注入任意 SQL 语句。sqlite3 支持多语句执行，攻击者可通过 UNION SELECT 窃取数据，或通过附加语句修改/删除数据。

**修复约束**：
- 修复必须将字符串拼接改为参数化查询：sql = 'SELECT id, name, email FROM users WHERE name LIKE ?'; cursor.execute(sql, ('%' + keyword + '%',))
- 或使用 ORM/query builder 抽象 SQL 构造
- keyword 中的通配符 % 和 _ 应在应用层转义后再传入 LIKE 子句，防止攻击者通过通配符进行拒绝服务
- 修复后应通过单元测试验证：传入 SQL 注入载荷不会改变查询语义

## 修复方案
**修复目标**：消除 search_users 函数中的 SQL 注入漏洞，将字符串拼接改为参数化查询，同时转义 LIKE 通配符以防止 DoS 攻击。

**修改文件**：
- `src/user/search.py`：新增 escape_like_wildcards 辅助函数，将 keyword 中的 % 和 _ 分别转义为 \% 和 \_（原因：防止攻击者通过注入大量通配符造成 LIKE 查询性能退化（DoS），同时保留用户正常使用通配符的能力）
- `src/user/search.py`：将第 18 行字符串拼接 SQL 替换为参数化查询：sql='SELECT id, name, email FROM users WHERE name LIKE ? ESCAPE \'\\\''; cursor.execute(sql, ('%' + escape_like_wildcards(keyword) + '%',))（原因：消除 SQL 注入根因——用户输入不再直接嵌入 SQL 语句，而是作为参数绑定传递）
- `tests/test_search.py`：新建单元测试文件，覆盖：正常关键词搜索、SQL 注入载荷（如 ' OR '1'='1）、LIKE 通配符转义、空关键词、特殊字符关键词（原因：验证修复有效且不引入回归；确保 SQL 注入载荷不会改变查询语义）

**修改策略**：将 search_users 中的字符串拼接 SQL 改为参数化查询，并添加 LIKE 通配符转义辅助函数

**实施步骤**：
1. 1. 在 src/user/search.py 中新增 escape_like_wildcards 函数：将 keyword 中的 % 转义为 \%，_ 转义为 \_，并保留 SQLite 默认的 ESCAPE '\' 语义。
2. 2. 修改 search_users 函数第 18 行：将 sql = "SELECT id, name, email FROM users WHERE name LIKE '%" + keyword + "%'" 替换为 sql = "SELECT id, name, email FROM users WHERE name LIKE ? ESCAPE '\'"
3. 3. 修改 cursor.execute(sql) 为 cursor.execute(sql, ('%' + escape_like_wildcards(keyword) + '%',))，使用参数化传递。
4. 4. 在 tests/ 目录新建 test_search.py，编写单元测试验证：正常搜索、SQL 注入载荷不改变语义、通配符转义正确。

**需要新增/保留的测试**：
- test_normal_search：传入普通关键词 'alice' 应返回 name 包含 'alice' 的用户记录，查询不报错
- test_sql_injection_or_tautology：传入 "' OR '1'='1" 不应返回全表数据，查询语义应仅匹配字面包含该字符串的 name
- test_sql_injection_union：传入 "' UNION SELECT 1,2,3--" 不应触发 UNION 注入，查询应仅作 LIKE 字面匹配
- test_wildcard_escaping_percent：输入 '100%' 应转义为 '100\%'，LIKE 查询仅匹配字面 '100%' 而非 '100' 后跟任意字符
- test_wildcard_escaping_underscore：输入 'a_b' 应转义为 'a\_b'，LIKE 查询仅匹配字面 'a_b' 而非 'a' + 任意单字符 + 'b'
- test_empty_keyword：传入空字符串应返回所有用户（LIKE '%%'），不报错
- test_special_characters：传入包含单引号、双引号、反斜杠等特殊字符的关键词，查询不报错且语义正确

**替代方案取舍**：
- 不采用 `仅对 keyword 做 input sanitization（如过滤单引号）而不使用参数化查询`：黑名单过滤不可靠，总有绕过方式；参数化查询是消除 SQL 注入的根因方案
- 不采用 `引入 SQLAlchemy ORM 重写整个数据访问层`：对于当前单函数、单查询的简单场景过度工程化，引入额外依赖和维护成本，且需要回归测试整个数据访问层
- 不采用 `使用存储过程封装查询`：SQLite 不支持存储过程，且当前架构不适用

## 修改文件列表
- src/user/search.py
- tests/test_search.py

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
- ESCAPE 子句兼容性：SQLite 默认支持 ESCAPE '\'，但若未来切换数据库（如 PostgreSQL 使用 ESCAPE '\' 同样兼容，MySQL 需确认），需验证目标数据库的 ESCAPE 语法。
- 转义后的 keyword 若本身包含反斜杠，需额外处理（如用户输入 'a\%b' 应被转义为 'a\\\%b'），escape_like_wildcards 应先转义反斜杠再转义通配符。
- 现有调用方：search_users 被 /users/search 路由直接调用，参数来源为 request.args.get('q')，修复不改变函数签名和返回值结构，兼容性良好。
- 测试环境需 sqlite3 内存数据库或临时文件，避免污染生产数据。
- escape_like_wildcards 会转义用户输入中的 % 和 _，可能改变某些合法搜索的预期行为（如用户确实想用通配符搜索），但这是安全性优先的合理权衡
- ESCAPE '\' 语法在 SQLite 以外的数据库（如 MySQL、PostgreSQL）中可能需要调整，跨数据库迁移时需注意
- 测试使用 mock 隔离了数据库，未覆盖真实 SQLite 执行路径；建议补充集成测试验证端到端行为

## 回滚方案
回滚修复变更
- revert changes
- 重新运行回归测试

## 人工审查重点
- 确认补丁与修复目标一致，且没有绕过验证或削弱安全控制。
- 确认验证过程运行在授权的非生产环境中。
- 高危漏洞：需要重点审查根因说明和漏洞回归验证证据。
- 检查受影响的公网入口或需认证 API 路径是否被完整覆盖。
- 检查变更范围，确认未引入无关业务行为变化。
