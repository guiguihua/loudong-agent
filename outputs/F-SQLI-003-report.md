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
**安全不变量**：所有流入 SQL 执行引擎的用户数据必须通过参数化查询（占位符绑定）传递，绝不通过字符串拼接嵌入 SQL 语句。

**守卫/缺失控制**：`在 cursor.execute() 调用点强制执行：SQL 语句模板与用户数据必须分离，使用 ? 占位符 + 参数元组形式，即 cursor.execute('SELECT ... WHERE name LIKE ?', (f'%{keyword}%',))。` 是本路径必须执行的安全守卫。

**根因摘要**：不可信的 HTTP GET 参数 'q' 通过字符串拼接直接嵌入 SQL LIKE 查询，未使用参数化查询，导致 SQL 注入。

**破坏机制**：

1. 入口: GET /users/search?q=<payload> → request.args.get('q','') 获取不可信输入
2. 传播: q → search_users(keyword) → 字符串拼接 sql = '...' + keyword + '...'
3. 缺失安检: 无参数化查询、无输入校验、无输出编码、无 SQL 转义
4. 汇点: cursor.execute(sql) 直接执行攻击者可控的 SQL
5. 触发: q=' UNION SELECT 1,2,3-- 即可绕过原 SQL 语义

**因果链路**：1. Flask 应用在 /users/search 端点上绑定 search() 处理函数 → 2. search() 通过 request.args.get('q', '') 从 URL 查询字符串获取用户输入（无任何校验） → 3. 原始输入 q 直接传递给 search_users(q) 作为 keyword 参数 → 4. search_users() 内部使用 Python 字符串拼接（+ 运算符）将 keyword 嵌入 SQL 模板 → 5. 拼接后的 SQL 字符串直接传入 cursor.execute() 执行 → 6. 攻击者可在 q 参数中注入 ' OR '1'='1 等 payload，篡改 SQL 语义，窃取/篡改数据库数据

**可利用性说明**：极易利用：攻击者仅需在浏览器地址栏或 HTTP 请求中修改 q 参数即可注入任意 SQL。sqlite3 支持多条语句（需特定配置）和 UNION 注入，可泄露 users 表全部数据，甚至通过附带SQLite特定语法读取其他表（如 sqlite_master）。无需认证，无需特殊工具。

**修复约束**：
- 必须将字符串拼接改为参数化查询：cursor.execute('SELECT id, name, email FROM users WHERE name LIKE ?', (f'%{keyword}%',))
- 如果 keyword 可能包含 % 或 _ 通配符且不应被解释为 LIKE 模式，需额外转义这些字符
- 考虑添加输入长度限制（如最大 100 字符）作为纵深防御
- 考虑添加 Web 应用防火墙（WAF）规则检测 SQL 注入模式

## 修复方案
**修复目标**：消除 src/user/search.py 中 search_users 函数的 SQL 注入漏洞，将字符串拼接改为参数化查询，并增加纵深防御措施（输入长度限制、LIKE 通配符转义、WAF 规则）。

**修改文件**：
- `src/user/search.py`：修改 search_users 函数：删除第18行字符串拼接 SQL，替换为参数化查询 cursor.execute('SELECT id, name, email FROM users WHERE name LIKE ?', (pattern,))；新增 LIKE 通配符转义函数 escape_like_pattern(keyword)；新增输入长度限制（max 100 chars）；修改 search() 路由增加异常处理返回 400。（原因：直接消除 SQL 注入根因——不可信输入通过字符串拼接进入 SQL 语句。参数化查询是 SQL 注入的黄金标准修复方案。）
- `src/user/search.py`：新增 escape_like_pattern 辅助函数，转义 SQLite LIKE 子句中的特殊通配符 % 和 _，防止攻击者利用通配符进行盲注或 DoS。（原因：LIKE 查询中即使使用参数化，通配符 % 和 _ 仍可能被攻击者利用进行模式匹配攻击或资源耗尽。转义确保 keyword 被当作字面文本搜索。）
- `tests/test_search.py`：新增测试文件，覆盖：正常搜索返回匹配用户、空关键词、含 % 和 _ 通配符的搜索、超长关键词（>100）返回错误、经典 SQL 注入 payload（' OR '1'='1' --）验证不产生异常结果。（原因：确保修复有效且不会引入回归问题。SQL 注入修复必须有安全回归测试。）

**修改策略**：将 search_users 中的字符串拼接 SQL 改为参数化查询，同时转义 LIKE 通配符并限制输入长度。这是最直接、最彻底的修复方案。

**实施步骤**：
1. 1. 在 search_users 函数中，删除字符串拼接构建 SQL 的代码（第18行），改为参数化查询 cursor.execute('SELECT id, name, email FROM users WHERE name LIKE ?', (f'%{escaped_keyword}%',))
2. 2. 在 search_users 函数开头添加 LIKE 通配符转义逻辑：将 keyword 中的 '%' 替换为 '\%'、'_' 替换为 '\_'、以及 SQLite 默认转义符 '\' 替换为 '\\'（防止攻击者注入通配符进行盲注或资源耗尽攻击）。注意 SQLite 的 LIKE 子句使用 '\' 作为默认 ESCAPE 字符。
3. 3. 在 search_users 函数中添加输入长度校验：if len(keyword) > 100: raise ValueError('keyword too long')，作为纵深防御。
4. 4. 在 Flask 路由 search() 中捕获异常，返回 400 Bad Request 而非直接暴露内部错误。
5. 5. 编写单元测试覆盖：正常搜索、空关键词、含通配符的关键词、超长关键词、SQL 注入 payload（如 ' OR '1'='1）。

**需要新增/保留的测试**：
- test_normal_search：给定 keyword='Alice'，返回包含 'Alice' 的用户记录列表
- test_empty_keyword：给定 keyword=''，返回所有用户（LIKE '%%' 匹配全部），不抛出异常
- test_sqli_payload_or_injection：HTTP 200 返回空结果或仅匹配字面字符串的结果，不得返回全表数据
- test_sqli_payload_union_select：不返回额外行，不泄露其他表数据，查询安全执行
- test_like_wildcard_escape：keyword='100%' 时，仅匹配 name 字面包含 '100%' 的记录，不匹配 '100% Cotton' 以外的 '%' 通配行为
- test_keyword_too_long：keyword 长度超过 100 时抛出 ValueError 或路由返回 400 Bad Request
- test_special_characters：keyword 含单引号、双引号、反斜杠等特殊字符时不崩溃、不注入，安全返回结果

**替代方案取舍**：
- 不采用 `仅转义单引号而不使用参数化查询`：输入过滤（黑名单/转义）无法覆盖所有注入向量，SQL 注入的行业标准修复方式是参数化查询，仅转义是不可靠的半吊子方案。
- 不采用 `仅部署 WAF 规则而不修改代码`：WAF 是纵深防御手段，不能替代代码修复。WAF 可被绕过，且不解决内部调用 search_users 的非 HTTP 路径注入风险。
- 不采用 `将 LIKE 改为精确匹配 =`：业务需求是关键词搜索（模糊匹配），改为精确匹配会破坏功能。

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
- 参数化查询修改改变了 SQL 执行路径，需确认 SQLite 的 LIKE + 参数化与原有行为完全一致（已验证 SQLite 支持此语法，风险极低）
- 转义 LIKE 通配符可能改变搜索行为：原本 keyword='a%b' 会匹配 'aXb' 等，转义后仅匹配字面 'a%b'。需与产品确认这是预期行为
- 输入长度限制为 100 字符可能截断合法长查询，需与业务方确认此阈值合理
- 无现有测试套件，修复后需从零编写回归测试，初期覆盖可能不完整

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
