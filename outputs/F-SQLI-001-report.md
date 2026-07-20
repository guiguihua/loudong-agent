# 修复 SQL Injection（F-SQLI-001）

## 修改摘要
候选补丁 patch-F-SQLI-001-001 已针对 SQL Injection 生成，并在隔离的临时工作区通过全部适用验证。补丁未写入或合并到原始代码仓库，需由人工审查后决定是否采用。

## 漏洞信息
- 漏洞 ID：F-SQLI-001
- 漏洞类型：SQL Injection
- 严重性：high
- 来源工具：SAST
- 受影响服务：customer-service

## 影响面
**证据等级**：状态 `possible`，置信度 0.30。以下列表仅应包含已由当前仓库、资产或运行时上下文支持的项目；潜在范围列在不确定项中。

**受影响服务/组件**：
- customer-service

**调用路径**：
1. 外部输入/请求 → search_users @ src/user/search.py:5 → SQL Injection 危险操作

**受影响数据**：
- 受影响数据（证据: user input 'keyword' from request.args.get('q') concatenated into SQL query — no parameterization）

**建议回归测试**：
- 验证 SQL Injection 的利用条件在修复后是否被阻断
- 验证正常认证流程不受影响

**不确定项**：
- unverified entry point removed from confirmed impact: ANY SQL Injection 触发入口

## 漏洞根因
**根因摘要**：F-SQLI-001: SQL Injection — 受影响位置 src/user/search.py:5. 证据: user input 'keyword' from request.args.get('q') concatenated into SQL query — no parameterization

## 修复方案
**修复目标**：Replace SQL string construction with parameterized queries while preserving existing query semantics.

**修改文件**：
- `src/user/search.py`：Replace SQL concatenation/interpolation with parameterized query execution.（原因：针对 SQL Injection 的安全控制（具体控制尚未从源码证据确认，需人工审查。））

**修改策略**：Use bound SQL parameters for every user-controlled value.

**实施步骤**：
1. Locate the vulnerable SQL execution path.
2. Move user-controlled values into driver placeholders instead of SQL text.
3. Preserve existing filters, result shape, and error behavior.
4. Add or run a SQL injection regression check before merging.

**需要新增/保留的测试**：
- F-SQLI-001 SQL injection regression：malicious SQL payload is treated as data and cannot change query structure
- F-SQLI-001 search behavior regression：normal queries keep the previous response shape and matching behavior

**替代方案取舍**：
- 不采用 `input blacklist only`：blacklists are bypass-prone and do not enforce the SQL parameterization invariant

## 修改文件列表
- src/user/search.py
- tests/test_user_search.py

## 候选补丁
### `src/user/search.py`

Git-generated diff from verified structured edits

```diff
diff --git a/src/user/search.py b/src/user/search.py
index 25d1f6f..cbb77e2 100644
--- a/src/user/search.py
+++ b/src/user/search.py
@@ -3,6 +3,6 @@ from flask import request

 def search_users(cursor):
     keyword = request.args.get("q", "")
-    sql = "select * from users where name like '%" + keyword + "%'"
-    cursor.execute(sql)
+    sql = "select * from users where name like %s"
+    cursor.execute(sql, (f"%{keyword}%",))
     return cursor.fetchall()
```

### `tests/test_user_search.py`

Git-generated diff from verified structured edits

```diff
diff --git a/tests/test_user_search.py b/tests/test_user_search.py
index 339733b..ec38f0a 100644
--- a/tests/test_user_search.py
+++ b/tests/test_user_search.py
@@ -1,2 +1,34 @@
 def test_search_users_returns_results():
     assert True
+
+def test_search_users_uses_bound_parameters_for_attack_and_legitimate_input():
+    import importlib
+    from types import SimpleNamespace
+
+    module = importlib.import_module("src.user.search")
+
+    class RecordingCursor:
+        def execute(self, *args):
+            self.last_execute = args
+
+        def fetchall(self):
+            return []
+
+    original_request = module.request
+    try:
+        cursor = RecordingCursor()
+        attack = "' OR '1'='1"
+        module.request = SimpleNamespace(args={"q": attack})
+        module.search_users(cursor)
+        query, params = cursor.last_execute
+        assert attack not in query
+        assert attack in repr(params)
+
+        legitimate = "alice"
+        module.request = SimpleNamespace(args={"q": legitimate})
+        assert module.search_users(cursor) == []
+        query, params = cursor.last_execute
+        assert legitimate not in query
+        assert legitimate in repr(params)
+    finally:
+        module.request = original_request
```

## 测试结果
- 构建验证：通过 - build validation passed
-   - "C:\Python314\python.exe" -m compileall -q .：通过（build command completed）
    命令: `"C:\Python314\python.exe" -m compileall -q .`；退出码: 0；耗时: 790 ms；证据:
```text
Unified diff applied successfully in the isolated workspace.
Command completed without output.
```
- 业务回归验证：通过 - business_regression validation passed
-   - "C:\Python314\python.exe" -m pytest -q：通过（business_regression command completed）
    命令: `"C:\Python314\python.exe" -m pytest -q`；退出码: 0；耗时: 10642 ms；证据:
```text
..                                                                       [100%]
2 passed in 0.86s
```

## 安全验证结果
- 安全回归验证：通过 - security_regression validation passed
-   - "C:\Python314\python.exe" -m pytest -q "tests/test_user_search.py"：通过（security_regression command completed）
    命令: `"C:\Python314\python.exe" -m pytest -q "tests/test_user_search.py"`；退出码: 0；耗时: 5706 ms；证据:
```text
..                                                                       [100%]
2 passed in 0.32s
```
- 差异风险验证：通过 - differential_risk validation passed
-   - candidate policy check：通过（candidate is within declared patch boundaries）
    命令: `internal:patch-policy-check`；退出码: 0；证据:
```text
changed_files=2
estimated_diff_lines=36
allowed_files_only=True
```

## 完整验证结果
- 构建验证：通过
-   - "C:\Python314\python.exe" -m compileall -q .：通过（build command completed）
    命令: `"C:\Python314\python.exe" -m compileall -q .`；退出码: 0；耗时: 790 ms；证据:
```text
Unified diff applied successfully in the isolated workspace.
Command completed without output.
```
- 业务回归验证：通过
-   - "C:\Python314\python.exe" -m pytest -q：通过（business_regression command completed）
    命令: `"C:\Python314\python.exe" -m pytest -q`；退出码: 0；耗时: 10642 ms；证据:
```text
..                                                                       [100%]
2 passed in 0.86s
```
- 安全回归验证：通过
-   - "C:\Python314\python.exe" -m pytest -q "tests/test_user_search.py"：通过（security_regression command completed）
    命令: `"C:\Python314\python.exe" -m pytest -q "tests/test_user_search.py"`；退出码: 0；耗时: 5706 ms；证据:
```text
..                                                                       [100%]
2 passed in 0.32s
```
- 差异风险验证：通过
-   - candidate policy check：通过（candidate is within declared patch boundaries）
    命令: `internal:patch-policy-check`；退出码: 0；证据:
```text
changed_files=2
estimated_diff_lines=36
allowed_files_only=True
```

## 风险说明
- LIKE wildcard semantics must remain compatible after parameter binding
- existing tests may be absent, so generated patch still needs human review
- Root-cause confidence is below 0.70; patch placement requires explicit human review.
- 根因置信度 < 0.45: source/sink 未确认，修复范围已自动扩大。需要人工确认实际修复目标文件。
- 影响面置信度仅为 0.30；未确认的服务、入口和调用路径仍需人工核实。
- 根因置信度仅为 0.30；补丁位置和安全不变量仍需人工复核。

## 回滚方案
Revert the generated code or manifest changes and rerun validation.
- revert patch
- rerun build and security checks

## 人工审查重点
- 确认补丁与修复目标一致，且没有绕过验证或削弱安全控制。
- 确认验证过程运行在授权的非生产环境中。
- 高危漏洞：需要重点审查根因说明和漏洞回归验证证据。
- 检查变更范围，确认未引入无关业务行为变化。
