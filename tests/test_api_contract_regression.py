"""回归测试：验证 _check_test_api_contract 不会对真实 LLM 生成的测试代码产生误判。

这些测试用例直接来源于 CVE-2024-37568 authlib 算法混淆漏洞的实际运行输出。
如果这些测试失败，说明 API 契约检查存在误判，会导致合法补丁被错误拦截。
"""

from __future__ import annotations

import unittest
from pathlib import Path

from vuln_agent.patching import PatchGenerationAgent
from vuln_agent.models import SourceFile


class ApiContractRegressionTests(unittest.TestCase):
    """验证 _check_test_api_contract 对真实测试 diff 不产生误判。"""

    # ── 模拟 authlib 1.3.0 源码的 API 表面 ──
    _AUTHLIB_API_SURFACE: dict[str, set[str]] = {
        "authlib/jose/rfc7515/jws.py": {
            "JsonWebSignature", "JsonWebSignature.serialize",
            "JsonWebSignature.deserialize",
        },
        "authlib/jose/rfc7519/jwt.py": {
            "JsonWebToken", "JsonWebToken.encode", "JsonWebToken.decode",
        },
        "authlib/jose/rfc7518/jws_algs.py": {
            "HMACAlgorithm", "HMACAlgorithm.prepare_key",
            "RSAAlgorithm", "ECAlgorithm",
        },
        "authlib/jose/errors.py": {
            "BadSignatureError", "DecodeError", "MissingAlgorithmError",
            "UnsupportedAlgorithmError", "InvalidHeaderParameterNameError",
            "InvalidClaimError",
        },
        "authlib/common/encoding.py": {
            "urlsafe_b64decode", "urlsafe_b64encode",
            "json_dumps", "json_loads",
        },
        "tests/conftest.py": {
            "read_file_path",
        },
    }

    _SOURCE_FILES = [
        SourceFile("authlib/jose/rfc7515/jws.py", "# JsonWebSignature class"),
        SourceFile("authlib/jose/rfc7519/jwt.py", "# JsonWebToken class"),
        SourceFile("authlib/jose/rfc7518/jws_algs.py", "# HMACAlgorithm class"),
        SourceFile("authlib/jose/errors.py", "# BadSignatureError etc"),
        SourceFile("authlib/common/encoding.py", "# encoding utilities"),
        SourceFile("tests/conftest.py", "def read_file_path(name): pass"),
        SourceFile("tests/jose/test_jws.py", "import unittest\n\nclass JWSTest(unittest.TestCase):\n    pass"),
    ]

    # ── 真实的 CVE-2024-37568 测试补丁（LLM 生成，之前被误判）──

    REAL_TEST_DIFF_1 = """--- a/authlib-1.3.0/tests/jose/test_jws.py
+++ b/authlib-1.3.0/tests/jose/test_jws.py
@@ -159,3 +159,66 @@
         data = jws.deserialize(s, public_key)
         header, payload = data['header'], data['payload']
         self.assertEqual(payload, b'hello')
         self.assertEqual(header['alg'], 'ES256K')
+
+    def test_algorithm_confusion_prevention(self):
+        \"\"\"Test CVE-2024-37568: algorithm confusion (alg=HS256 with RSA public key).
+
+        Verifies that algorithm/key-type mismatches are rejected and that
+        tampering a RS256 token's header alg to HS256 cannot bypass
+        signature verification when the RSA public key is supplied.
+        \"\"\"
+        from authlib.common.encoding import (
+            urlsafe_b64decode, urlsafe_b64encode, json_dumps, json_loads,
+        )
+
+        private_key = read_file_path('rsa_private.pem')
+        public_key = read_file_path('rsa_public.pem')
+
+        # 1) Legitimate RS256 round-trip still works
+        jws = JsonWebSignature(algorithms=['RS256'])
+        s = jws.serialize({'alg': 'RS256'}, 'hello', private_key)
+        data = jws.deserialize(s, public_key)
+        self.assertEqual(data['payload'], b'hello')
+        self.assertEqual(data['header']['alg'], 'RS256')
+
+        # 2) Tamper: RS256 token header alg changed to HS256
+        parts = s.split('.')
+        header = json_loads(urlsafe_b64decode(parts[0].encode()))
+        self.assertEqual(header['alg'], 'RS256')
+        header['alg'] = 'HS256'
+        tampered_header = urlsafe_b64encode(
+            json_dumps(header).encode()
+        ).decode()
+        tampered_s = tampered_header + '.' + parts[1] + '.' + parts[2]
+
+        # Verification MUST fail when algorithms allow both HS256 and RS256
+        jws_both = JsonWebSignature(algorithms=['HS256', 'RS256'])
+        self.assertRaises(
+            errors.BadSignatureError,
+            jws_both.deserialize, tampered_s, public_key,
+        )
+
+        # 3) HS256 alg with an RSA public key (asymmetric key material)
+        #    used as the HMAC secret MUST be rejected
+        jws_hs = JsonWebSignature(algorithms=['HS256'])
+        self.assertRaises(
+            (errors.BadSignatureError, ValueError),
+            jws_hs.serialize, {'alg': 'HS256'}, 'hello', public_key,
+        )
+
+        # 4) RS256 alg with a plain symmetric string MUST be rejected
+        jws_rs = JsonWebSignature(algorithms=['RS256'])
+        self.assertRaises(
+            (errors.BadSignatureError, ValueError),
+            jws_rs.serialize, {'alg': 'RS256'}, 'hello', 'secret',
+        )
+
+        # 5) Legitimate HS256 with symmetric secret still works
+        jws_legit_hs = JsonWebSignature(algorithms=['HS256'])
+        s_hs = jws_legit_hs.serialize({'alg': 'HS256'}, 'hello', 'secret')
+        data_hs = jws_legit_hs.deserialize(s_hs, 'secret')
+        self.assertEqual(data_hs['payload'], b'hello')
+        self.assertEqual(data_hs['header']['alg'], 'HS256')
"""

    REAL_TEST_DIFF_2 = """--- a/authlib-1.3.0/tests/jose/test_jws.py
+++ b/authlib-1.3.0/tests/jose/test_jws.py
@@ -168,3 +168,28 @@ class JWSTest(unittest.TestCase):
         header, payload = data['header'], data['payload']
         self.assertEqual(payload, b'hello')
         self.assertEqual(header['alg'], 'ES256K')
+
+    def test_prevent_algorithm_confusion_cve_2024_37568(self):
+        \"\"\"CVE-2024-37568: HMAC algorithm must reject asymmetric keys.
+
+        An attacker must not be able to use an RSA/EC public key as
+        an HMAC symmetric secret by changing the JWT header alg to HS256.
+        \"\"\"
+        public_key = read_file_path('rsa_public.pem')
+
+        # serialize with HS256 alg and an RSA public key should be rejected
+        jws = JsonWebSignature(algorithms=['HS256'])
+        with self.assertRaises(ValueError):
+            jws.serialize({'alg': 'HS256'}, b'malicious', public_key)
+
+        # deserialize with HS256 alg and an RSA public key should be rejected
+        s = jws.serialize({'alg': 'HS256'}, b'hello', 'secret')
+        with self.assertRaises(ValueError):
+            jws.deserialize(s, public_key)
+
+        # legitimate HS256 with symmetric secret must still work
+        data = jws.deserialize(s, 'secret')
+        self.assertEqual(data['payload'], b'hello')
+        self.assertEqual(data['header']['alg'], 'HS256')
+"""

    def test_real_cve_2024_37568_diff_1_no_false_positives(self):
        """测试补丁 1（完整算法混淆回归测试）不应产生 API 契约误判。"""
        artifact = {
            "patch_type": "test",
            "target": "tests/jose/test_jws.py",
            "content": self.REAL_TEST_DIFF_1,
        }
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        self.assertEqual(
            issues, [],
            f"期望零误判，实际产生 {len(issues)} 个: {issues}"
        )

    def test_real_cve_2024_37568_diff_2_no_false_positives(self):
        """测试补丁 2（简化算法混淆回归测试）不应产生 API 契约误判。"""
        artifact = {
            "patch_type": "test",
            "target": "tests/jose/test_jws.py",
            "content": self.REAL_TEST_DIFF_2,
        }
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        self.assertEqual(
            issues, [],
            f"期望零误判，实际产生 {len(issues)} 个: {issues}"
        )

    def test_method_definition_not_flagged_as_call(self):
        """def test_xxx(self): 方法定义不应被识别为函数调用。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,5 @@
 old
+    def test_algorithm_confusion_prevention(self):
+        jws = JsonWebSignature(algorithms=['RS256'])
+        s = jws.serialize({}, 'hello', key_obj)
+        self.assertEqual(s, s)
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        # 不应把 def 行中的 test_algorithm_confusion_prevention 当成函数调用
        func_names = [i for i in issues if "test_algorithm_confusion_prevention" in i]
        self.assertEqual(func_names, [], f"方法定义被误判为函数调用: {func_names}")

    def test_docstring_content_not_flagged(self):
        """docstring 中的普通词汇不应被识别为函数调用。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,8 @@
 old
+    def test_confusion_fix(self):
+        \"\"\"Test algorithm confusion (alg=HS256) prevention.\"\"\"
+        jws = JsonWebSignature(algorithms=['RS256'])
+        s = jws.serialize({}, 'hello', key_obj)
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        # "confusion" 出现在 docstring 中，不应被误判
        confusion_issues = [i for i in issues if "confusion" in i]
        self.assertEqual(confusion_issues, [], f"docstring 词汇被误判: {confusion_issues}")

    def test_import_statement_not_flagged(self):
        """import 关键字不应被识别为函数调用。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,6 @@
 old
+        from authlib.common.encoding import (
+            urlsafe_b64decode, urlsafe_b64encode,
+        )
+        jws = JsonWebSignature(algorithms=['RS256'])
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        import_issues = [i for i in issues if "import" in i]
        self.assertEqual(import_issues, [], f"import 关键字被误判: {import_issues}")

    def test_local_variable_method_calls_not_flagged(self):
        """局部变量如 s.split() 不应被误判。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,6 @@
 old
+        s = jws.serialize({}, 'hello', key_obj)
+        parts = s.split('.')
+        header = json_loads(parts[0])
+        self.assertEqual(header, header)
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        # s.split() — s 是局部变量，不应因为 split 不在 API 表面而误判
        split_issues = [i for i in issues if "split" in i.lower()]
        self.assertEqual(split_issues, [], f"局部变量方法调用被误判: {split_issues}")

    def test_known_test_object_methods_not_flagged(self):
        """已知测试对象 (jws, data, header, payload) 的方法调用不应被误判。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,7 @@
 old
+        jws = JsonWebSignature(algorithms=['RS256'])
+        data = jws.deserialize(s, key_obj)
+        self.assertEqual(data['payload'], b'hello')
+        self.assertEqual(data['header']['alg'], 'RS256')
+        payload = data['payload']
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        self.assertEqual(issues, [], f"已知测试对象的方法被误判: {issues}")

    def test_truly_unknown_api_still_flagged(self):
        """真正不存在的 API 调用仍应被正确识别。"""
        diff = """--- a/tests/test_x.py
+++ b/tests/test_x.py
@@ -1 +1,4 @@
 old
+        jwk = jwk.generate_key('RSA', 2048)
+        token = jwt.encode(payload={}, algorithm='HS256')
"""
        artifact = {"patch_type": "test", "target": "tests/test_x.py", "content": diff}
        issues = PatchGenerationAgent._check_test_api_contract(
            artifact, self._SOURCE_FILES, self._AUTHLIB_API_SURFACE,
        )
        # jwk.generate_key 和 jwt.encode 在 authlib 1.3.0 中不存在 → 应被识别
        self.assertGreaterEqual(
            len(issues), 1,
            f"真正不存在的 API 未被识别: {issues}"
        )


if __name__ == "__main__":
    unittest.main()
