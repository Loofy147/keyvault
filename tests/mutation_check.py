"""Break security-critical behaviours on purpose (in a temp copy) and confirm the tests fail.

Usage: python tests/mutation_check.py   (needs pytest in the same environment)
"""
import os, shutil, subprocess, sys, tempfile

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
TMP = tempfile.mkdtemp(prefix="keyvault-mut-")
MUT = os.path.join(TMP, "work")
EXPECTED_SURVIVORS = {"parser-agreement check removed (defense in depth)"}  # no known input exercises it

M = [
 ("truncation: no read-ahead / tail trim", "keyvault/proxy.py",
  "read_limit = max_bytes + pad", "read_limit = max_bytes",
  ["tests/test_keyvault.py", "-k", "truncation"]),
 ("truncation: keep tail where partial secret sits", "keyvault/proxy.py",
  "cut = max(0, len(b) - pad) if hit_limit else len(b)", "cut = len(b)",
  ["tests/test_keyvault.py", "-k", "truncation"]),
 ("proxy follows redirects", "keyvault/proxy.py",
  "follow_redirects=False", "follow_redirects=True",
  "tests/test_keyvault.py::test_redirect_not_followed"),
 ("host allowlist always true", "keyvault/vault.py",
  "    host = host.lower().rstrip(\".\")\n    if pattern.startswith", "    return True\n    host = host.lower().rstrip(\".\")\n    if pattern.startswith",
  "tests/test_keyvault.py::test_denied_urls_never_reach_the_network"),
 ("wildcard also matches apex/look-alikes", "keyvault/vault.py",
  "return host.endswith(suffix) and len(host) > len(suffix)", "return host.endswith(suffix.lstrip('.'))",
  "tests/test_keyvault.py::test_host_matching"),
 ("caller may override managed headers", "keyvault/proxy.py",
  "if lk in FORBIDDEN_REQUEST_HEADERS or lk == managed:", "if False:",
  "tests/test_keyvault.py::test_policy_rules"),
 ("response body not redacted", "keyvault/proxy.py",
  "text, n = redact(raw.decode(\"utf-8\", \"replace\"), cred, variants)", "text, n = raw.decode(\"utf-8\", \"replace\"), 0",
  "tests/test_keyvault.py::test_injection_all_kinds_and_redaction"),
 ("response headers not redacted", "keyvault/proxy.py",
  "out_headers[lk], n = redact(v, cred, variants)", "out_headers[lk], n = v, 0",
  "tests/test_keyvault.py::test_binary_omitted_and_response_headers_filtered"),
 ("all response headers passed through", "keyvault/proxy.py",
  "if lk in KEEP_HEADERS or lk.startswith(KEEP_PREFIXES):", "if True:",
  "tests/test_keyvault.py::test_binary_omitted_and_response_headers_filtered"),
 ("KDF header not bound as AAD", "keyvault/vault.py",
  "return json.dumps({\"v\": env[\"v\"], \"kdf\": env[\"kdf\"]}, sort_keys=True, separators=(\",\", \":\")).encode()",
  "return b\"\"",
  "tests/test_keyvault.py::test_wrong_passphrase_and_tamper"),
 ("KDF cost cap removed", "keyvault/vault.py",
  "if not (MIN_LOG_N <= n <= MAX_LOG_N and 1 <= r <= 16 and 1 <= p <= 4):", "if False:",
  "tests/test_keyvault.py::test_wrong_passphrase_and_tamper"),
 ("session never expires", "keyvault/vault.py",
  "if expires <= time.time():", "if False:",
  "tests/test_keyvault.py::test_session_unlock_sources_and_expiry"),
 ("old-key backup kept after passwd", "keyvault/vault.py",
  "self.path.with_name(self.path.name + \".bak\").unlink(missing_ok=True)", "pass",
  "tests/test_keyvault.py::test_session_unlock_sources_and_expiry"),
 ("master passphrase leaked to child env", "keyvault/cli.py",
  "env.pop(\"KEYVAULT_PASSPHRASE\", None)  # never hand the master passphrase to the child", "pass",
  "tests/test_keyvault.py::test_cli_flow"),
 ("env-only creds visible to agents", "keyvault/mcp_server.py",
  "if c.kind != \"none\" and (allow is None or n in allow)", "if (allow is None or n in allow)",
  "tests/test_keyvault.py::test_mcp_end_to_end"),
 ("allow scope ignored", "keyvault/mcp_server.py",
  "if c.kind != \"none\" and (allow is None or n in allow)", "if c.kind != \"none\"",
  "tests/test_keyvault.py::test_mcp_end_to_end"),
 ("notes/env var exposed to agents", "keyvault/vault.py",
  "\"tags\": list(self.tags),\n        }", "\"tags\": list(self.tags), \"notes\": self.notes, \"env_var\": self.env_var,\n        }",
  "tests/test_keyvault.py::test_agent_view_hides_private_fields"),
 ("lock does not cut off running server", "keyvault/vault.py",
  "if self.source == \"session\":", "if False:",
  "tests/test_keyvault.py::test_mcp_end_to_end"),
 ("audit log leaks full URL incl. credential query param", "keyvault/proxy.py",
  '\"host\": plan[\"host\"], \"path\": plan[\"path\"], \"query_keys\": plan[\"query_keys\"], \"status\": status,',
  '\"host\": plan[\"host\"], \"path\": plan[\"path\"], \"query_keys\": plan[\"query_keys\"], \"status\": status, \"url\": plan[\"url\"],',
  "tests/test_keyvault.py::test_audit_log_records_without_secrets"),
 ("plain http allowed to any host", "keyvault/proxy.py",
  'if scheme == \"http\" and not loopback_ok:', "if False:",
  "tests/test_keyvault.py::test_denied_urls_never_reach_the_network"),
 ("URL userinfo allowed", "keyvault/proxy.py",
  'if \"@\" in parts.netloc:', "if False:",
  "tests/test_keyvault.py::test_denied_urls_never_reach_the_network"),
 ("parser-agreement check removed (defense in depth)", "keyvault/proxy.py",
  'if (httpx.URL(url).host or \"\").lower().rstrip(".") != host:', "if False:",
  "tests/test_keyvault.py::test_denied_urls_never_reach_the_network"),
 ("methods default to all (not read-only)", "keyvault/vault.py",
  'methods: list = field(default_factory=lambda: [\"GET\", \"HEAD\"])',
  'methods: list = field(default_factory=lambda: [\"GET\", \"HEAD\", \"POST\", \"PUT\", \"PATCH\", \"DELETE\"])',
  "tests/test_keyvault.py::test_policy_rules"),
 ("vault file written world-readable", "keyvault/vault.py",
  "        if backup and path.exists():", "        os.chmod(tmp, 0o644)\n        if backup and path.exists():",
  "tests/test_keyvault.py::test_file_properties"),
 ("session accepted after vault re-key", "keyvault/vault.py",
  'if salt != read_envelope(vpath)[\"kdf\"][\"salt\"]:  # vault re-keyed or replaced', "if False:",
  "tests/test_keyvault.py::test_session_unlock_sources_and_expiry"),
 ("get not audited", "keyvault/cli.py",
  '    V.audit({\"actor\": \"cli\", \"action\": \"get\", \"credential\": a.name})\n    print(c.value)', "    print(c.value)",
  "tests/test_keyvault.py::test_cli_flow"),
]

def fresh():
    if os.path.exists(MUT): shutil.rmtree(MUT)
    shutil.copytree(SRC, MUT, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.egg-info"))

fresh()
env = dict(os.environ, PYTHONPATH=MUT)
print("imports from:", subprocess.run([PY, "-c", "import keyvault;print(keyvault.__file__)"], env=env, capture_output=True, text=True, cwd=TMP).stdout.strip())

survived = []
for label, rel, old, new, sel in M:
    fresh()
    p = os.path.join(MUT, rel)
    s = open(p).read()
    if s.count(old) != 1:
        print(f"!! cannot apply (found {s.count(old)}x): {label}"); survived.append((label, "NOT APPLIED")); continue
    open(p, "w").write(s.replace(old, new))
    sel_args = sel if isinstance(sel, list) else [sel]
    r = subprocess.run([PY, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *sel_args], env=env, cwd=MUT, capture_output=True, text=True)
    killed = r.returncode != 0
    tail = [l for l in r.stdout.splitlines() if l.startswith(("FAILED", "ERROR")) or " passed" in l or " failed" in l][-2:]
    print(("KILLED  " if killed else "SURVIVED") + " | " + label + " | " + (tail[-1] if tail else ""))
    if not killed: survived.append((label, "tests still pass"))
print()
print(f"{len(M) - len(survived)}/{len(M)} mutations caught")
for l, why in survived: print("  not caught:", l, "-", why)
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0 if {l for l, _ in survived} <= EXPECTED_SURVIVORS else 1)
