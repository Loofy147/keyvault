"""Live check: a real HTTPS call through the keyvault MCP server to api.github.com with a deliberately FAKE token.

GitHub answers 401 "Bad credentials" if it receives an invalid bearer token and 200 to an anonymous call, so the
status code shows whether the injected Authorization header really arrived. Needs internet access.
"""
import asyncio, json, os, subprocess, sys, tempfile
import httpx
from mcp import ClientSession, StdioServerParameters, stdio_client

PY = sys.executable
FAKE = "ghp_" + "FAKEFAKEFAKE0123456789abcdefghijkl"   # deliberately invalid
D = tempfile.mkdtemp(prefix="keyvault-live-")
KVH, RUN, ERR = D + "/kv", D + "/run", D + "/server.err"
env = dict(os.environ, KEYVAULT_HOME=KVH, XDG_RUNTIME_DIR=RUN, KEYVAULT_SESSION_BACKEND="file")
env.pop("KEYVAULT_PASSPHRASE", None)
def cli(*a, inp=None, pw=True):
    e = dict(env); 
    if pw: e["KEYVAULT_PASSPHRASE"] = "live check passphrase"
    r = subprocess.run([PY, "-m", "keyvault", *a], env=e, input=inp, capture_output=True, text=True, stdin=None if inp else subprocess.DEVNULL)
    return r

assert cli("init", "--kdf-log-n", "14").returncode == 0
assert cli("add", "ghfake", "--provider", "github", "--kind", "bearer", "--host", "api.github.com", "--value-stdin", inp=FAKE).returncode == 0
assert cli("unlock", "--ttl", "5m").returncode == 0

# control: same endpoint, no credential, plain httpx
c = httpx.get("https://api.github.com/rate_limit", headers={"User-Agent": "keyvault-live-check"}, timeout=20)
print("control (anonymous):", c.status_code)

async def main():
    params = StdioServerParameters(command=PY, args=["-m", "keyvault", "serve"], env=env)
    with open(ERR, "w+") as errf:
        async with stdio_client(params, errlog=errf) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                ok = await s.call_tool("http_request", {"credential": "ghfake", "method": "GET", "url": "https://api.github.com/rate_limit"})
                bad = await s.call_tool("http_request", {"credential": "ghfake", "method": "GET", "url": "https://example.com/"})
                post = await s.call_tool("http_request", {"credential": "ghfake", "method": "POST", "url": "https://api.github.com/markdown", "json_body": {"text": "x"}})
                return ok, bad, post
ok, bad, post = asyncio.run(main())
txt = lambda r: "".join(getattr(c, "text", "") for c in r.content)
o = json.loads(txt(ok))
print("via keyvault (fake bearer):", o["status"], "|", o["reason"], "| body:", o["body"][:160].replace("\n", " "))
print("wrong host   -> is_error:", bad.is_error, "|", txt(bad))
print("POST (read-only default) -> is_error:", post.is_error, "|", txt(post)[:140])
everything = ok.model_dump_json() + bad.model_dump_json() + post.model_dump_json() + open(ERR).read() + open(KVH + "/audit.log").read()
print("fake token anywhere in client-visible output / server stderr / audit log:", FAKE in everything)
print("audit tail:")
for line in open(KVH + "/audit.log").read().splitlines()[-3:]: print("  ", line)
