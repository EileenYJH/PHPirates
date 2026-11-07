"""Build step 1: prove Ollama answers and returns a patched PHP file.

Run on the host (stdlib only):
    python scripts/check_ollama.py
    python scripts/check_ollama.py --model qwen2.5:7b --file src/target/site/public/search.php --type xss
"""
import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("LLM_BASE_URL", "http://localhost:11434/v1")
sys.path.insert(0, os.path.join(ROOT, "src", "agent"))
sys.dont_write_bytecode = True
import llm  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--file", default=os.path.join(ROOT, "src", "target", "site", "public", "login.php"))
ap.add_argument("--type", default="sqli", choices=sorted(llm.GUIDE))
ap.add_argument("--model", default=llm.MODEL)
a = ap.parse_args()

with open(a.file, encoding="utf-8") as f:
    source = f.read()
print("Asking %s at %s to fix %s (%s)..." % (a.model, llm.BASE_URL, os.path.basename(a.file), a.type))
start = time.time()
try:
    patched = llm.request_patch(os.path.basename(a.file), a.type, source, model=a.model)
except Exception as e:
    sys.exit("FAILED: could not reach the model: %s" % e)
print("Reply in %.1fs\n" % (time.time() - start))
if not patched:
    sys.exit("FAILED: the reply contained no PHP file")
print(patched)
hints = {"sqli": "prepare(", "xss": "htmlspecialchars($q", "fileupload": "in_array("}
print("--- looks like a %s fix: %s" % (a.type, "yes" if hints[a.type] in patched else "check by eye"))
