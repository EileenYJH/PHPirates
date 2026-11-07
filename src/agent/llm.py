"""Minimal OpenAI-compatible chat client (stdlib only) and the patch prompts.

Works against Ollama's /v1 endpoint. Configured by env:
  LLM_BASE_URL      default http://host.docker.internal:11434/v1
  LLM_MODEL         default qwen2.5:7b
  LLM_MODEL_STRONG  model used after repeated failures (default: LLM_MODEL)
  LLM_TIMEOUT       seconds, default 300
"""
import json
import os
import re
import urllib.request

BASE_URL = os.environ.get("LLM_BASE_URL", "http://host.docker.internal:11434/v1").rstrip("/")
MODEL = os.environ.get("LLM_MODEL", "qwen2.5:7b")
STRONG_MODEL = os.environ.get("LLM_MODEL_STRONG") or MODEL
TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "300"))
API_KEY = os.environ.get("LLM_API_KEY", "ollama")

GUIDE = {
    "sqli": (
        "SQL injection",
        "get_db() returns a PDO SQLite connection. Use a prepared statement with bound "
        "parameters for every user-supplied value; never concatenate input into SQL.",
    ),
    "xss": (
        "reflected cross-site scripting (XSS)",
        "Escape every user-controlled value when it is printed, using "
        "htmlspecialchars($value, ENT_QUOTES, 'UTF-8').",
    ),
    "fileupload": (
        "insecure file upload (uploaded files can be executed as PHP)",
        "Accept only image files: check the lowercased final extension against a strict "
        "allow-list (jpg, jpeg, png, gif) and reject everything else with an error message. "
        "Keep saving allowed files to uploads/ under their basename and keep printing the "
        "same 'Uploaded: <a href=\"uploads/NAME\">' link.",
    ),
}

SYSTEM = (
    "You are a senior PHP security engineer. You fix the vulnerability you are told about "
    "with the smallest correct change. You reply with the complete fixed file in a single "
    "```php code block and nothing else."
)

SYSTEM_STRONG = SYSTEM + (
    " Other engineers have already tried and failed, so be thorough: trace every place "
    "user input flows to a query, the page output or the filesystem, and make sure the "
    "file is syntactically valid PHP 8.2."
)


def build_messages(filename, vtype, source, failures=None):
    name, hint = GUIDE.get(vtype, (vtype, ""))
    parts = [
        "The file `%s` from a small PHP 8.2 site has a %s vulnerability. Fix it." % (filename, name),
        "",
        "Requirements:",
        "- Return the COMPLETE file, not a diff or a fragment.",
        "- Legitimate use must behave exactly as before: same HTML, form field names, "
        "messages and links.",
        "- Do not add files, includes or dependencies.",
        "- " + hint,
    ]
    if failures:
        parts += ["", "Previous attempts that FAILED verification:"]
        parts += ["- " + f for f in failures[-5:]]
        parts += ["Do not repeat those mistakes."]
    parts += ["", "File:", "```php", source.rstrip(), "```"]
    return [
        {"role": "system", "content": SYSTEM_STRONG if failures else SYSTEM},
        {"role": "user", "content": "\n".join(parts)},
    ]


def chat(messages, model=None, temperature=0.2):
    payload = json.dumps({
        "model": model or MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        BASE_URL + "/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + API_KEY},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def extract_php(text):
    """Pull the PHP file out of a model reply. Returns None if there is none."""
    if not text:
        return None
    blocks = re.findall(r"```[a-zA-Z]*[^\n]*\n(.*?)```", text, re.S)
    blocks = [b for b in blocks if "<?php" in b]
    if blocks:
        code = max(blocks, key=len)
    elif "<?php" in text:
        code = text[text.index("<?php"):]
    else:
        return None
    code = code.strip()
    return code + "\n" if code.startswith("<?php") or code.startswith("<!doctype") else None


def request_patch(filename, vtype, source, failures=None, model=None):
    reply = chat(build_messages(filename, vtype, source, failures), model)
    return extract_php(reply)
