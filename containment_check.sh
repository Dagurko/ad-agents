#!/bin/sh
# Evidence for the containment section (option 2: native Ollama on loopback, text-only agents).
# Run from ad-agents/: ./containment_check.sh | tee logs/containment_$(date +%Y%m%d).txt
cd "$(dirname "$0")"
echo "== $(date) =="
echo "\n-- 1. Ollama listening sockets (expect 127.0.0.1 only) --"
lsof -nP -iTCP:11434 -sTCP:LISTEN
echo "\n-- 2. Ollama unreachable from the LAN address (expect failure) --"
LAN=$(ipconfig getifaddr en0)
curl -s -m 3 "http://$LAN:11434/api/version" && echo "REACHABLE (BAD)" || echo "unreachable via $LAN (OK)"
echo "\n-- 3. Every network call in the code (expect only the Ollama URL in llm.py) --"
grep -rnE "requests\.|urllib|http\.client|socket|subprocess|os\.system|eval\(|exec\(" src/ || echo "none"
echo "\n-- 4. OLLAMA_URL default --"
grep -n "OLLAMA_URL" src/llm.py
