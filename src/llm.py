import os, requests

URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
last_meta = {}   # done_reason / eval_count of the most recent call


def chat(model, messages, temperature=0.7, seed=None, json_mode=False, max_tokens=None):
    body = {"model": model, "messages": messages, "stream": False,
            "options": {"temperature": temperature}}
    if max_tokens is not None:
        body["options"]["num_predict"] = max_tokens
    if seed is not None:
        body["options"]["seed"] = seed
    if json_mode:
        body["format"] = "json"
    r = requests.post(f"{URL}/api/chat", json=body, timeout=300)
    r.raise_for_status()
    data = r.json()
    last_meta.clear()
    last_meta.update(done_reason=data.get("done_reason"), eval_count=data.get("eval_count"),
                     prompt_eval_count=data.get("prompt_eval_count"))
    return data["message"]["content"]
