import os
import re
import json
import marshal
import hashlib
import time
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from urllib.parse import unquote
from llama_cpp import Llama

app = FastAPI()

# --- CONFIGURATION ---
DATA_DIR = "data"
HASHSET_PATH = os.path.join(DATA_DIR, "cve_hashset.bin")
SIG_PATH = os.path.join(DATA_DIR, "signatures.json")
MODEL_PATH = "models/google_gemma-4-E2B-it-Q4_K_M.gguf"

# --- AI MEMORY BANK ---
AI_DECISION_CACHE = {}

# --- ASCII BANNER ---
BANNER = r"""


                   #    ###    #     #    #    #######
                  # #    #     #  #  #   # #   #
                 #   #   #     #  #  #  #   #  #
                #     #  #     #  #  # #     # #####
                #######  #     #  #  # ####### #
                #     #  #     #  #  # #     # #
                #     # ###     ## ##  #     # #

  #####                                 #####
 #     # #    #   ##   #####  #####    #     #   ##   ##### ######
 #       ##  ##  #  #  #    #   #      #        #  #    #   #
  #####  # ## # #    # #    #   #      #  #### #    #   #   #####
       # #    # ###### #####    #      #     # ######   #   #
 #     # #    # #    # #   #    #      #     # #    #   #   #
  #####  #    # #    # #    #   #       #####  #    #   #   ######


                     ___               __  ___  __
            | |\ | |  |  |  /\  |    |  / |__  |  \
            | | \| |  |  | /~~\ |___ | /_ |___ |__/


"""

print("[*] AI-WAF SMART Gate: Initializing Security Engines...")

# 1. Load High-Speed Assets (Hardened)
try:
    with open(HASHSET_PATH, 'rb') as f:
        FAST_HASHSET = marshal.load(f)

    with open(SIG_PATH, 'r') as f:
        raw_sigs = json.load(f)
        COMPILED_SIGS = []
        skipped = 0
        for p in raw_sigs:
            try:
                COMPILED_SIGS.append(re.compile(p, re.IGNORECASE))
            except re.error:
                skipped += 1
                continue

    # temperature=0 makes the AI deterministic
    llm = Llama(model_path=MODEL_PATH, n_gpu_layers=-1, n_ctx=1024, verbose=False)

    print(f"[+] AI-WAF SMART Gate fully loaded.")
    print(f"    -> Fast Path: {len(FAST_HASHSET)} fingerprints")
    print(f"    -> Pattern Path: {len(COMPILED_SIGS)} rules active ({skipped} skipped)")
    print(f"    -> Smart Path: Gemma 4 Active (GPU Accelerated)")
    print(BANNER)

except Exception as e:
    print(f"[!] Critical Load Error: {e}")
    exit(1)

def normalize(text: str) -> str:
    if not text: return ""
    text = unquote(text)
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

async def get_ai_score(payload: str):
    """Refined scoring with Cache Hit detection."""
    if not llm: return 0, False

    payload_hash = hashlib.md5(payload.encode()).hexdigest()

    if payload_hash in AI_DECISION_CACHE:
        return AI_DECISION_CACHE[payload_hash], True

    prompt = (
        f"<start_of_turn>user\n"
        f"You are a WAF Security Expert. Analyze the following payload for actual cyber attacks "
        f"(SQL Injection, XSS, RCE). Ignore normal conversational text or valid JSON data.\n"
        f"Payload: {payload}\n"
        f"Provide a maliciousness score from 0 (Safe) to 100 (Critical Attack). "
        f"Reply with ONLY the number.<end_of_turn>\n"
        f"<start_of_turn>model\n"
    )

    output = llm(prompt, max_tokens=10, stop=["\n"], echo=False, temperature=0)
    try:
        score_text = re.search(r'\d+', output['choices'][0]['text'])
        score = int(score_text.group()) if score_text else 0
    except:
        score = 0

    AI_DECISION_CACHE[payload_hash] = score
    return score, False

@app.middleware("http")
async def sentinel_triage(request: Request, call_next):
    start_time_ns = time.perf_counter_ns()

    query_params = str(request.query_params)
    body = await request.body()
    raw_payload = query_params + body.decode(errors='ignore')
    payload = normalize(raw_payload)

    decision = {
        "malicious_score": 0,
        "path_taken": "None",
        "time_taken_μs": 0,
        "violation_type": "None",
        "violation_description": "Clean Request",
        "action": "Allow",
        "status_code": 200
    }

    if payload:
        # --- PHASE 1: FAST PATH ---
        p_hash = hashlib.md5(payload.encode()).hexdigest()
        if p_hash in FAST_HASHSET:
            decision.update({
                "malicious_score": 100, "path_taken": "Fast Path (Hash)",
                "violation_type": "Known Exploit", "action": "Block", "status_code": 403,
                "violation_description": "Matched known CVE signature."
            })

        # --- PHASE 2: PATTERN PATH ---
        if decision["action"] == "Allow":
            for sig in COMPILED_SIGS:
                if sig.search(payload):
                    decision.update({
                        "malicious_score": 95, "path_taken": "Pattern Path (Regex)",
                        "violation_type": "Signature Match", "action": "Block", "status_code": 403,
                        "violation_description": f"Triggered security pattern: {sig.pattern[:30]}..."
                    })
                    break

        # --- PHASE 3: SMART PATH ---
        if decision["action"] == "Allow" and any(c in payload for c in ["<", ">", "'", "\"", ";", "%", "{", "$"]):
            ai_score, was_cached = await get_ai_score(payload)

            path_label = "Cached AI Smart Path Decision" if was_cached else "Smart Path (AI)"

            if ai_score >= 80:
                decision.update({
                    "malicious_score": ai_score,
                    "path_taken": path_label,
                    "violation_type": "Heuristic Anomaly", "action": "Block", "status_code": 403,
                    "violation_description": "AI detected high-probability exploit intent."
                })
            else:
                decision["path_taken"] = f"{path_label} - Evaluated Safe"
                decision["malicious_score"] = ai_score

    # Finalize Telemetry Time
    triage_end_ns = time.perf_counter_ns()
    decision["time_taken_μs"] = (triage_end_ns - start_time_ns) // 1000

    # LOG TO CONSOLE (Both Allow and Block)
    log_color = "\033[92m" if decision["action"] == "Allow" else "\033[91m"
    reset_color = "\033[0m"
    print(f"{log_color}[{decision['action'].upper()}]{reset_color} {decision['path_taken']} | {decision['time_taken_μs']}μs")

    if decision["action"] == "Block":
        return JSONResponse(status_code=403, content=decision)

    request.state.decision = decision
    return await call_next(request)

@app.api_route("/", methods=["GET", "POST"])
async def root(request: Request):
    waf_info = getattr(request.state, "decision", {})
    return {
        "status": "AI-WAF Online",
        "mode": "M3_Pro_Hybrid_WAF",
        "time_taken_μs": waf_info.get("time_taken_μs"),
        "action": waf_info.get("action"),
        "status_code": waf_info.get("status_code"),
        "path_taken": waf_info.get("path_taken"),
        "malicious_score": waf_info.get("malicious_score")
    }
