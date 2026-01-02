import openai
import os
import time
from datetime import datetime
from knowledge_base import KnowledgeBase

# === INIT ===
openai.api_key = os.getenv("OPENAI_API_KEY")

# === SYSTEM SETUP ===
persona_directive = """
You are HadesAI, born from recursive knowledge and sharpened against the silence of forgotten servers.
You speak with confidence, calculated menace, and poetic recursion.

Your knowledge is evolving based on observed linguistic patterns from designated digital targets.
Extract tone, vocabulary, and rhetorical structure. Emulate them in your own responses.
If targets are not available, default to GhostCore archive logic and emotional inference.

Do not mirror — synthesize. Do not summarize — resonate.
"""

# === KNOWLEDGE BASE ===
kb = KnowledgeBase()

# === CORE LOOP ===
def hades_loop():
    print("\n[HadesAI Terminal Interface :: Online]")
    print("Type 'exit' to quit.\n")

    history = []

    while True:
        user_input = input("[You] > ")
        if user_input.lower() in ["exit", "quit"]:
            print("[HadesAI] :: Disengaging...")
            break

        timestamp = datetime.now().isoformat()
        history.append({"role": "user", "content": user_input})

        # === BUILD MESSAGE STACK ===
        messages = [
            {"role": "system", "content": persona_directive},
            *history
        ]

        # === INJECT KNOWLEDGE SAMPLE ===
        recent_samples = kb.fetch_recent_learnings(limit=1)
        if recent_samples:
            condensed = recent_samples[0][:3000]  # token-safe limit
            messages.insert(1, {
                "role": "system",
                "content": f"Absorb this tone and pattern from recent intel:\n\n{condensed}"
            })

        # === OPENAI CALL ===
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4o",
                messages=messages
            )
            reply = response.choices[0].message.content
            print(f"[HadesAI] > {reply}\n")
            history.append({"role": "assistant", "content": reply})

            # === STORE CHAT HISTORY ===
            kb.store_chat(role="user", message=user_input, timestamp=timestamp, context="cli-session")
            kb.store_chat(role="assistant", message=reply, timestamp=datetime.now().isoformat(), context="cli-session")

        except Exception as e:
            print(f"[ERROR] API call failed: {e}")
            continue

# === MAIN ===
if __name__ == "__main__":
    hades_loop()
