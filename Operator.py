# AI Operator Interface (Full Intelligence Layer with Planning Phase)
# Embedded logic for parsing, planning, and executing AI-driven red team commands
from mistral_runtime import ask_mistral
import re
import json
import time
from GhostMemory import GhostMemory
from mistral_runtime import ask_mistral
class Operator:
    def __init__(self):
        self.operation_state = {
            "mode": "offensive",
            "active_target": None,
            "last_command": None,
            "history": [],
            "planning_mode": True,
            "pending_confirmation": None,
            "active": True  # New flag to maintain operation
        }
        
    # Simulated system state (memory of context)
    operation_state = {
        "mode": "offensive",
        "active_target": None,
        "last_command": None,
        "history": [],
        "planning_mode": True,  # NEW: Toggle for planning phase
        "pending_confirmation": None
    }

    # Intent parser powered by AI (fallback to rules)
    def parse_intent(self, message):
        prompt = f"""
        You are an AI operations assistant for a red team operator. Interpret the following user message and return a JSON object with:
        - action (e.g., 'recon', 'attack', 'pause', 'defend', 'analyze')
        - target (IP, user, or 'none')
        - intent_description (summary of user goal)
        Message: "{message}"
        """
        response = ask_mistral(prompt, max_tokens=256)

        try:
            parsed = json.loads(response.strip())
        except:
            parsed = {
                "action": "unknown",
                "target": "none",
                "intent_description": response.strip()
            }
        return parsed

    # Generate AI-style replies
    def ai_reply(self, operator_message, parsed_intent):
        context = f"The operator said: '{operator_message}'\n"
        context += f"Parsed Action: {parsed_intent['action']}\nTarget: {parsed_intent['target']}\n"
        prompt = context + "\nGenerate a natural, tactical response in character as an intelligent assistant."
        return ask_mistral(prompt, max_tokens=128)

    # Plan phase: describe tactics before action
    def generate_plan(self, intent):
        action = intent['action']
        target = intent['target']
        desc = intent['intent_description']
        prompt = f"""
        You are an AI red team strategist. Based on the planned action '{action}' on target '{target}', describe a step-by-step plan for execution. Keep it short and clear.
        Also include what tools/modules might be used.
        Goal: {desc}
        """
        return ask_mistral(prompt, max_tokens=200)
    

    # Safe execution gateway
    def execute_intent(self, intent):
        action = intent["action"]
        target = intent["target"]
        self.operation_state["last_command"] = intent
        self.operation_state["history"].append((action, target, time.time()))

        if action == "recon":
            return f"🛰️ Launching reconnaissance on {target}..."
        elif action == "attack":
            return f"🚀 Executing attack sequence against {target}."
        elif action == "defend":
            self.operation_state["mode"] = "defensive"
            return "🛡️ Switched to defensive posture. Countermeasures active."
        elif action == "pause":
            self.operation_state["mode"] = "paused"
            return "⏸️ All operations paused. Awaiting further instructions."
        elif action == "analyze":
            return f"📊 Running vulnerability analysis on {target}..."
        else:
            return "🤔 I wasn't able to classify that command. Could you clarify?"

    async def handle_operator_input(self, message):
        parsed = self.parse_intent(message)
        reply = self.ai_reply(message, parsed)

        if self.operation_state["planning_mode"]:
            plan = self.generate_plan(parsed)
            reply += f"\n🧠 Tactical plan:\n{plan}\n\n✅ Type 'confirm' to execute or 'revise' to adjust."
            self.operation_state["pending_confirmation"] = parsed
        else:
            if parsed["action"] in ["attack", "pivot", "exfil"]:
                reply += "\n⚠️ This action requires confirmation. Type 'confirm' to proceed."
                self.operation_state["pending_confirmation"] = parsed
            else:
                result = await self.execute_intent(parsed)
                reply += "\n" + result

        return {"response": reply, "status": "active"}

    async def execute_intent(self, intent):
        action = intent["action"]
        target = intent["target"]
        self.operation_state["last_command"] = intent
        self.operation_state["history"].append((action, target, time.time()))

        # Keep operation running after execution
        self.operation_state["active"] = True
        return f"🚀 Executing {action} on {target}..."

    # Optional confirmation command processor
    async def handle_confirmation(self, input_text):
        if input_text.strip().lower() == "confirm" and self.operation_state["pending_confirmation"]:
            intent = self.operation_state["pending_confirmation"]
            result = self.execute_intent(intent)
            self.operation_state["pending_confirmation"] = None
            return f"✅ Confirmed.\n{result}"
        elif input_text.strip().lower() == "revise":
            self.operation_state["pending_confirmation"] = None
            return "✏️ Awaiting revised instructions."
        else:
            return None

# Update the test run section
if __name__ == "__main__":
    import asyncio

    operator = Operator()

    print("🔧 AI Red Team Operator Online. Type your commands. Type 'exit' to quit.\n")
    
    while operator.operation_state["active"]:
        user_input = input("🧑‍💻 >>> ")
        
        if user_input.strip().lower() in ["exit", "quit"]:
            print("👋 Shutting down operator interface.")
            break
        
        # Handle confirmation if pending
        if operator.operation_state["pending_confirmation"]:
            confirmation_response = asyncio.run(operator.handle_confirmation(user_input))
            if confirmation_response:
                print(confirmation_response)
                continue

        # Handle normal input
        result = asyncio.run(operator.handle_operator_input(user_input))
        print(result["response"])

