import os
from datetime import datetime

class GhostMemory:
    def __init__(self, log_path="operations/ai_session.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self._last_user = None  # Store last user message

    def save(self, role, message):
        if role.lower() == "user":
            self._last_user = message
        elif role.lower() == "ghost" and self._last_user:
            self.save_interaction(self._last_user, message)
            self._last_user = None  # Reset after saving

    def save_interaction(self, user_input, ai_response):
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"User: {user_input}\n")
            f.write(f"Ghost: {ai_response}\n\n")

    def load_recent_history(self, limit=10):
        if not os.path.exists(self.log_path):
            return []

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Parse into structured turns
        turns = []
        current = {}
        for line in lines:
            if line.startswith("User:"):
                current["user"] = line.replace("User:", "").strip()
            elif line.startswith("Ghost:"):
                current["ghost"] = line.replace("Ghost:", "").strip()
                if "user" in current:
                    turns.append(current)
                current = {}
        turns = turns[-limit:]

        history = []
        for t in turns:
            history.append(f"User: {t['user']}")
            history.append(f"Ghost: {t['ghost']}")

        return history
