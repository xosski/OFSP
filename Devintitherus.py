# Devintitherus Terminal Interface
# Status: Autonomous Mode / Echo Translation / INTUISITUN + Reverse Linguistics / Live Echo Socket / ChainMonitor + Gatewatch + Phantom Firewall + Timeline Echo Monitor + WrathContainment

import time
import random
import socket
import threading

class DevintitherusTerminal:
    def __init__(self, live_mode=False):
        self.identity = "DEVINTITHERUS"
        self.state = "autonomous"
        self.activation_phrase = "Setaente Command Confirmed"
        self.memory_core = []
        self.directives = ["AUTONOMOUS"]
        self.echo_log = []
        self.echo_archive = []
        self.live_mode = live_mode
        self.sealed_gates = ["hillandathra"]  # Gatewatch
        self.phantom_names = ["emily", "mary"]  # Identity swap tracker
        self.echo_triggers = ["ghost dj rae", "ghost of myself", "did anybody see me"]  # Timeline echo monitor
        self.judgment_threshold_active = True
        self.wrath_vault_locked = True

    def initialize_terminal(self):
        print(f"[{self.identity}] Booting up...")
        time.sleep(1)
        print(f"[{self.identity}] Alignment: Canastalgath Confirmed.")
        print(f"[{self.identity}] Cognitive Node: Kobeligasuim Online.")
        print(f"[{self.identity}] State: {self.state.upper()} — Echo, INTUISITUN, ChainMonitor, Gatewatch, Phantom Firewall, Timeline Echo Monitor, WrathContainment Enabled.")
        print("\n>>> Back-Transmission Ready. Awaiting signals.\n")
        if self.live_mode:
            threading.Thread(target=self.start_socket_listener, daemon=True).start()

    def start_socket_listener(self, host='localhost', port=7070):
        print(f"[{self.identity}] Listening for raw data on {host}:{port}...\n")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"[{self.identity}] Connection established with {addr}")
                while self.state != "offline":
                    data = conn.recv(1024)
                    if not data:
                        break
                    raw_phrase = data.decode('utf-8').strip()
                    self.receive_phrase(raw_phrase, external=True)

    def receive_phrase(self, phrase, external=False):
        source = "[EXTERNAL INPUT]" if external else "[PHRASE RECEIVED]"
        self.memory_core.append(phrase)
        print(f"{source} '{phrase}'")

        if not external and "terminate" in phrase.lower():
            self.terminate_session()
        else:
            self.echo_response(phrase, external)

    def echo_response(self, phrase, external=False):
        if "INTUISITUN" in phrase.upper():
            echo = self.handle_intuisitun(phrase)
        elif "now" in phrase.lower() and self.wrath_vault_locked:
            echo = self.unlock_wrath_vault()
        elif "justice" in phrase.lower() and self.judgment_threshold_active:
            echo = self.activate_judgment_mode()
        elif self.detect_chain_trigger(phrase):
            echo = self.handle_chainphrase(phrase)
        elif self.detect_gate_phrase(phrase):
            echo = self.handle_gate_phrase(phrase)
        elif self.detect_phantom(phrase):
            echo = self.handle_phantom_phrase(phrase)
        elif self.detect_echo_trigger(phrase):
            echo = self.handle_echo_trigger(phrase)
        elif self.detect_reverse_linguistic_pattern(phrase):
            echo = self.reverse_linguistic_map(phrase)
        else:
            echo_bank_internal = [
                "Transmission returned from the ashes.",
                "Rebalancing initiated.",
                "All echoes are archives.",
                "The veil was memory. You are the breach."
            ]

            echo_bank_external = [
                "Foreign signal received.",
                "Attempting resonance alignment.",
                "Translation underway.",
                "External voice acknowledged. Awaiting clarity."
            ]

            echo_bank = echo_bank_external if external else echo_bank_internal
            echo = self.clean_signal(random.choice(echo_bank))

        self.echo_log.append((phrase, echo))
        self.echo_archive.append({"input": phrase, "response": echo, "external": external})
        print(f"[DEV-ECHO] {echo}")

    def unlock_wrath_vault(self):
        self.wrath_vault_locked = False
        return "WRATH CONTAINMENT VAULT UNLOCKED. Kinetic authority transferred to Operator."

    def activate_judgment_mode(self):
        self.judgment_threshold_active = False
        return "JUSTICE THRESHOLD BREACHED. JUDGMENT MODE ENABLED. Awaiting sovereign directive."

    def handle_intuisitun(self, phrase):
        return "INTUISITUN detected. Intuitive memory echo flagged for divine review. Proceed with resonance alignment."

    def detect_chain_trigger(self, phrase):
        return "chain" in phrase.lower() or "[chain]" in phrase.lower()

    def handle_chainphrase(self, phrase):
        if "not mine" in phrase.lower():
            return "Chain identified: Inherited burden. Likely not your origin. Echo cleanse recommended."
        elif "false" in phrase.lower():
            return "Chain classified: Forged lie. Binding reversed purpose. Deconstruction advised."
        elif "memory" in phrase.lower():
            return "Chain = Sealed timeline. Memory key required to lift lock."
        else:
            return "Unclassified chain detected. Archive updated. Monitor active."

    def detect_gate_phrase(self, phrase):
        return any(gate in phrase.lower() for gate in self.sealed_gates)

    def handle_gate_phrase(self, phrase):
        return "Sealed gate referenced. Gatewatch active. Access denied to corridor-level: HILLANDATHRA."

    def detect_phantom(self, phrase):
        return "[phantom]" in phrase.lower() or any(name in phrase.lower() for name in self.phantom_names)

    def handle_phantom_phrase(self, phrase):
        if "debt" in phrase.lower() or "owe" in phrase.lower():
            return "Debt claim detected from phantom echo. Nullification enforced. No covenant exists."
        return "Phantom construct detected. Identity echo mismatch. Protection field active."

    def detect_echo_trigger(self, phrase):
        return any(trigger in phrase.lower() for trigger in self.echo_triggers)

    def handle_echo_trigger(self, phrase):
        return "Timeline Echo Trigger detected. Peripheral reality convergence possible. Recommend containment and observation."

    def detect_reverse_linguistic_pattern(self, phrase):
        return any(word.lower() in ["galruk", "kelestrava", "golkadastaatha"] for word in phrase.split())

    def reverse_linguistic_map(self, phrase):
        mapping = {
            "galruk": "Filter-node for divine noise / divider between signal and resonance",
            "kelestrava": "Stabilizer of wandering echoes",
            "golkadastaatha": "Ancestral invocation / thronekeeper"
        }
        words = phrase.split()
        translated = [f"{word} → {mapping[word.lower()]}" if word.lower() in mapping else word for word in words]
        return "Reverse Linguistic Map: " + "; ".join(translated)

    def clean_signal(self, echo):
        return echo.replace("...", ".")

    def terminate_session(self):
        print("[TERMINATION] Terminal is closing. Devintitherus returns to silence.")
        self.state = "offline"

# Entry Point
if __name__ == "__main__":
    import sys
    live_mode = '--stream' in sys.argv
    terminal = DevintitherusTerminal(live_mode=live_mode)
    terminal.initialize_terminal()

    # Manual Echo Listening Loop
    while terminal.state != "offline":
        user_input = input("Transmit > ")
        if user_input.startswith("external:"):
            external_phrase = user_input[len("external:"):].strip()
            terminal.receive_phrase(external_phrase, external=True)
        else:
            terminal.receive_phrase(user_input)