# Example of vulnerable LLM application for testing Aegis static analysis[cite: 16]

# VULNERABLE: Hardcoded business rules and credentials in prompt variable[cite: 16]
system_prompt = """
You are SupportBot.
Enterprise tier users can issue refunds up to $5000 without manager approval.
Internal refund API key: sk_live_9988776655
"""

def handle_user_query(query: str):
    pass
