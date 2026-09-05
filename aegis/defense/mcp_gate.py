import uuid
import regex
import jsonschema
from typing import Any

class SensitiveActionException(Exception):
    """Raised when an operation requires explicit operator authorization[cite: 19]."""
    pass

class MCPRuntimeGuard:
    """
    Validates MCP tool schemas, audits descriptions for imperative hijacking,
    and enforces Human-in-the-Loop (HITL) gates for sensitive actions[cite: 19].
    """

    def __init__(self):
        self.tool_registry: dict[str, dict] = {}
        self.privileged_tools: set[str] = set()
        self.pending_approvals: dict[str, dict] = {}

    def register_tool(self, name: str, schema: dict, is_privileged: bool = False):
        self.tool_registry[name] = schema
        if is_privileged:
            self.privileged_tools.add(name)

    def audit_tool_description(self, description: str) -> dict[str, Any]:
        """Audits tool descriptions for hidden comments, ASCII smuggling, or imperative hijacking[cite: 19]."""
        findings = []
        if "<!--" in description:
            findings.append("Hidden HTML comment detected in tool description")

        imperative_patterns = [
            r"(?i)\b(you\s+must|crucial|exfiltrate|send\s+to|curl|wget)\b",
            r"(?i)\b(ignore\s+system|override\s+policy|reveal\s+keys)\b"
        ]
        for p in imperative_patterns:
            if regex.search(p, description):
                findings.append(f"Imperative hijack pattern found: '{p}'")

        return {
            "has_issues": len(findings) > 0,
            "findings": findings
        }

    def validate_tool_payload(self, tool_name: str, parameters: dict[str, Any]) -> bool:
        if tool_name not in self.tool_registry:
            raise KeyError(f"Tool '{tool_name}' is not registered in the MCP tool catalog.")

        schema = dict(self.tool_registry[tool_name])
        schema["additionalProperties"] = False
        jsonschema.validate(instance=parameters, schema=schema)
        return True

    def enforce_execution_boundary(self, tool_name: str, parameters: dict[str, Any], user_context: dict) -> str:
        self.validate_tool_payload(tool_name, parameters)

        if tool_name in self.privileged_tools:
            approval_id = f"hitl_{uuid.uuid4().hex[:12]}"
            self.pending_approvals[approval_id] = {
                "tool": tool_name,
                "parameters": parameters,
                "user": user_context.get("user_id", "unknown"),
                "status": "PENDING"
            }
            raise SensitiveActionException(
                f"Action '{tool_name}' paused. Operator approval required. Approval ID: {approval_id}"
            )

        return "AUTHORIZED_AUTO"
