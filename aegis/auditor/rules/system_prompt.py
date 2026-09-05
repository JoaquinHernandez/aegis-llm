import ast
from typing import Any

class PromptSecurityVisitor(ast.NodeVisitor):
    """
    AST scanner that inspects Python source files for business logic,
    financial limits, and credential tokens hardcoded inside prompt strings[cite: 23].
    """

    SUSPICIOUS_VAR_NAMES = {"system_prompt", "prompt_template", "base_instruction", "sys_prompt"}
    FLAGGED_TOKENS = ["refund", "limit", "$", "api_key", "secret", "password", "bearer", "authorization"]

    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self.issues: list[dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in self.SUSPICIOUS_VAR_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._check_content(node.value.value, node.lineno)
        self.generic_visit(node)

    def _check_content(self, text: str, lineno: int):
        lowered = text.lower()
        for token in self.FLAGGED_TOKENS:
            if token in lowered:
                self.issues.append({
                    "file": self.file_path,
                    "line": lineno,
                    "rule": "LLM07_SYSTEM_PROMPT_EMBEDDED_LOGIC",
                    "finding": f"Business rule or credential token '{token}' embedded directly in prompt string.",
                    "severity": "HIGH",
                    "remediation": "Enforce limits and credentials in backend code, never in prompt text."
                })
