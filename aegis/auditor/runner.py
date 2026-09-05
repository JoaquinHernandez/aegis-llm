import os
import ast
from aegis.auditor.rules.system_prompt import PromptSecurityVisitor

class CodeAuditor:
    """Scans Python files and directories for AI architectural anti-patterns[cite: 21]."""

    def __init__(self, target_path: str):
        self.target_path = target_path

    def run(self) -> list[dict]:
        findings = []
        if os.path.isfile(self.target_path):
            findings.extend(self._scan_file(self.target_path))
        else:
            for root, _, files in os.walk(self.target_path):
                for f in files:
                    if f.endswith(".py"):
                        full_path = os.path.join(root, f)
                        findings.extend(self._scan_file(full_path))
        return findings

    def _scan_file(self, file_path: str) -> list[dict]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as source_file:
                tree = ast.parse(source_file.read(), filename=file_path)
                visitor = PromptSecurityVisitor(file_path=file_path)
                visitor.visit(tree)
                findings.extend(visitor.issues)
        except Exception:
            pass
        return findings
