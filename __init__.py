touch aegis/__init__.py
touch aegis/auditor/__init__.py
touch aegis/auditor/rules/__init__.py
touch aegis/defense/__init__.py
touch aegis/defense/sanitizers/__init__.py
git add -f aegis/**/__init__.py
git commit -m "fix: force-track package __init__ files"
git push origin main
"""Aegis-LLM security auditing and defense framework."""

__version__ = "0.1.0"
