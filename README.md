# aegis-llm
# 🛡️ Aegis-LLM: AI Security Auditing & Defense Suite

A practical security framework to audit AI application source code, stop prompt injections, and enforce Model Context Protocol (MCP) tool guardrails[cite: 14]. Built for the **OWASP Top 10 for LLM Applications (2025)**[cite: 14].

---

## 💡 What Aegis Does

1. **Static AST Code Auditor (`aegis audit <path>`)**: Scans Python files to detect sensitive business logic, pricing tiers, and API keys placed in prompt strings[cite: 14].
2. **Deterministic Input Sanitizer**: Neutralizes zero-width Unicode characters, ANSI tags, and hidden HTML comments used to smuggle injection attacks[cite: 14].
3. **Fail-Closed LLM Judge**: A secondary verification layer that evaluates untrusted prompts and fails closed (blocks execution) if an error occurs[cite: 14, 20].
4. **MCP Tool Guardrails (`aegis mcp-inspect "<description>"`)**: Verifies tool schema contracts and halts destructive actions for human approval[cite: 14, 19].

---

## 🎯 OWASP Top 10 for LLM Applications (2025) Coverage

| OWASP ID | Vulnerability | Aegis Module | Protection Mechanism |
|:---|:---|:---|:---|
| **LLM01** | Prompt Injection | `aegis.defense.sanitizers` | NFKC normalization and invisible zero-width stripping[cite: 14]. |
| **LLM02** | Sensitive Info Disclosure | `aegis.defense.judge` | Pattern scanning and output inspection[cite: 14]. |
| **LLM03** | Supply Chain Vulnerabilities | `aegis.defense.mcp_gate` | Strict JSON schema contract validation (`additionalProperties: false`)[cite: 14, 19]. |
| **LLM04** | Data & Model Poisoning | `aegis.defense.sanitizers` | RAG ingestion cleansing and hidden comment removal[cite: 14, 22]. |
| **LLM05** | Improper Output Handling | `aegis.defense.judge` | Blocks shell execution and unverified SQL queries[cite: 14]. |
| **LLM06** | Excessive Agency | `aegis.defense.mcp_gate` | Human-in-the-Loop (HITL) execution interceptor[cite: 14, 19]. |
| **LLM07** | System Prompt Leakage | `aegis.auditor.rules` | AST scanner flags sensitive parameters in prompt definitions[cite: 14, 23]. |
| **LLM08** | Vector Weaknesses | `aegis.defense.sanitizers` | Bounded token lengths and context envelope fencing[cite: 14]. |
| **LLM09** | Misinformation | `aegis.defense.judge` | Intent validation and attribution checks[cite: 14]. |
| **LLM10** | Unbounded Consumption | `aegis.defense.sanitizers` | Payload truncation to prevent denial of service. |

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone [https://github.com/](https://github.com/)<your-username>/aegis-llm.git
cd aegis-llm
pip install -e .
