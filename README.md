# 🛡️ Hemdall — The AI Security Framework for LLM Applications

**Hemdall** is an open-source, local-first security framework designed to **detect, prevent, and mitigate prompt-based threats** to AI and LLM applications.

Named after the mythological guardian Heimdallr, Hemdall watches over your AI stack—securing interfaces, shielding internal logic, and enforcing safety policies without relying on cloud services or external dependencies.

---

## 🚀 How It Works

Hemdall acts as a pluggable middleware layer or integrated module within your AI pipeline (e.g., FastAPI, LangChain, or Ollama), inspecting every interaction between your app and local or remote LLMs. It applies **rule-based** and **behavioral** policies to detect:

- Prompt Injection
- Jailbreak Attempts
- Prompt Leakage
- Unsafe or Non-Compliant Outputs

All processing is done **locally**, ensuring your sensitive data stays private and protected.

---

## ✅ Why Choose Hemdall?

### 🧱 Defend Against Prompt-Based Attacks
Leverage real-time detection and sanitization of malicious prompts that attempt to override system instructions, exfiltrate data, or bypass safeguards.

### 🔒 Ensure Data Privacy & Local Integrity
Built with a local-first philosophy. No cloud APIs, no external telemetry. Hemdall runs 100% in your infrastructure—ideal for air-gapped or security-sensitive deployments.

### 🧠 Prevent Prompt Leakage
Block attempts to extract system prompts, internal business logic, or credentials from your LLM stack.

### ⚙️ Pluggable & Extensible Architecture
Integrate Hemdall into your existing LLM stack with minimal changes. Easily extend it with custom detectors, sanitizers, or policies to fit your specific use case.

### 📜 Detailed Logging & Forensics
Get structured logs of blocked requests, attack attempts, and policy matches. Perfect for auditing and compliance.

### ⚡ Lightweight & High-Performance
Written in clean, idiomatic Python with no unnecessary dependencies. Designed for fast inference with minimal overhead.

---

## 🔧 Core Features

- 🔍 Input Sanitization & Filtering  
  Pre-process prompts using heuristics and regex-based detectors.

- 🧠 Behavioral Analysis  
  Detect jailbreaks and malicious intent using known patterns and NLP-based intent matching.

- 🛡️ Prompt Leakage Prevention  
  Actively protect internal instructions and credentials from user-facing exposure.

- 🧰 Pluggable Policy System  
  Customize and extend policies to meet domain-specific requirements.

- ⚙️ Integration Ready  
  Works with LangChain, FastAPI, Ollama, or your custom stack.

- 📜 Policy Configuration  
  Adjustable via UI or YAML config files.

---

## 🧠 Use Cases

### 🤖 Public-Facing Chatbots
Prevent users from injecting harmful instructions, leaking sensitive data, or triggering inappropriate LLM outputs.

### 🏢 Internal AI Assistants
Block accidental exposure of API keys, project names, or proprietary logic within internal tooling.

### 🏥 Regulated Industries (HIPAA, GDPR)
Implement structured policies for PII redaction, data handling, and compliance logging.

### 📝 Content Generation Platforms
Enforce strict filters against offensive or off-brand language. Maintain safety while enabling creativity.

