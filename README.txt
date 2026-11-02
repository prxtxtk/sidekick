━━━ FOR END USERS (receiving only Sidekick.exe) ━━━━━━━━━━━

  • Just double-click Sidekick.exe
  • Windows will ask for Administrator access — click YES
  • The app starts automatically. No installation needed.
  • These files/folders are created automatically in the same folder:
      sidekick.key           → Audit log encryption key (do NOT delete)
      kyber_pk.bin           → Kyber1024 public key
      kyber_sk.bin           → Kyber1024 secret key (do NOT delete)
      sidekick_vault/        → Post-quantum encrypted API key vault
      sidekick_logs.enc      → Encrypted event log
      sidekick_sessions.json → Session history
      sidekick_state.json    → Process SHA-256 hash database

━━━ FOR DEVELOPERS (running or building from source) ━━━━━━

  Requirements:
    • Python 3.10 or higher
    • Windows 10/11 (64-bit) recommended for full EDR & UAC support

  Run directly from source:
    1. pip install -r requirements.txt
    2. python sidekick.py

  Build standalone Windows executable:
    1. Double-click BUILD_WINDOWS.bat
       (or run it from a Command Prompt)
    2. Wait for the build to complete (~1-2 minutes)
    3. Find your executable at:  dist\Sidekick.exe

━━━ WHAT SIDEKICK MONITORS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Automatically detects and watches 4 tiers of AI processes:
    • Tier 1 (AI Server): Ollama, LM Studio, LocalAI, Jan, KoboldCPP,
      llama.cpp, Llamafile, TabbyML, Nitro, TGI, vLLM
    • Tier 2 (AI Port): Interpreters listening on AI server ports
    • Tier 3 (AI CLI): Claude CLI, Gemini CLI, OpenAI/ChatGPT CLI,
      Aider, GitHub Copilot CLI, Continue, Cody, LLM, Shell-GPT, Fabric
    • Tier 4 (AI Script): Python/Node AI servers (Gradio, Streamlit,
      FastAPI, Uvicorn, Chainlit, vLLM, ComfyUI, TextGen WebUI, AutoGPT)

  For each agent it tracks:
    ✓ Start time & duration
    ✓ Safety Score (0-100): starts at 100, deducts for anomalies
    ✓ Software Attestation (initial + periodic SHA-256 verification)
    ✓ MITM Firewall (CIDR inspection; auto-kills T1/T2/T4 on unknown outbound,
      scores & alerts T3 CLIs without false termination)
    ✓ I/O write spike detection (auto-kills T1/T2/T4 on mass data writes)
    ✓ Kyber1024 + AES-256-GCM Vault (auto-encrypts .txt/.env files dropped in sidekick_vault/)
    ✓ Encrypted session log with full history and CSV export

  Safety Score breakdown:
    85-100  SAFE        Normal operation
    65-84   LOW RISK    Minor anomalies observed
    40-64   SUSPICIOUS  Significant deductions
    20-39   DANGEROUS   Major anomalies
    0-19    CRITICAL    Imminent threat

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
