# Craft Engine - Project Governance & Scaling Roadmap

## 1. Security & Secrets Management
- **Environment Isolation:** `.env` files must NEVER be committed. Use a Secrets Manager (AWS/HashiCorp) for production keys.
- **Admin Access:** Access to the `PasskeyVault` master key is restricted to the Project Owner.
- **Key Derivation:** The PBKDF2 iteration count (600,000) is a mandatory security floor and must not be lowered for "speed."

## 2. Capability Tiers (Roadmap)
### Free Tier (Community)
- Standard Brotli/Zstd compression.
- Manual integrity verification.
- Buffer-limited file handling (up to 200MB).

### Premium/Pro Tier
- Custom `craft-codec` (Strategy 12) access.
- Constant-memory v4 Streaming for large-scale data.
- Automated `craft watch` with email/webhook notifications.

### Enterprise/Government Tier
- Hardware Security Module (HSM) integration.
- Deterministic, Reproducible build audits.
- Signed Audit Logging for every archival transaction.

## 3. Future Expansion
- **Plugin Architecture:** New compression strategies will be developed in separate, private repositories and linked as optional modules.
- **Multi-Cloud Vaulting:** Support for distributing encrypted chunks across different cloud providers to prevent provider-lock-in and enhance durability.
