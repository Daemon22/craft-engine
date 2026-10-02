# Craft Engine - Business Expansion & Stakeholder Strategy

This document outlines the roadmap for transitioning from an open-core engine to a tiered, commercially viable platform suitable for high-stakes partnerships.

## 1. Stakeholder Engagement Models

### Government & Intelligence
*   **Trust Model:** "White-Box" audit access. Provide source-level visibility for security review while maintaining proprietary rights.
*   **Compliance:** Map integrity pillars (A-F) to specific standards (e.g., FIPS 140-2, NIST 800-53).
*   **Air-Gapped Deployment:** Optimize the CLI for environments with zero internet access, using offline "Doctor" verification.
*   **Auditability:** Every archival action creates a SHA-256 signed audit trail to prove non-repudiation.

### Entrepreneurs & Startups
*   **The "Dev-First" SDK:** Provide the `easy.ts` facade as a primary selling point. 
*   **Platform-as-a-Service (PaaS):** Offer the Next.js API routes as a managed service where you host the heavy PBKDF2 compute, selling "Craft Credits."
*   **Custom Strategy Plugins:** Allow entrepreneurs to write their own `Pre-Processor` folds (Fold 8, Fold 9) for niche data types (e.g., specialized medical or financial data).

## 2. Monetization & Tiering (Temporal Capabilities)

### Temporal (Time-Limited) Features
*   **Self-Destructing Packages:** Implement metadata fields that define an `expiryDate`. The `macro()` function will refuse to decrypt the payload if the system clock is past the expiry, unless an Admin Override key is provided.
*   **Trial Strategy Access:** Enable Strategy 12 (Elite Codec) for a 30-day trial period, controlled via a signed license token.

### Feature Gating
| Feature | Free | Pro | Gov/Enterprise |
| :--- | :--- | :--- | :--- |
| Max File Size | 500MB | 10GB | Unlimited |
| Multi-file Archive | No | Yes | Yes |
| Streaming (v4) | No | Yes | Yes |
| Custom Folds | No | 1 | Unlimited |
| Audit Logs | Console only | JSON file | Signed DB / HSM |
| Support | Community | 24/7 | Dedicated Engineer |

## 3. Strict Ownership & Control
*   **Version Pinning:** Strictly control the `CRAFT_VERSION` byte. Only the Owner can authorize a bump to a new version, ensuring backward compatibility is never accidentally broken during expansions.
*   **Proprietary Codecs:** The Elite Codec (`craft-codec`) resides in a separate repository. In the main engine, it is called via a dynamic bridge that checks the `CraftTier`.
*   **Admin Dashboard (Separated):** A specialized admin-only CLI suite (`craft-admin`) for managing license tokens, viewing global analytics, and performing vault recovery.
