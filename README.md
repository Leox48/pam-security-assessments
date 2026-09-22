# PAM Security Assessments

> Methodology, attack chains, and hardening guidance for enterprise Privileged Access Management platforms — based on real-world security assessments.

---

## About This Repository

This repository documents security research and assessment methodologies for enterprise PAM (Privileged Access Management) platforms. The content is based on hands-on penetration testing experience across enterprise environments and is intended for:

- **Security engineers** assessing PAM deployments in their organization
- **Red teamers** approaching PAM components as part of internal engagements
- **Blue teamers and PAM administrators** looking to understand attack patterns and harden their deployments
- **Security professionals** preparing for PAM-focused assessments

All content is written from an offensive security perspective, with defensive recommendations included for each finding class. No client data, proprietary configurations, or confidential information is disclosed. Scenarios and examples are either fictional or derived from public documentation and vendor advisories.

---

## Repository Structure

```
pam-security-assessments/
│
├── README.md                          ← You are here
│
├── cyberark/
│   └── credential-provider-methodology.md   ← CyberArk AIM/CP assessment guide
│
├── hashicorp-vault/                   ← Coming soon
│
└── beyondtrust/                       ← Coming soon
```

---

## Coverage

### ✅ CyberArk Credential Provider (AIM/CP)

**File:** [`cyberark/credential-provider-methodology.md`](./cyberark/credential-provider-methodology.md)

A comprehensive methodology for assessing CyberArk Application Identity Manager (AIM) Credential Provider deployments on Linux. Covers:

- Architecture and threat model
- Pre-engagement checklist and information gathering
- Phase-by-phase assessment methodology (host recon → config analysis → AppID restriction testing → privilege escalation → host controls)
- CP error code reference and how to use error responses as a diagnostic tool
- Common misconfigurations with risk ratings
- Attack chains with prerequisites, steps, and impact
- Full hardening recommendations
- Detection and monitoring guidance

**Key attack patterns documented:**
- Sudo impersonation → AppID OS User bypass → credential theft
- NOPASSWD sudo escalation → root → CP credential file offline attack
- RCE in application → direct CP credential extraction
- AppID enumeration via error differentiation

---

### 🔜 HashiCorp Vault *(coming soon)*

Assessment methodology for HashiCorp Vault deployments — covering token-based auth weaknesses, policy misconfiguration, secret engine exposure, and audit log gaps.

---

### 🔜 BeyondTrust Password Safe *(coming soon)*

Assessment methodology for BeyondTrust Password Safe — covering API security, session recording bypass, and privilege escalation patterns.

---

## Key Concepts

### Why PAM Security Assessment is Different

Most penetration testers are comfortable with web application testing (OWASP Top 10, API security) or infrastructure testing (network services, AD). PAM assessments require a different mindset:

- The target is **not a web application** — there is no HTTP, no browser, no form to submit
- The attack surface is **the trust model** between the application, the PAM agent, and the Vault
- The critical question is always: **"Who can request credentials on behalf of this AppID, and is that restriction bypassable?"**
- The most impactful findings come from **chaining** host-level misconfigurations (sudoers, file permissions) with PAM-level weaknesses (insufficient AppID restrictions)

### The PAM Assessment Mindset

```
Web PT mindset:        Find input → inject payload → observe output
PAM assessment mindset: Find trust boundary → identify who/what crosses it →
                        test if the boundary can be bypassed
```

---

## Methodology Philosophy

The assessments documented here follow these principles:

**Evidence-based:** Every finding is supported by observable output — error codes, log entries, command output. No theoretical vulnerabilities without proof of concept.

**Manual-first:** These assessments rely on native system tools and platform CLIs, not automated scanners. Automated tools miss the context-dependent findings that matter most in PAM environments.

**Chain-oriented:** Individual weaknesses are analyzed for their chaining potential. A world-readable file and a sudo misconfiguration are each low-severity in isolation — combined, they may constitute a critical credential theft path.

**Remediation-focused:** Every finding class includes specific, actionable remediation guidance for the platform being assessed.

---

## Author

**Leonardo Sole** — Offensive Security Engineer

Specialized in web application penetration testing, API security, and enterprise security assessments across industrial and enterprise environments. Experience across CyberArk PAM, cloud-native applications (Azure), GenAI/RAG security, and legacy enterprise platforms.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-leonardo--sole48-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/leonardo-sole48/)

---

## Disclaimer

All techniques and methodologies described in this repository are intended for use in **authorized security assessments only**. The author does not condone unauthorized access to computer systems. Always obtain explicit written authorization before conducting security testing.

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

*If you find this useful, a ⭐ on the repo is appreciated.*
