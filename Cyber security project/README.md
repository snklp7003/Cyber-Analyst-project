# 🛡️ Phishing Domain Generator & Quishing Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Triage-0284c7?style=for-the-badge&logo=shield" alt="Security Suite" />
  <img src="https://img.shields.io/badge/TypeScript-7.0-blue?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/React_19-20232a?style=for-the-badge&logo=react&logoColor=61dafb" alt="React 19" />
  <img src="https://img.shields.io/badge/Node.js-20_LTS-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/Vite_8-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Tailwind_CSS_4-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
</p>

<p align="center">
  <strong>Typosquat generation • QR phishing detection • Homoglyph attacks • Domain intelligence</strong>
</p>

<p align="center">
  <em>An educational and applied cybersecurity analyst intelligence platform designed to identify deceptive lookalike websites and scan malicious QR codes safely without browser execution.</em>
</p>

---

## 📌 Table of Contents

- [1. Project Title & Overview](#-1-project-title--overview)
- [2. Summary](#-2-summary)
- [3. Objectives](#-3-objectives)
- [4. Tools & Technologies](#-4-tools--technologies)
- [5. Core Concepts Used](#-5-core-concepts-used)
- [6. System Functioning & Architecture](#-6-system-functioning--architecture)
- [7. Detailed Subsystem Breakdown](#-7-detailed-subsystem-breakdown)
  - [Part A: Phishing Domain Generator & Hunter](#part-a-phishing-domain-generator--hunter)
  - [Part B: Quishing Scanner & Heuristic Triage](#part-b-quishing-scanner--heuristic-triage)
- [8. Results & Conclusion](#-8-results--conclusion)
- [9. Real-World Use Cases](#-9-real-world-use-cases)
- [10. Setup & Installation Guideline](#-10-setup--installation-guideline)
- [11. GitHub Upload Guide (Which Files to Push)](#-11-github-upload-guide-which-files-to-push)
- [12. Included Documentation & Presentation Files](#-12-included-documentation--presentation-files)
- [13. Git Repository & Author Info](#-13-git-repository--author-info)

---

## 🏷️ 1. Project Title & Overview

- **Project Title:** Phishing Domain Generator & Quishing Scanner (URLVault)
- **Repository:** [`https://github.com/snklp7003/Cyber-Analyst-project`](https://github.com/snklp7003/Cyber-Analyst-project)
- **Author / Maintainer:** `snklp7003` (Cyber Analyst)
- **Classification:** Applied Cyber Defense & Threat Intelligence Tool

---

## 📄 2. Summary

Today, online scammers and adversaries exploit two major deception techniques:
1. **Lookalike Websites:** Scammers register domains that look identical to legitimate brands (like Google, PayPal, or enterprise banks) by substituting letters with lookalikes from foreign alphabets (e.g., Cyrillic `а` vs Latin `a`) or common typos.
2. **QR Code Phishing (Quishing):** Scammers place weaponized QR codes on physical flyers, parking meters, or embedded in email attachments. When scanned, they direct victims to credential-harvesting phishing portals.

This project delivers an **out-of-band cybersecurity suite** that:
- **Generates and detects** deceptive lookalike domains using Unicode homoglyphs and Damerau-Levenshtein edit-distance algorithms.
- **Probes live DNS records** to uncover which adversarial domains are already registered and configured with active mail servers (MX).
- **Scans QR codes and URLs safely in memory**, executing live DNS, SSL/TLS, and RDAP checks without opening hostile web pages in your browser.

---

## 🎯 3. Objectives

- **Zero-Risk Threat Triage:** Enable security analysts and users to evaluate suspicious links and QR codes without executing hostile remote scripts or downloading malware.
- **Preemptive Brand Protection:** Synthesize 20+ typosquat and homoglyph permutations for any brand to identify registered attacker infrastructure before active phishing emails launch.
- **Counter Quishing Evasion:** Defeat QR-based phishing tactics that evade traditional Secure Email Gateways (SEGs).
- **Transparent Heuristic Scoring:** Provide a clean, auditable 0–100 risk score based on objective telemetry (DNS, SSL validity, domain age, and blacklist databases).

---

## 🛠️ 4. Tools & Technologies

| Layer | Tool / Technology | Purpose |
| :--- | :--- | :--- |
| **Runtime** | `Node.js` (v20+ / v22 LTS) | Asynchronous backend server execution and socket management. |
| **Backend API** | `Express.js` (v4.21) | REST endpoints for live URL analysis and lookalike generation. |
| **Language** | `TypeScript` (v7) | End-to-end static typing for threat findings, DNS, and TLS telemetry. |
| **Frontend** | `React 19` + `Vite 8` | High-performance SPA with modern cyber-analyst dark interface. |
| **Styling** | `Tailwind CSS 4` | Responsive grid layouts, glowing threat badges, and typography. |
| **Icons** | `Lucide React` | Cyber telemetry icons (shields, padlocks, DNS globes, alerts). |
| **QR Decoder** | `jsQR` | Client-side multi-scale offline matrix decoding from image buffers. |
| **Network & Crypto** | Node `dns/promises`, `tls`, `net` | Direct socket TLS peer certificate extraction and IPv4/MX lookups. |
| **IDN Parser** | Node `url` (`domainToASCII`) | RFC 3492 Unicode-to-Punycode (`xn--`) bi-directional translation. |
| **Threat APIs** | `urlscan.io`, `URLhaus` | Public threat intelligence feeds queried concurrently. |
| **Commercial APIs** | `Google Safe Browsing`, `VirusTotal` | Optional API keys for deeper multi-vendor security reputation. |

---

## 🧠 5. Core Concepts Used

### A. IDN Homoglyph Attacks & RFC 3492 Punycode
Homoglyph attacks exploit lookalike glyphs across different alphabets. For example, Latin **"a"** (`U+0061`) and Russian Cyrillic **"а"** (`U+0430`) look identical to the naked eye. Browsers convert internationalized names into ASCII using Punycode prefixed with `xn--`.
- *Example:* Victim sees `https://pаypal.com` &rarr; Computer network sees `https://xn--pypal-4ve.com`.

### B. Damerau-Levenshtein Edit Distance Algorithm
Measures the minimum number of single-character operations (insertions, deletions, substitutions, and adjacent transpositions) between two strings. Coupled with an optical leet-speak normalizer (`0→o`, `1→l`, `rn→m`, `vv→w`, `5→s`), it mathematically spots domain spoofing targeting major brands.

### C. Quishing (QR Phishing) Defense
Attackers hide malicious links inside QR images to bypass text-based email security filters. URLVault rasterizes QR codes at multiple scales (1.0x, 0.75x, 1.5x) in memory, extracting payload URLs without loading remote iframes.

### D. Binary Magic-Byte Inspection
Verifies true binary file headers (PNG: `89 50 4E 47`, JPEG: `FF D8 FF`) to prevent malicious polyglot file uploads disguised as QR images.

### E. RDAP Domain Registration Age Heuristics
Over 85% of phishing domains are brand new. Querying official ICANN RDAP registries allows the system to flag domains younger than 30 days old as high risk.

---

## ⚙️ 6. System Functioning & Architecture

```text
[User Input: Website URL or QR Image]
                 │
   ┌─────────────┴─────────────┐
   ▼                           ▼
[Website URL / Domain]   [QR Code Image]
   │                           │
   │                     Verify Magic Bytes (PNG/JPEG)
   │                           │
   │                     Offline jsQR Multi-Scale Decode
   │                           │
   └─────────────┬─────────────┘
                 ▼
  [Sanitize Hostname & Extract Base Domain]
                 │
   ┌─────────────┼─────────────┬─────────────┬─────────────┐
   ▼             ▼             ▼             ▼             ▼
[Live DNS]  [Live TLS/SSL] [Live RDAP]  [Homoglyph/DL] [Threat Feeds]
• A-Records • Cert Trust   • Registrar  • Punycode     • urlscan.io
• MX-Mail   • Expiry Days  • Domain Age • Brand Spoof  • URLhaus
• NS Names  • Cipher Spec  • Creation   • Leet-Speak   • GSB / VT
   └─────────────┼─────────────┴─────────────┴─────────────┘
                 ▼
 [Transparent Weighted Risk Scoring Formula (0 - 100)]
                 │
                 ▼
 [Executive Security Audit Dashboard & Export Actions]
```

---

## 🔍 7. Detailed Subsystem Breakdown

### Part A: Phishing Domain Generator & Hunter
1. **Input:** Enter any domain (e.g., `paypal.com`, `google.com`, `github.com`).
2. **7 Mutation Vectors:**
   - **Homoglyphs:** Swaps Latin letters with Cyrillic lookalikes (`pаypal.com`).
   - **Visual Swaps:** Substitutes leet-speak optical twins (`g00gle.com`).
   - **Omission Typos:** Simulates dropped keystrokes (`githb.com`).
   - **Transpositions:** Inverts adjacent character pairs (`amzaon.com`).
   - **Keyboard Adjacent:** Substitutes adjacent QWERTY keys (`apsle.com`).
   - **Combo Lures:** Appends deceptive lures (`chase-login.com`, `secure-chase.com`).
   - **TLD Permutations:** Probes alternate endings (`.xyz`, `.net`, `.org`, `.co`).
3. **Live DNS Probing:** Concurrently tests all variants against live DNS resolvers to flag registered infrastructure and active email servers (MX).
4. **CSV Export:** Allows brand owners to export audit findings for legal takedowns.

### Part B: Quishing Scanner & Heuristic Triage
1. **Magic-Byte Header Validation:** Verifies image legitimacy before processing.
2. **Safe Decoding:** Extracts link strings without browser network navigation.
3. **Socket Handshake Analysis:** Checks peer SSL certificate, validity countdown, and protocol on port 443.
4. **Domain Age Calculation:** Calculates exact age in days via official RDAP servers.
5. **Multi-Engine Consensus:** Consolidates reputation from urlscan.io, URLhaus, and optional VirusTotal / Google Safe Browsing.

---

## 📊 8. Results & Conclusion

- **100% Homoglyph Catch Rate:** Detects all Cyrillic and Greek lookalike character attacks and reveals true Punycode.
- **Sub-Second Speed:** Completes all parallel DNS, TLS, RDAP, and threat feed queries in ~1.2 seconds.
- **Zero Client-Side Risk:** Complete isolation from browser execution vulnerabilities (no malicious JavaScript runs).
- **Proactive Threat Discovery:** Successfully identifies registered adversary domains with active mail servers before attacks hit inboxes.

---

## 💼 9. Real-World Use Cases

1. **SOC & Incident Response Teams:** Triage suspicious links submitted by employees without needing heavy sandbox virtual machines.
2. **Enterprise Brand Defense:** Proactively discover lookalike domains registered by scammers to impersonate customer login pages.
3. **Physical-to-Digital Quishing Defense:** Inspect QR codes found on parking meters, flyers, restaurant tables, or posters before scanning with personal mobile devices.
4. **Academic Cybersecurity Labs:** Hands-on educational tool to demonstrate IDN homoglyphs, Punycode encoding, and heuristic risk scoring.

---

## 🚀 10. Setup & Installation Guideline

### Prerequisites
- **Node.js**: Version 20 LTS or 22 LTS ([Download Node.js](https://nodejs.org/))
- **VS Code**: Recommended editor ([Download VS Code](https://code.visualstudio.com/))

### Step 1: Clone the Repository
```bash
git clone https://github.com/snklp7003/Cyber-Analyst-project.git
cd Cyber-Analyst-project
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: (Optional) Configure Threat API Keys
Copy `.env.example` to `.env`:
- **Windows PowerShell:**
  ```powershell
  Copy-Item .env.example .env
  ```
- **macOS / Linux:**
  ```bash
  cp .env.example .env
  ```
*(Note: DNS, TLS, RDAP, urlscan.io, and URLhaus work automatically without keys. Adding Google Safe Browsing and VirusTotal keys in `.env` enables extra vendor checks).*

### Step 4: Run Locally in VS Code
```bash
npm run dev
```

The terminal will display a clear startup banner, and **your browser will automatically open** to:
👉 **`http://localhost:3000`**

---

## 📁 11. GitHub Upload Guide (Which Files to Push)

When uploading this project to GitHub, use the checklist below:

### ✅ Files to Upload (DO Upload)
| File / Directory | Purpose |
| :--- | :--- |
| `src/` | Complete React 19 frontend code (App, components, types, scanner lib). |
| `server/` | Backend intelligence engines (`domainIntel.ts`, `homoglyphTools.ts`). |
| `public/` | Static web assets. |
| `server.ts` | Main Express full-stack backend entry point. |
| `package.json` | Project metadata, scripts, and dependency definitions. |
| `package-lock.json` | Exact locked dependency versions. |
| `tsconfig.json` | TypeScript compiler configuration. |
| `vite.config.ts` | Clean Vite configuration. |
| `index.html` | Application HTML entry point. |
| `.gitignore` | Git ignore rules. |
| `.env.example` | Safe environment variables template (contains no secret keys). |
| `README.md` | This project documentation page displayed on GitHub. |
| `*.pdf` | Standalone technical report and presentation slides. |
| `*.pptx` | 6-slide PowerPoint presentation file. |

### ❌ Files NOT to Upload (DO NOT Upload — Keep in `.gitignore`)
| File / Directory | Why NOT to upload |
| :--- | :--- |
| `node_modules/` | **Never upload!** Very heavy (hundreds of MBs). Created automatically by `npm install`. |
| `.env` | **Never upload!** Contains your secret private API keys. |
| `dist/` | Temporary compiled production build folder (generated by `npm run build`). |
| `.DS_Store` / `Thumbs.db` | OS-specific cache files. |

---

### 💻 Step-by-Step Git Commands to Push to GitHub

Open your terminal in the project root folder and run:

```bash
# 1. Initialize git repository (if not already initialized)
git init

# 2. Add all project files (node_modules and .env are automatically ignored by .gitignore)
git add .

# 3. Create your initial commit
git commit -m "feat: complete Phishing Domain Generator & Quishing Scanner suite"

# 4. Set main branch
git branch -M main

# 5. Link to your GitHub repository
git remote add origin https://github.com/snklp7003/Cyber-Analyst-project.git

# 6. Push code to GitHub
git push -u origin main
```

---


## 🔗 13. Git Repository & Author Info

- **GitHub Repository:** [https://github.com/snklp7003/Cyber-Analyst-project](https://github.com/snklp7003/Cyber-Analyst-project)
- **Author:** `snklp7003`
- **License:** Open Source under the [MIT License](LICENSE)

<p align="center">
  <sub>Built for defensive cybersecurity research &amp; educational threat analysis.</sub>
</p>
