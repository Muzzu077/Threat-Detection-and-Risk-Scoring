# ThreatPulse - Complete Project Explanation (Plain English)

> **One-line summary:** ThreatPulse is an AI-powered security system that watches your network traffic in real-time, detects 15 types of cyber attacks, and automatically fights back.

---

## What Does This Project Do? (The Big Picture)

Imagine you own a building with 100 doors. You need:
1. **Cameras** on every door (to see who's coming in)
2. **A smart guard** who can tell the difference between a visitor and a burglar
3. **Automatic locks** that slam shut when a burglar is detected
4. **A control room** where you see everything on screens

ThreatPulse does exactly this, but for computer networks:
- **Cameras** = Log Ingestion (watches every network request)
- **Smart Guard** = ML Engine (AI that classifies attacks with 97% accuracy)
- **Automatic Locks** = SOAR Playbooks (blocks IPs, disables accounts automatically)
- **Control Room** = React Dashboard (beautiful real-time UI)

---

## The 15 Types of Cyber Attacks We Detect

Based on **OWASP Top 10 (2021 + 2023 API Security)** - the global standard for web security threats:

### Category 1: Injection Attacks (Someone puts bad code into your system)

| # | Attack | Plain English | Real-World Example | OWASP |
|---|--------|--------------|-------------------|-------|
| 1 | **SQL Injection** | Attacker types database commands into a login form to steal all user data | The 2017 Equifax breach that exposed 147 million people | 2021 #3 |
| 2 | **XSS (Cross-Site Scripting)** | Attacker plants a hidden script on your website that steals cookies from visitors | Hackers injecting fake login popups on banking sites | 2021 #3 |
| 3 | **Command Injection** | Attacker sends OS commands through your website to take over the server | Typing `; rm -rf /` in a search box to delete the server | 2021 #3 |

### Category 2: Broken Access Control (Someone goes where they shouldn't)

| # | Attack | Plain English | Real-World Example | OWASP |
|---|--------|--------------|-------------------|-------|
| 4 | **Privilege Escalation** | A normal user tricks the system into giving them admin powers | A bank teller giving themselves manager access | 2021 #1 |
| 5 | **Directory Traversal** | Attacker navigates to secret files by manipulating file paths (../../../etc/passwd) | Reading server config files that contain passwords | 2021 #1 |
| 6 | **Insider Threat** | A trusted employee secretly steals company data | Edward Snowden-type scenarios, but malicious | 2021 #1 |

### Category 3: Authentication Attacks (Someone steals your keys)

| # | Attack | Plain English | Real-World Example | OWASP |
|---|--------|--------------|-------------------|-------|
| 7 | **Brute Force** | Trying thousands of passwords until one works | Like trying every combination on a padlock | 2021 #7 |
| 8 | **Credential Stuffing** | Using leaked passwords from one site to log into another | If your Netflix password leaked, they try it on your bank | 2021 #7 |
| 9 | **Session Hijacking** | Stealing someone's logged-in session to impersonate them | Stealing someone's boarding pass after they checked in | 2021 #7 |

### Category 4: Infrastructure Attacks (Attacking the building itself)

| # | Attack | Plain English | Real-World Example | OWASP |
|---|--------|--------------|-------------------|-------|
| 10 | **DoS Attack** | Flooding a server with so many requests it crashes | Like 1 million people calling a pizza shop at once | 2023 API #4 |
| 11 | **Port Scan** | Scanning all "doors" of a server to find open ones | A burglar checking every window and door of a house | Discovery |
| 12 | **SSRF** | Tricking the server into attacking its own internal network | Telling a security guard to open the vault for you | 2021 #10 |

### Category 5: Malware & Data Theft

| # | Attack | Plain English | Real-World Example | OWASP |
|---|--------|--------------|-------------------|-------|
| 13 | **Malware Upload** | Uploading a virus/backdoor to the server | Emailing a trojan horse disguised as a PDF | 2021 #8 |
| 14 | **Data Exfiltration** | Secretly copying and sending data outside the company | Uploading the company database to a hacker's server | Exfiltration |
| 15 | **Normal** | Not an attack. Regular user activity. | You browsing a website normally | N/A |

---

## How Each Feature Works (In Plain English)

### 1. ML Engine (The Brain)

**What it is:** An AI model (LightGBM) that looks at every network request and says "this is an attack" or "this is normal."

**How it works (like a doctor):**
```
Patient walks in (network request arrives)
    |
Doctor checks vital signs (extracts 21 features: who, what, when, where, network patterns)
    |
Compares to medical textbook (trained on 10,000 labeled examples)
    |
Diagnosis: "SQL Injection" with 94% confidence
    |
Prescribes treatment (triggers SOAR playbook)
```

**The 21 features it looks at:**
- **Who**: username, role (admin/user/guest)
- **What**: action (login, download, api_call), resource accessed
- **When**: hour of day (3 AM login = suspicious)
- **Where**: IP address, country
- **Network fingerprint**: 15 CIC-IDS2017 features (packet sizes, flow duration, flag counts, etc.)

**Accuracy:** 97% across all 15 attack types

---

### 2. MITRE ATT&CK Mapping (The Universal Language)

**What it is:** A global encyclopedia of hacker techniques maintained by the US government (MITRE Corporation). Every attack has a "T-number" ID.

**Why it matters:**
- Without MITRE: "We detected something bad"
- With MITRE: "We detected T1110.004 (Credential Stuffing) - Credential Access tactic"

**How it works in ThreatPulse:**
```
ML Engine says: "This is a brute_force attack"
    |
MITRE Mapper looks up: brute_force -> T1110 (Brute Force)
    |
Returns:
  - Technique ID: T1110
  - Tactic: Credential Access
  - Sub-technique: T1110.001 - Password Guessing
  - Description: "Adversaries try many passwords..."
  - Mitigation: "Enable MFA, Account Lockout..."
  - Kill Chain Phase: Where this fits in the attack lifecycle
```

**Think of it as:** A common medical coding system. Instead of doctors saying "the patient has a bad heart," they say "ICD-10: I21.9 (Acute Myocardial Infarction)." Now every doctor worldwide understands exactly what happened.

---

### 3. SOAR Playbooks (The Automatic Response)

**What SOAR stands for:** Security Orchestration, Automation, and Response

**What it does:** When an attack is detected, it automatically runs a pre-defined "recipe" of countermeasures.

**How it works (like a fire alarm system):**
```
BEFORE (Old approach):
  Fire detected -> Guard calls manager -> Manager calls fire dept -> 20 min delay

AFTER (SOAR):
  Fire detected -> AUTOMATICALLY: sprinklers ON + alarm sounds + doors lock + fire dept called
  Response time: < 1 second
```

**Example: SQL Injection Playbook (risk score = 85)**
```
Step 1: [ALWAYS]     Block attacker IP          -> EXECUTED
Step 2: [ALWAYS]     Deploy WAF SQL filter      -> EXECUTED
Step 3: [ALWAYS]     Rate limit subnet          -> EXECUTED
Step 4: [ALWAYS]     Alert DBA team             -> EXECUTED
Result: 4/4 actions taken in < 1 second
```

**Example: Port Scan Playbook (risk score = 45)**
```
Step 1: [ALWAYS]      Rate limit scanner IP     -> EXECUTED
Step 2: [risk >= 80]  Block persistent scanners -> SKIPPED (risk only 45)
Step 3: [risk >= 70]  DROP scan traffic         -> SKIPPED
Step 4: [risk >= 80]  Alert if scan persists    -> SKIPPED
Result: 1/4 actions taken (low risk = gentle response)
```

**We have 15 playbooks** - one for each attack type, plus a default fallback.

---

### 4. UEBA (User Behavior Analytics)

**What it is:** Learns what "normal" looks like for each employee, then flags anything unusual.

**How it works (like a parent who knows their child):**
```
Learning Phase (first 10 events per user):
  "Alice usually logs in at 9 AM from IP 192.168.1.5"
  "Alice usually accesses: home, products, user_settings"
  "Alice's average login hour: 10.2 AM, std deviation: 1.5 hours"

Detection Phase:
  Alice logs in at 3 AM from IP 45.33.22.11 -> ANOMALY!

  Why?
  Z-score = |3 - 10.2| / 1.5 = 4.8 (way above 2.5 threshold)
  + New IP never seen before
  + Accessing "database" for the first time

  Result: Risk score boosted by +25
```

**Key concept - Z-Score:** Measures how many "standard deviations" away something is from normal. A z-score > 2.5 means "this is extremely unusual" (happens less than 1% of the time).

---

### 5. Threat Intelligence (Checking Criminal Records)

**What it is:** Before processing any IP, we check it against global databases of known bad IPs.

**Three sources we check:**

| Source | What it Contains | Think of it As |
|--------|-----------------|----------------|
| **AbuseIPDB** | Crowd-reported malicious IPs (API lookup) | A "most wanted" list for IP addresses |
| **Tor Exit Nodes** | IPs belonging to the Tor anonymity network | People wearing masks (not always bad, but suspicious) |
| **Emerging Threats** | Compromised/malicious IPs from security researchers | FBI's criminal database for computers |

**How it works:**
```
New request from IP 185.220.101.3
    |
Check #1: AbuseIPDB -> Score: 85% (highly reported)
Check #2: Tor Exit Nodes -> YES, this is a Tor exit node
Check #3: Emerging Threats -> YES, known compromised IP
    |
Result: Risk boost = +20 (Tor) + +25 (ET) = +45 added to risk score
```

---

### 6. OSINT Feeds (Open Source Intelligence)

**What it is:** Free, real-time threat data feeds from the global security community.

**Our 3 feeds:**
1. **Tor Exit Nodes** (check.torproject.org) - ~1,000 IPs of Tor exit relays
2. **Emerging Threats** (rules.emergingthreats.net) - ~800 compromised IPs
3. **URLhaus** (abuse.ch) - Recently discovered malicious URLs

**How it differs from Threat Intel:** Threat Intel = checking one specific IP. OSINT = bulk downloading lists of ALL known bad IPs and checking incoming traffic against them automatically.

---

### 7. Adversarial Robustness Testing (Testing Our Own Defenses)

**What it is:** We attack our own ML model with tricky evasion techniques to see if it can still detect them.

**Why it matters:** Smart hackers don't just attack - they disguise their attacks to look normal. We need to know if our AI can see through disguises.

**The 5 evasion tests:**

| Test | What the Attacker Does | Think of it As |
|------|----------------------|----------------|
| **Slow Brute Force** | Spreads login attempts over hours instead of seconds | A pickpocket who works slowly over days |
| **Mimicry Attack** | Makes attack traffic look like normal user behavior | A spy wearing a company uniform |
| **IP Rotation** | Scans from thousands of different IPs | A criminal who changes cars after every robbery |
| **Insider Exfil** | Uses legitimate credentials for data theft | An employee stealing one file per day |
| **Encoded SQLi** | Obfuscates SQL injection with URL encoding | Writing a threat note in code |

**Our result:** 100% detection rate (ROBUST verdict)

---

### 8. Online Learning / Feedback Loop (Getting Smarter Over Time)

**What it is:** When a security analyst reviews an alert and says "this was actually a false alarm," that feedback is stored and used to improve the model.

**How it works:**
```
Day 1: ML flags Alice's bulk download as "data_exfiltration" (risk: 82)
    |
Analyst reviews: "No, Alice is in finance. She downloads reports every Monday."
    |
Analyst clicks: [FALSE POSITIVE] button
    |
System records:
  - Original prediction: data_exfiltration
  - Analyst correction: false_positive
  - Updated FP rate: 8.3% for data_exfiltration
    |
Drift Monitor: "FP rate is 8.3% - model is performing well"
(If FP rate exceeds 15%, system recommends retraining)
```

---

### 9. MTTD / MTTR Metrics (How Fast Are We?)

**What these mean:**
- **MTTD (Mean Time To Detect)** = How quickly we spot an attack after it starts
- **MTTR (Mean Time To Respond)** = How quickly we take action after detecting it

**Why it matters:**
```
Industry averages (without AI):
  MTTD: 197 days (IBM 2023 report)
  MTTR: 69 days

ThreatPulse:
  MTTD: < 10 seconds (real-time ML classification)
  MTTR: < 1 second (automated SOAR playbooks)
```

**These are SLA-grade metrics** that enterprises use to measure their security team's effectiveness.

---

### 10. Attack Graph / Kill Chain Visualization

**What it is:** A visual network diagram showing how attacks flow through your system.

**Kill Chain concept:**
```
Step 1: Reconnaissance    (Attacker scans your ports)
Step 2: Initial Access    (Attacker finds a way in - SQL injection)
Step 3: Execution         (Attacker runs malicious code)
Step 4: Privilege Escalation (Attacker becomes admin)
Step 5: Discovery         (Attacker maps your internal network)
Step 6: Exfiltration      (Attacker steals your data)
```

**Our D3.js graph** shows this visually: nodes are IPs/users/resources, edges are attack relationships, colored by severity.

---

### 11. AI-Powered Analysis (Gemini Integration)

**What it is:** For every high-risk incident, Google's Gemini AI writes a human-readable summary explaining:
- What happened
- Why it's dangerous
- What you should do

**Example output:**
> "User `apt29_cozybear` attempted credential stuffing from IP 185.220.101.3 (Tor exit node) targeting the admin login page. 47 failed attempts detected in 2 minutes. This matches APT29 (Cozy Bear) tactics. Recommend: Block IP range, enforce MFA on admin accounts, check for successful logins."

---

### 12. Telegram Alerts (Instant Notification)

**What it is:** When a critical threat is detected, ThreatPulse sends an instant Telegram message to the security team's phone.

**What the alert contains:**
- Incident ID and severity
- Attacker IP and username
- Attack type with MITRE ID
- AI-generated summary
- Quick action buttons (View Incident, Block IP)

---

## System Architecture (How It All Connects)

```
                    ┌─────────────────────────────────────────┐
                    │            REACT DASHBOARD               │
                    │  (8 pages: Dashboard, Incidents, ML,     │
                    │   Threat Intel, SOAR, Playbooks,         │
                    │   Attack Graph, Investigation)           │
                    └──────────────────┬──────────────────────┘
                                       │ HTTP/REST API
                    ┌──────────────────▼──────────────────────┐
                    │           FASTAPI BACKEND                │
                    │  (45 API endpoints, Python)              │
                    └────┬─────┬──────┬──────┬──────┬────────┘
                         │     │      │      │      │
            ┌────────────▼─┐ ┌─▼────┐ │  ┌───▼──┐ ┌─▼────────┐
            │  ML ENGINE   │ │ UEBA │ │  │ SOAR │ │  THREAT   │
            │  (LightGBM)  │ │      │ │  │      │ │  INTEL    │
            │  15 classes   │ │Z-score│ │  │ 15   │ │ AbuseIPDB│
            │  97% accuracy │ │anomaly│ │  │plays │ │ OSINT    │
            └──────────────┘ └──────┘ │  └──────┘ └──────────┘
                                      │
                              ┌───────▼───────┐
                              │   SQLITE DB   │
                              │ Events + INC  │
                              └───────────────┘
```

---

## Tech Stack Summary

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | React + Vite + Recharts + D3.js | Fast, interactive, beautiful charts |
| Backend | FastAPI (Python) | Fastest Python web framework, auto-docs |
| ML Model | LightGBM | Best accuracy for tabular data, fast inference |
| Database | SQLite + SQLAlchemy | Simple, no setup needed, good for demos |
| Alerts | Telegram Bot API | Free, instant, mobile-friendly |
| AI Summary | Google Gemini API | Best free AI for text generation |
| Deployment | Docker Compose | One-command deployment |

---

## How to Explain This to a Non-Technical Person

> "ThreatPulse is like a smart security guard for computer networks. It watches every request that comes into your system - who's asking, what they want, and when. Using AI (like facial recognition but for network traffic), it can identify 15 different types of cyber attacks with 97% accuracy. When it spots an attack, it doesn't just ring an alarm - it automatically blocks the attacker, locks compromised accounts, and notifies the security team on their phone within seconds. It uses the same threat classification system (MITRE ATT&CK) that the FBI and Pentagon use. And it gets smarter over time - when security analysts correct a mistake, the system learns from it."

---

## Numbers That Matter

| Metric | Value |
|--------|-------|
| Attack types detected | **15** (based on OWASP Top 10) |
| ML model accuracy | **97%** |
| Automated playbooks | **15** (one per attack type) |
| API endpoints | **45** |
| OSINT indicators loaded | **1,849+** |
| Response time (SOAR) | **< 1 second** |
| MITRE techniques mapped | **15+** |
| Frontend pages | **8** |
| Network features analyzed | **21** per request |
| Adversarial robustness | **100%** detection rate |
