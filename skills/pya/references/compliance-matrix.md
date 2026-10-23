# Compliance Matrix: Code-Level Requirements

## Purpose

Maps security findings to compliance requirements. Used when `--compliance <target>` is given.
PYA reports **code-level evidence** for or against a requirement. It never certifies compliance:
most requirements also need process, people and operational evidence that a code audit cannot see.

Versions, dates and URLs for every framework live in `standards.md`. Targets:

| Target | Framework | Version |
|---|---|---|
| `pci` | PCI DSS | 4.0.1 |
| `hipaa` | HIPAA Security Rule | current 45 CFR 164.312 (NPRM pending) |
| `soc2` | SOC 2 Trust Services Criteria | 2017 TSC, revised points of focus 2022 |
| `gdpr` | GDPR | Regulation (EU) 2016/679 |
| `nist` | NIST SP 800-53 | Release 5.2.0 |
| `ssdf` | NIST SP 800-218 SSDF | v1.1 |
| `csf` | NIST Cybersecurity Framework | 2.0 |
| `cra` | EU Cyber Resilience Act | Art. 14 reporting (applies since 2026-09-11) |
| `asvs` | OWASP ASVS | 5.0.0 |

---

## PCI DSS 4.0.1 (Payment Card Industry)

Source: https://www.pcisecuritystandards.org/rfc_instructions_pci-dss-v4-0-1-june2026/ . The
future-dated requirements of 4.0 (including 6.4.3 and 11.6.1) have been mandatory since 2025-03-31.

### Requirement 6: Develop and Maintain Secure Systems and Software

| Req | Description | Code-Level Check | Maps to CWE |
|-----|-------------|------------------|-------------|
| 6.2.1 | Bespoke and custom software developed securely | Secure SDLC evidence, code review process | General |
| 6.2.2 | Software development personnel trained | N/A (process, not code) | N/A |
| 6.2.3 | Bespoke software reviewed prior to release | This audit is supporting evidence, not the whole requirement | General |
| 6.2.4 | Prevent common attacks in bespoke software | SQLi, XSS, CSRF, buffer overflow, command injection, path traversal detection | CWE-89, 79, 352, 120, 78, 22 |
| 6.3.1 | Security vulnerabilities identified and addressed | Dependency scanning against the feed and OSV | Various |
| 6.3.2 | Inventory of bespoke software and third-party components | Manifests and lockfiles exist and are complete; SBOM generated | N/A |
| 6.4.1 | Public-facing web apps protected against attacks | WAF or equivalent, input validation | CWE-79, 89 |
| 6.4.2 | Automated technical solution for public-facing web apps | Evidence of WAF or RASP configuration in IaC | CWE-693 |
| **6.4.3** | **Payment page scripts managed** (authorized, integrity assured, inventoried with justification) | See "Payment page scripts" below | CWE-829, 494 |

### Requirement 11.6.1: Change and Tamper Detection on Payment Pages

| Req | Description | Code-Level Check | Maps to CWE |
|-----|-------------|------------------|-------------|
| **11.6.1** | Alert on unauthorized changes to security-impacting HTTP headers and script contents of payment pages as received by the browser | CSP (with reporting) or another tamper-detection mechanism configured for checkout routes; security headers set in code or IaC, not ad hoc | CWE-829, 693 |

### Payment page scripts (6.4.3, 11.6.1)

**Report when** a checkout, payment or card-entry page (routes or templates named `checkout`, `payment`, `billing`, `pay`, or pages that load a payment SDK) loads a third-party script and any of these is true:

- the `<script src>` has no `integrity="sha384-..."` attribute and the URL is not versioned and pinned;
- there is no Content-Security-Policy restricting `script-src` on that route;
- there is no inventory of the page's scripts (a list in code, config or docs with a justification for each);
- tag managers or "load any script" loaders are present on the page.

**Skip when** the card fields are entirely inside a provider-hosted iframe or redirect (the page itself never handles card data) and the merchant page loads only first-party scripts. Note the scope reduction in the report.

```html
<!-- VULNERABLE: unpinned third-party script on the payment page, no SRI, no CSP -->
<script src="https://cdn.example-analytics.com/latest/tracker.js"></script>

<!-- SAFE: pinned, integrity-checked, allowed by CSP, listed in the script inventory -->
<script src="https://cdn.example.com/lib/4.2.1/lib.min.js"
        integrity="sha384-<hash>" crossorigin="anonymous"></script>
<!-- Content-Security-Policy: script-src 'self' https://cdn.example.com; report-to csp -->
```

### Requirement 8: Identify Users and Authenticate Access

| Req | Description | Code-Level Check |
|-----|-------------|------------------|
| 8.2.1 | Unique IDs for all users | No shared or hardcoded credentials in code |
| 8.2.8 | Idle session timeout | Session expiry of 15 minutes or less on CDE admin sessions |
| 8.3.1 | Strong authentication for users | Authentication implementation quality |
| 8.3.6 | Passwords: minimum 12 characters | Password policy enforcement in validation code |
| 8.4.2 | MFA for all access into the CDE | MFA present for admin and CDE flows |
| 8.6.1 | System and application accounts managed | No hardcoded service account passwords |
| 8.6.2 | No hardcoded passwords for application accounts in scripts, config or code | Secret scanner results |

### Requirement 3: Protect Stored Account Data

| Req | Description | Code-Level Check |
|-----|-------------|------------------|
| 3.3.1 | Sensitive authentication data not retained after authorization | No CVV/CVC storage, no full track data |
| 3.4.1 | PAN masked when displayed | Masking in UI and logs |
| 3.5.1 | PAN rendered unreadable wherever stored | Encryption, truncation, tokenization or keyed hashing |
| 3.5.1.2 | Disk-level encryption not the sole mechanism | Application-level protection for PAN |

### Requirement 4: Protect Cardholder Data in Transit

| Req | Description | Code-Level Check |
|-----|-------------|------------------|
| 4.2.1 | Strong cryptography for transmission, trusted certificates | TLS 1.2+ enforced, certificate validation enabled, no `verify=False`, no stale vendored CA bundles |
| 4.2.2 | PAN secured when sent via end-user messaging | No PAN in logs, emails, chat messages |

### Requirement 10: Log and Monitor All Access

| Req | Description | Code-Level Check |
|-----|-------------|------------------|
| 10.2.1 | Audit logs enabled and active | Logging framework configured and active |
| 10.2.1.1 | Logs capture individual user access to cardholder data | Data access events logged with user identity |
| 10.2.1.2 | Logs capture all admin actions | Admin action logging implementation |
| 10.2.2 | Logs record required details | Timestamp, user, event type, outcome, affected data |
| 10.3.2 | Audit logs protected from modification | Log file permissions, append-only or remote sink |

### PCI DSS Code-Level Detection Patterns

```text
# PAN (Primary Account Number) in code
# Visa: starts with 4, 16 digits
# Mastercard: starts with 5[1-5] or 2[2-7], 16 digits
# Amex: starts with 3[47], 15 digits
# Discover: starts with 6011 or 65, 16 digits
Regex: \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b

# CVV in code (must never be stored after authorization, 3.3.1)
Variables named: cvv, cvc, cvv2, cvc2, security_code, card_code

# PAN in logs (violates 3.4.1 / 3.5.1)
logger.info("Card number: " + pan)
console.log("Payment with card " + cardNumber)
```

---

## HIPAA (Health Insurance Portability and Accountability Act)

Map to the **current** Security Rule text (45 CFR 164.312,
https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C). The Security
Rule NPRM is still pending; its final rule is now targeted for July 2027 (secondary source:
https://www.alston.com/en/insights/publications/2026/07/hhs-delays-hipaa-security-rule-2027).
Do not report proposed-rule requirements as failures. You may add an INFO note that the NPRM would
make some "addressable" items, such as encryption, mandatory.

### 164.312 Technical Safeguards

| Safeguard | Description | Code-Level Check | Maps to |
|-----------|-------------|------------------|---------|
| (a)(1) Access Control | Allow access only to authorized persons or software | Auth system with unique IDs, authorization on ePHI endpoints | CWE-862, 639 |
| (a)(2)(i) Unique User ID | Assign unique name or number | User model with unique identifiers, no shared accounts | CWE-287 |
| (a)(2)(ii) Emergency Access | Procedures for emergency access | Break-glass implementation with logging | Design |
| (a)(2)(iii) Automatic Logoff (addressable) | Terminate session after inactivity | Session expiry, idle timeout | CWE-613 |
| (a)(2)(iv) Encryption and Decryption (addressable) | Encrypt ePHI | Encryption at rest for health data fields | CWE-311 |
| (b) Audit Controls | Record and examine activity | Audit logging for ePHI access events | CWE-778 |
| (c)(1) Integrity | Protect ePHI from improper alteration | Input validation, access control on mutations | CWE-345 |
| (c)(2) Mechanism to authenticate ePHI (addressable) | Verify data has not been altered | HMAC, checksums, signed records | CWE-354 |
| (d) Person or Entity Authentication | Verify identity of persons seeking access | Authentication implementation quality | CWE-287, 306 |
| (e)(1) Transmission Security | Guard against unauthorized access in transit | TLS enforcement, no HTTP for health data | CWE-319 |
| (e)(2)(i) Integrity Controls (addressable) | Ensure ePHI not modified in transit | TLS, message authentication | CWE-319 |
| (e)(2)(ii) Encryption (addressable) | Encrypt ePHI in transit | TLS 1.2+ enforcement, certificate validation | CWE-295, 326 |

### 164.308 Administrative Safeguards (Code-Relevant Subset)

| Safeguard | Description | Code-Level Check |
|-----------|-------------|------------------|
| (a)(1)(ii)(D) | Information system activity review | Log review process, log aggregation implementation |
| (a)(3)(ii)(A) | Authorization and supervision | RBAC implementation for ePHI access |
| (a)(4)(ii)(B) | Access authorization | Authorization checks on ePHI endpoints |
| (a)(4)(ii)(C) | Access establishment and modification | User provisioning and deprovisioning implementation |
| (a)(5)(ii)(D) | Password management | Password policy, hashing |

### ePHI Identifiers: 18 Types to Detect in Code

The HIPAA Privacy Rule defines 18 identifier types that constitute Protected Health Information (PHI) when associated with health data:

| # | Identifier | Detection Patterns (variable names, field names, comments) |
|---|------------|-----------------------------------------------------------|
| 1 | Names | `patient_name`, `first_name`, `last_name`, `full_name`, `subscriber_name` |
| 2 | Geographic data (smaller than state) | `address`, `street`, `city`, `zip_code`, `postal_code`, `county` |
| 3 | Dates (except year) | `date_of_birth`, `dob`, `admission_date`, `discharge_date`, `death_date` |
| 4 | Phone numbers | `phone`, `telephone`, `mobile`, `fax`, `contact_number` |
| 5 | Fax numbers | `fax`, `fax_number` |
| 6 | Email addresses | `email`, `email_address`, `patient_email` |
| 7 | Social Security numbers | `ssn`, `social_security`, `social_security_number`, `ss_number` |
| 8 | Medical record numbers | `mrn`, `medical_record`, `medical_record_number`, `chart_number` |
| 9 | Health plan beneficiary numbers | `beneficiary_id`, `member_id`, `subscriber_id`, `plan_number` |
| 10 | Account numbers | `account_number`, `acct_no`, `patient_account` |
| 11 | Certificate/license numbers | `license_number`, `certificate_number`, `dea_number`, `npi` |
| 12 | Vehicle identifiers | `vin`, `vehicle_id`, `license_plate`, `plate_number` |
| 13 | Device identifiers | `device_id`, `serial_number`, `udi`, `device_identifier` |
| 14 | Web URLs | `url`, `web_address`, `patient_portal_url` |
| 15 | IP addresses | `ip_address`, `client_ip`, `source_ip` |
| 16 | Biometric identifiers | `fingerprint`, `retina`, `voiceprint`, `face_geometry`, `biometric` |
| 17 | Full-face photographs | `photo`, `photograph`, `face_image`, `patient_photo`, `headshot` |
| 18 | Any other unique identifier | `patient_id`, `unique_id`, `external_id`, `case_number` |

### ePHI Context Detection Keywords

Search for variables, fields, comments, and API endpoints containing:

```text
patient, diagnosis, treatment, prescription, medication, medical,
health, PHI, ePHI, HIPAA, clinical, provider, insurance, beneficiary,
SSN, DOB, MRN, ICD, CPT, procedure, lab_result, vital_sign,
allergy, immunization, encounter, referral, claim, eligibility,
prior_auth, preauthorization, discharge, admission, prognosis
```

### HIPAA Violation Patterns in Code

```python
# ePHI in logs (VIOLATION)
logger.info(f"Patient {patient.name} SSN: {patient.ssn}")
print(f"Processing record for {patient.full_name}")

# ePHI in URLs (VIOLATION)
requests.get(f"/api/patients?ssn={ssn}")
redirect(f"/patient/{patient_ssn}/records")

# ePHI in error messages returned to client (VIOLATION)
return JsonResponse({"error": f"Patient {name} not found"})

# ePHI stored without encryption (VIOLATION)
cursor.execute("INSERT INTO patients (ssn, diagnosis) VALUES (%s, %s)", (ssn, diagnosis))
# Missing: application-level encryption before storage

# ePHI transmitted without TLS (VIOLATION)
requests.get("http://api.hospital.com/patient/123")  # HTTP, not HTTPS
```

---

## SOC 2 (Trust Services Criteria)

Criteria: AICPA 2017 Trust Services Criteria with revised points of focus (2022),
https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 .
The 2022 revision changed only the points of focus, which are guidance, not requirements. Cite the
criterion ID (for example CC6.1); cite a point of focus only as supporting context.

### Common Criteria Relevant to Code

| Criteria | Description | Code-Level Check |
|----------|-------------|------------------|
| CC6.1 | Logical access security over protected information assets | Authentication and authorization implementation, encryption key handling |
| CC6.2 | Registration and authorization of new users | User registration flow security, approval before access |
| CC6.3 | Role-based access, least privilege, removal of access | RBAC implementation, permission checks before data access |
| CC6.6 | Restrict access from outside system boundaries | API authentication on all endpoints, network segmentation in IaC |
| CC6.7 | Restrict transmission and movement of data | TLS enforcement, no plaintext sensitive data |
| CC6.8 | Prevent or detect unauthorized or malicious software | Dependency integrity (lockfiles, hashes, provenance), no install hooks from untrusted packages |
| CC7.1 | Detect configuration changes and new vulnerabilities | Dependency and config scanning in CI, drift detection |
| CC7.2 | Monitor for anomalies | Alerting configuration, rate limiting, anomaly detection |
| CC7.3 | Evaluate security events | Incident response procedures (SECURITY.md, runbooks) |
| CC8.1 | Authorize, test and approve changes | Branch protection, required reviews, CI security gates, SHA-pinned actions |

### Additional Categories

| Criteria | Description | Code-Level Check |
|----------|-------------|------------------|
| A1.1 | Capacity meets demand | Auto-scaling configuration, resource limits |
| A1.2 | Environmental protections, backups | Backup implementation, disaster recovery config |
| A1.3 | Recovery testing | Backup restoration process, failover configuration |
| C1.1 | Confidential information identified and protected | Data classification in code, encryption for classified data |
| C1.2 | Confidential information disposed of | Secure deletion implementation, retention policies |
| PI1.2 | Processing integrity: inputs complete and accurate | Input validation, schema checks |
| PI1.3 | Processing integrity: processing complete and accurate | Transactional integrity, idempotency |
| PI1.4 | Processing integrity: outputs complete and accurate | Output validation |
| P1.1 | Privacy: notice | Privacy notice endpoint and versioning |
| P2.1 | Privacy: choice and consent | Consent capture and storage |
| P3.1 | Privacy: collection consistent with objectives | Data minimization in collection code |

### SOC 2 Code-Level Detection

```python
# Missing authentication on API endpoint (CC6.1 gap)
@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify(User.query.all())  # No auth check

# Should be:
@app.route('/api/users', methods=['GET'])
@require_auth
@require_role('admin')
def get_users():
    audit_log('user_list_accessed', current_user)
    return jsonify(User.query.all())

# Missing audit logging (CC7.2 gap)
def delete_user(user_id):
    User.query.get(user_id).delete()  # No logging
    db.session.commit()
```

---

## GDPR: General Data Protection Regulation

### Article 25: Data Protection by Design and Default

| Principle | Code-Level Check |
|-----------|------------------|
| Data minimization | Only collect necessary fields; no over-collection; SELECT specific columns, not SELECT * |
| Purpose limitation | Data used only for stated purpose; no repurposing without consent |
| Storage limitation | Data retention/deletion implementation; TTL on records; automated cleanup jobs |
| Integrity and confidentiality | Encryption, access controls, audit logging |
| Pseudonymization | Anonymization/pseudonymization of PII where possible; hashed identifiers |

### Article 32: Security of Processing

| Measure | Code-Level Check |
|---------|------------------|
| Encryption of personal data | Encryption at rest and in transit for PII fields |
| Confidentiality, integrity, availability | Access controls, input validation, redundancy/failover |
| Resilience of processing systems | Error handling, circuit breakers, graceful degradation, backup config |
| Regular testing and evaluation | Test suite covering security controls, security test cases |

### Data Subject Rights: Code Implementation Checks

| Right | Article | What to Check in Code |
|-------|---------|----------------------|
| Right to access | Art. 15 | Data export/download endpoint exists; returns all data held on subject |
| Right to rectification | Art. 16 | Data update endpoints for PII fields; user-accessible profile editing |
| Right to erasure ("right to be forgotten") | Art. 17 | Data deletion endpoint; cascading deletes across all stores; backup purge consideration |
| Right to restrict processing | Art. 18 | Ability to flag/pause processing of specific user records; processing status field |
| Right to data portability | Art. 20 | Data export in machine-readable format (JSON, CSV); downloadable by user |
| Right to object | Art. 21 | Opt-out mechanism implementation; marketing consent toggle; processing objection endpoint |
| Right not to be subject to automated decisions | Art. 22 | Human review mechanism for automated decisions; override capability |

### GDPR PII Detection Patterns

Search for fields, variables, database columns, and API parameters matching:

```text
# Direct identifiers
email, phone, address, name, surname, first_name, last_name,
full_name, username, user_name

# Government identifiers
dob, date_of_birth, ssn, social_security, passport, passport_number,
national_id, tax_id, drivers_license

# Location data
ip_address, ip, client_ip, location, gps, latitude, longitude,
geo, geolocation, coordinates, postal_code, zip_code

# Device/browser identifiers
cookie, session_id, device_id, fingerprint, user_agent,
advertising_id, idfa, gaid

# Financial
bank_account, iban, credit_card, card_number, billing_address

# Biometric / special category
biometric, fingerprint, face_id, health_data, genetic,
racial_origin, ethnic_origin, political_opinion,
religious_belief, sexual_orientation, trade_union
```

### GDPR Violation Patterns in Code

```python
# Over-collection (data minimization violation)
# Collecting fields not needed for the service
user_data = {
    'name': form.name,
    'email': form.email,
    'phone': form.phone,         # Not needed for newsletter
    'address': form.address,     # Not needed for newsletter
    'dob': form.date_of_birth,   # Not needed for newsletter
}

# No retention/deletion mechanism (storage limitation violation)
# Data stored indefinitely with no TTL or cleanup
db.users.insert(user_data)  # No expiry, no deletion job

# PII in logs (integrity/confidentiality violation)
logger.info(f"New user registered: {user.email}, {user.phone}")

# Missing consent tracking (lawfulness violation)
def subscribe_to_marketing(email):
    add_to_mailing_list(email)  # No consent record created

# Should include:
def subscribe_to_marketing(email, consent_source):
    record_consent(email, 'marketing', consent_source, datetime.utcnow())
    add_to_mailing_list(email)

# No data export endpoint (portability violation)
# API has no endpoint for users to download their data

# Missing cascading delete (erasure violation)
def delete_user(user_id):
    db.users.delete(user_id)
    # Missing: db.orders.anonymize(user_id)
    # Missing: db.logs.purge(user_id)
    # Missing: db.analytics.anonymize(user_id)
    # Missing: cache.invalidate(user_id)
    # Missing: search_index.remove(user_id)
    # Missing: third_party_api.request_deletion(user_id)
```

### GDPR Special Category Data (Article 9)

Extra protection required for:

- Racial or ethnic origin
- Political opinions
- Religious or philosophical beliefs
- Trade union membership
- Genetic data
- Biometric data (for identification)
- Health data
- Sex life or sexual orientation

**Code detection**: Search for field names, enums, or comments referencing these categories. If found, verify:

1. Explicit consent or legal basis documented
2. Higher encryption standard applied
3. Stricter access controls than standard PII
4. Separate storage/database consideration

---

## NIST SP 800-53 Release 5.2.0 (Federal Systems)

Source: https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls (2025-08-27).
Release 5.2.0 focuses on software development and deployment: resiliency by design, developer
testing, update management, and software integrity and validation.

### Controls added in 5.2.0

Exact control titles: confirm in the CPRT catalog linked from the source page before quoting them.

| Control | Topic (from the 5.2.0 scope) | Code-Level Check |
|---------|------------------------------|------------------|
| SA-15(13) | Development process and tools (logging) | Structured, consistent security-event logging built into the codebase (fields, formats) |
| SA-24 | Design for cyber resiliency | Fail-safe defaults, graceful degradation, no single component whose failure disables security controls |
| SI-02(07) | Flaw remediation (root cause) | Fixes address the root cause and variants, not one instance; regression tests for fixed vulns |

### Selected Controls Detectable in Code

| Control | Description | Code-Level Check |
|---------|-------------|------------------|
| AC-2 | Account Management | User lifecycle management (create, disable, delete) |
| AC-3 | Access Enforcement | Authorization checks on all protected resources |
| AC-6 | Least Privilege | Minimal permissions, no wildcard IAM, no `Bash(*)` in agent settings |
| AC-7 | Unsuccessful Logon Attempts | Account lockout or throttling after failed attempts |
| AC-12 | Session Termination | Session expiry |
| AU-2 | Event Logging | Security-relevant events logged |
| AU-3 | Content of Audit Records | Logs contain what, when, where, who, outcome |
| AU-9 | Protection of Audit Information | Log integrity, tamper protection |
| CM-7 | Least Functionality | Debug endpoints off, unused services removed |
| IA-2 | Identification and Authentication | MFA implementation |
| IA-5 | Authenticator Management | Password hashing (bcrypt/argon2), no hardcoded secrets |
| SA-11 | Developer Testing and Evaluation | Security tests and static analysis in CI |
| SC-7 | Boundary Protection | SSRF controls, network segmentation |
| SC-8 | Transmission Confidentiality and Integrity | TLS enforcement |
| SC-12 | Cryptographic Key Management | Key storage, rotation, destruction |
| SC-13 | Cryptographic Protection | Approved algorithms (AES-256, SHA-256+) |
| SC-28 | Protection of Information at Rest | Encryption at rest for sensitive data |
| SI-2 | Flaw Remediation | Dependencies on fixed versions; KEV matches fixed first |
| SI-7 | Software, Firmware and Information Integrity | Signed artifacts, verified downloads, provenance checks |
| SI-10 | Information Input Validation | Server-side validation on all inputs |
| SI-11 | Error Handling | No sensitive data in error messages |

---

## NIST SSDF (SP 800-218) v1.1

v1.1 is the final version. The 1.2 draft (https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) is not
final; do not cite its practice IDs as requirements.

| Practice | Description | Code-Level Evidence |
|----------|-------------|---------------------|
| PO.3 | Implement supporting toolchains | Security tools wired into CI (SAST, secret and dependency scanning) |
| PO.5 | Implement and maintain secure environments | CI with least-privilege tokens, SHA-pinned actions, no `pull_request_target` head checkout |
| PS.1 | Protect all forms of code from unauthorized access and tampering | Branch protection, CODEOWNERS on workflows, signed commits |
| PS.2 | Provide a mechanism to verify software release integrity | Signed releases, checksums, provenance, immutable releases |
| PS.3 | Archive and protect each software release | Release artifacts and SBOMs retained |
| PW.4 | Reuse existing, well-secured software | Maintained dependencies, lockfiles, no vendored stale copies (CA bundles, crypto) |
| PW.5 | Create source code by adhering to secure coding practices | The audit's vulnerability findings |
| PW.6 | Configure compilation and build processes securely | Hardened compiler flags, reproducible builds |
| PW.7 | Review and analyze code | Code review and static analysis evidence |
| PW.8 | Test executable code | Security tests, fuzzing |
| PW.9 | Configure software to have secure settings by default | Secure defaults (no debug, no wildcard CORS, strict TLS) |
| RV.1 | Identify and confirm vulnerabilities on an ongoing basis | Dependency monitoring, SECURITY.md with a reporting channel |
| RV.2 | Assess, prioritize and remediate vulnerabilities | Remediation queue, KEV and EPSS prioritization |
| RV.3 | Analyze vulnerabilities to identify root causes | Variant fixes, regression tests |

---

## NIST Cybersecurity Framework 2.0

Source: https://www.nist.gov/cyberframework . CSF 2.0 has six functions: Govern (GV), Identify
(ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC). Map code findings at the category level.

| Category | Code-Level Evidence |
|----------|---------------------|
| GV.SC Supply chain risk management | Dependency pinning, provenance, feed matches, CI action pinning |
| ID.AM Asset management | Manifests, SBOM, inventory of agent and MCP configs |
| ID.RA Risk assessment | This audit; vulnerability findings with severity |
| PR.AA Identity management, authentication and access control | Authn and authz findings |
| PR.DS Data security | Encryption, secret handling, PII in logs |
| PR.PS Platform security | Secure configuration, hardening, software integrity |
| PR.IR Technology infrastructure resilience | Network segmentation, resource limits |
| DE.CM Continuous monitoring | Logging and alerting implementation |
| RS.MA / RS.AN Incident management and analysis | SECURITY.md, runbooks, response-order notes |

---

## EU Cyber Resilience Act, Article 14 (`--compliance cra`)

Source: https://ncsc.gov.ie/cra/ . Reporting obligations have applied since **2026-09-11** to
manufacturers of products with digital elements placed on the EU market. Reports go through ENISA's
Single Reporting Platform, which routes them to the national CSIRT and ENISA.

| Event | Early warning | Notification | Final report |
|-------|---------------|--------------|--------------|
| Actively exploited vulnerability in the product | within 24 hours of awareness | within 72 hours of awareness | within 14 days after a corrective or mitigating measure is available |
| Severe incident affecting the product's security | within 24 hours of awareness | within 72 hours of awareness | within one month of the notification |

**What PYA reports (evidence only, never legal conclusions):**

| Check | Report when | Severity |
|-------|-------------|----------|
| KEV-matched or feed-flagged exploited component shipped in the product | A dependency or base image matches a KEV entry or a feed entry marked exploited | CRITICAL finding, plus a note: "If this product is on the EU market and the vulnerability is exploited in it, Art. 14 reporting clocks may apply (24h / 72h / 14 days)." |
| No vulnerability intake channel | No `SECURITY.md`, `security.txt` or documented reporting contact | MEDIUM compliance gap |
| No component inventory | No SBOM generation step and no lockfiles | MEDIUM compliance gap |
| No security update path | No documented update or release process for the product | LOW compliance gap |

Never tell the user they are or are not "CRA compliant". Report the evidence and the clock.

---

## OWASP ASVS 5.0.0

Source: https://github.com/OWASP/ASVS/tree/master/5.0/en . Cite requirements as
`v5.0.0-<chapter>.<section>.<requirement>` (for example `v5.0.0-1.2.5`), and only cite a
requirement number you have read in the source; otherwise cite the chapter (`v5.0.0-V8`).

| ASVS 5.0.0 Chapter | Key Topics | Maps to CWE | PYA agent |
|--------------------|-----------|-------------|-----------|
| V1 Encoding and Sanitization | Output encoding, injection prevention, safe deserialization | CWE-79, 89, 78, 94, 502 | vuln-scanner |
| V2 Validation and Business Logic | Input validation, business-logic limits, anti-automation | CWE-20, 840, 770 | logic-reviewer |
| V3 Web Frontend Security | CSP, cookies, browser security headers, third-party scripts and SRI | CWE-79, 1021, 829 | vuln-scanner |
| V4 API and Web Service | REST, GraphQL, WebSocket security, mass assignment | CWE-915, 284 | authz-reviewer |
| V5 File Handling | Upload validation, file storage, path traversal | CWE-434, 22 | vuln-scanner |
| V6 Authentication | Passwords, MFA, credential recovery | CWE-287, 306, 798 | authz-reviewer |
| V7 Session Management | Session timeout, fixation, termination | CWE-384, 613 | authz-reviewer |
| V8 Authorization | Access control, IDOR, least privilege | CWE-862, 863, 639, 284 | authz-reviewer |
| V9 Self-contained Tokens | JWT validation, signatures, audience and issuer checks | CWE-347, 287 | authz-reviewer |
| V10 OAuth and OIDC | Client, authorization server and resource server rules, PKCE, `iss` validation | CWE-346, 352, 601 | authz-reviewer, agentic-auditor (MCP OAuth) |
| V11 Cryptography | Algorithms, key management, random values | CWE-327, 326, 338 | vuln-scanner |
| V12 Secure Communication | TLS configuration, certificate validation | CWE-295, 319 | vuln-scanner, iac-scanner |
| V13 Configuration | Secure build and deploy, secrets management, unintended information leakage | CWE-16, 798, 200 | iac-scanner, secret-scanner |
| V14 Data Protection | Sensitive data classification, client-side storage, data minimization | CWE-311, 312, 532 | secret-scanner, vuln-scanner |
| V15 Secure Coding and Architecture | Dependency management, dangerous functionality, concurrency | CWE-1395, 829, 362 | dependency-auditor, logic-reviewer |
| V16 Security Logging and Error Handling | Security event logging, log protection, error handling | CWE-778, 532, 209 | logic-reviewer |
| V17 WebRTC | TURN, media and signaling security | CWE-284, 319 | vuln-scanner |

---

## Cross-Framework Mapping

Maps vulnerability findings to all applicable requirements at once. ASVS column gives the chapter.

| CWE | Vulnerability | PCI DSS 4.0.1 | HIPAA | SOC 2 | GDPR | NIST 800-53 | ASVS 5.0.0 |
|-----|--------------|---------------|-------|-------|------|-------------|------------|
| CWE-79 | Cross-Site Scripting | 6.2.4, 6.4.1 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V1, V3 |
| CWE-89 | SQL Injection | 6.2.4, 6.4.1 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V1 |
| CWE-78 | OS Command Injection | 6.2.4 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V1 |
| CWE-22 | Path Traversal | 6.2.4 | 164.312(a)(1) | CC6.1 | Art. 32 | AC-3 | V5 |
| CWE-287 | Improper Authentication | 8.3.1 | 164.312(d) | CC6.1 | Art. 32 | IA-2 | V6 |
| CWE-295 | Improper Certificate Validation | 4.2.1 | 164.312(e)(2)(ii) | CC6.7 | Art. 32 | SC-8 | V12 |
| CWE-311 | Missing Encryption | 3.5.1, 4.2.1 | 164.312(a)(2)(iv) | CC6.7 | Art. 32 | SC-28 | V14 |
| CWE-319 | Cleartext Transmission | 4.2.1 | 164.312(e)(1) | CC6.7 | Art. 32 | SC-8 | V12 |
| CWE-326 | Inadequate Encryption Strength | 3.5.1 | 164.312(e)(2)(ii) | CC6.7 | Art. 32 | SC-13 | V11 |
| CWE-327 | Broken Cryptographic Algorithm | 3.5.1 | 164.312(a)(2)(iv) | CC6.7 | Art. 32 | SC-13 | V11 |
| CWE-338 | Weak PRNG for secrets | 6.2.4 | 164.312(d) | CC6.1 | Art. 32 | SC-13 | V11 |
| CWE-352 | Cross-Site Request Forgery | 6.2.4 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V3 |
| CWE-434 | Unrestricted File Upload | 6.2.4 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V5 |
| CWE-502 | Unsafe Deserialization | 6.2.4 | 164.312(c)(1) | CC6.1 | Art. 32 | SI-10 | V1 |
| CWE-532 | Info Exposure Through Logs | 3.4.1 | 164.312(b) | CC7.2 | Art. 25 | AU-9, SI-11 | V16 |
| CWE-613 | Insufficient Session Expiration | 8.2.8 | 164.312(a)(2)(iii) | CC6.1 | Art. 32 | AC-12 | V7 |
| CWE-639 | Authorization Bypass (IDOR) | 6.2.4 | 164.312(a)(1) | CC6.3 | Art. 32 | AC-3 | V8 |
| CWE-778 | Insufficient Logging | 10.2.1 | 164.312(b) | CC7.2 | Art. 32 | AU-2 | V16 |
| CWE-798 | Hardcoded Credentials | 8.6.2 | 164.312(d) | CC6.1 | Art. 32 | IA-5 | V13 |
| CWE-829 | Untrusted third-party script or code | 6.4.3, 11.6.1 | 164.312(c)(1) | CC6.8 | Art. 32 | SI-7 | V3, V15 |
| CWE-918 | Server-Side Request Forgery | 6.2.4 | 164.312(c)(1) | CC6.6 | Art. 32 | SC-7 | V1 |
| CWE-1395 | Vulnerable Third-Party Component | 6.3.1, 6.3.2 | 164.308(a)(1) | CC7.1 | Art. 32 | SI-2 | V15 |

CRA: any CWE above in a component matched to KEV or an exploited feed entry also gets the Art. 14 note.
SSDF: every vulnerability finding is evidence under PW.5 (and PW.4 for components); CSF 2.0 maps by agent area as in its table.

---

## Compliance Reporting Format

When `--compliance` is used, append this section to the security audit report:

```markdown
## Compliance Assessment: [FRAMEWORK NAME AND VERSION]

Scope note: code-level evidence only. This is not a certification or legal opinion.

### Summary
- Requirements checked: XX
- Evidence of gap (FAIL): XX
- Evidence of control (PASS): XX
- Not applicable or not assessable from code: XX

### Requirement-by-Requirement Status

| Requirement | Status | Finding | Remediation |
|-------------|--------|---------|-------------|
| [Req ID] | PASS / FAIL / NA / NOT ASSESSABLE | [VULN-XXX if failed, or evidence location if passed] | [Fix guidance or N/A] |

### Critical Gaps
[FAIL items that would block an attestation]

### Recommendations
[Prioritized list of changes]
```

### Multi-Framework Report

When several targets are given (for example `--compliance pci --compliance hipaa`), generate a combined report:

```markdown
## Multi-Framework Compliance Assessment

### Cross-Framework Summary
| Framework | Version | Checked | PASS | FAIL | N/A |
|-----------|---------|---------|------|------|-----|
| PCI DSS | 4.0.1 | XX | XX | XX | XX |
| HIPAA | 164.312 (current) | XX | XX | XX | XX |
| SOC 2 | 2017 TSC (2022 PoF) | XX | XX | XX | XX |
| GDPR | 2016/679 | XX | XX | XX | XX |

### Shared Findings
[Findings that affect several frameworks: fix once, satisfy many]

### Framework-Specific Findings
[Findings unique to one framework]
```

### Compliance Evidence Collection

For each PASS, record the evidence:

```markdown
| Requirement | Evidence Type | Location | Details |
|-------------|--------------|----------|---------|
| PCI 6.2.4 (SQLi) | Code pattern | src/db/queries.ts:45 | Parameterized queries used throughout |
| PCI 6.4.3 | Config | app/checkout/layout.tsx:12 | Third-party scripts pinned with SRI, CSP script-src set |
| HIPAA 164.312(e)(1) | Configuration | lib/http-client.ts:12 | TLS 1.2 minimum enforced |
| SOC 2 CC7.2 | Implementation | src/middleware/logger.ts | Structured logging with audit events |
| GDPR Art. 17 | Endpoint | src/api/users/delete.ts | Cascading delete with third-party notification |
```
