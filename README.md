# Automated Web Vulnerability Scanner & Visual Report Generator

## 1. Project Proposal
**Overview:**
This project aims to build a custom Web Pentesting Tool designed to automatically scan target URLs and detect common web vulnerabilities. Instead of relying on existing automated tools, the scanner will manually implement the request logic, payload injection, and response analysis.

**Objectives:**
* Develop a core pentesting engine from scratch to simulate real-world penetration testing methodologies.
* Detect a selected set of high-impact web vulnerabilities (exact vulnerabilities to be finalized during the analysis phase).
* Provide a visual interactive timeline representing the attack flow (Request -> Payload -> Response -> Impact).
* Automatically generate a professional, structured security report based on the scan findings.
* Develop a Dummy Vulnerable Web Application to safely demonstrate and test the scanner's capabilities.

---

## 2. Project Plan & Timeline
The project follows the official deadlines:
* **Phase 1: Project Planning & Management** - Deadline: Feb 20, 2026
* **Phase 2: Literature Review & Requirements Gathering** - Deadline: Apr 20, 2026
* **Phase 3: System Analysis & Design** - Deadline: May 1, 2026
* **Phase 4: Implementation (Source Code)** - Deadline: Jul 10, 2026
* **Phase 5: Final Presentation & Testing** - Deadline: Jul 17, 2026

---

## 3. Task Assignment & Roles
*(Note: Roles will be adapted as the project progresses)*

1. **Team Member 1 (Backend & Core Engine Developer):** Responsible for developing the core pentesting engine, handling HTTP requests, and response parsing.
2. **Team Member 2 (Security Analyst):** Responsible for researching vulnerabilities, crafting custom payloads, and validating exploitation logic.
3. **Team Member 3 (Vulnerable App Developer):** Responsible for building the intentional Dummy Vulnerable Web Application for safe testing.
4. **Team Member 4 (Frontend & Visualization):** Responsible for building the visual interactive timeline that illustrates the attack flow.
5. **Team Member 5 (Reporting & Documentation Lead):** Responsible for the Automated Report Generator module and maintaining project documentation.
6. **Team Member 6 (Quality Assurance & Integration):** Responsible for testing the scanner against the dummy app, reporting bugs, and ensuring smooth integration between modules.

---

## 4. Risk Assessment & Mitigation Plan 
| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Scanner Blocked by WAF** | High | Test strictly against the local Dummy Vulnerable Application to avoid external network blocks. |
| **False Positives/Negatives** | High | Implement strict validation rules and manual verification logic to ensure accurate detection. |
| **Integration Issues** | Medium | Conduct weekly code reviews and use GitHub for continuous version control and testing. |

---

## 5. Key Performance Indicators (KPIs) 
* **Detection Accuracy:** High success rate in detecting the targeted vulnerabilities within the dummy application with minimal false positives.
* **Scan Efficiency:** Optimized response time during the automated scanning process.
* **Reporting Quality:** Generation of a clear, actionable, and structured Markdown report directly after the scan completes.