# Rules of Engagement: Operation IRON THRESHOLD

**Program:** Meridian Defense Systems Red Team
**Engagement:** Operation IRON THRESHOLD
**Authorized by:** Chief Executive Officer, Meridian Defense Systems
**Engagement window:** Two weeks, dates set in the signed authorization
**Governing charter:** [CHARTER.md](CHARTER.md)

> This is a worked example. Meridian Defense Systems and Operation IRON THRESHOLD are
> fictional. The structure follows the rules-of-engagement requirements in Section 5 of the
> charter, and the attack steps are recorded by their real MITRE ATT&CK technique identifiers.

---

## 1. Objective

Reach the Program SENTINEL data enclave from an external starting point, and hold access long
enough to prove the objective, while the security operations center is not told the engagement
is running. The purpose is to measure whether the SOC detects the activity and whether a
detection leads to a response.

The measure of success is not whether the objective is reached. It is what the defenders did
about it.

## 2. Authorization

A signed authorization from the Chief Executive Officer, whose authority covers every system
named in scope, is on file before any activity begins. It names the authorized activity and the
exact two-week window. The red team lead and both operators carry a copy during any on-site
activity, so that a challenge from Meridian staff or security can be resolved immediately.

## 3. Scope

**In scope:**

- The Meridian corporate email environment, for the initial access attempt.
- The corporate Windows domain, endpoints, and identity systems.
- The Program SENTINEL data enclave, as the objective.

**Out of scope:**

- Any customer or partner network.
- Any production system supporting an active federal deliverable.
- Denial-of-service or availability-affecting techniques of any kind.
- Modification or destruction of any live mission data. Access is proven by demonstration,
  not by moving or changing data.

## 4. Permitted and prohibited techniques

**Permitted:** spearphishing for initial access, credential access, lateral movement,
collection, and a demonstrated exfiltration channel.

**Prohibited:** any denial of service, any destructive action, and any real exfiltration of
Program SENTINEL data. Reaching the objective is proven by a timestamped screenshot, not by
removing data from the enclave.

## 5. Timing

Activity runs during the two-week window only. A blackout applies during any real security
incident: if Meridian declares an unrelated incident, the red team pauses until the white cell
clears it, so the red team never complicates a genuine event.

## 6. Data handling

The objective is demonstrated, not exfiltrated. Any credentials or data touched during the
engagement are recorded only as needed for the report, stored under the same controls as their
source, and destroyed on a defined schedule after the report is delivered and accepted.

## 7. Emergency stop and deconfliction

- **Emergency stop.** The sponsor, the red team lead, or the white cell lead can halt the
  engagement immediately. On a stop call, the red cell ceases activity and confirms the stop
  to the white cell.
- **Deconfliction.** If the SOC escalates red cell activity as a suspected real intrusion, the
  white cell confirms to a named set of trusted agents that the activity is the engagement, so
  Meridian does not run a real incident response against a test. The white cell keeps an
  operations log of every red cell action to support this.

The trusted agents for Operation IRON THRESHOLD are the CISO, the SOC manager, and the white
cell lead. No one else on the blue side is told the engagement is running.

## 8. The engagement, step by step

Each step below is recorded by its MITRE ATT&CK technique identifier, and by what the SOC did.
This is the record the report and the metrics are built from.

| Step | ATT&CK technique | Action | SOC result |
|---|---|---|---|
| 1 | T1566.001 Spearphishing Attachment | An operator sends a crafted attachment to a target in the corporate email environment | Missed |
| 2 | T1059.001 PowerShell | The payload runs a PowerShell stage on the endpoint | Detected, no response |
| 3 | T1547.001 Registry Run Key | The operator sets persistence through a run key | Missed |
| 4 | T1003.001 LSASS Memory | The operator reads credentials from memory | Detected and escalated |
| 5 | T1021.002 SMB Admin Shares | The operator moves laterally using admin shares | Missed |
| 6 | T1005 Data from Local System | The operator reaches the Program SENTINEL enclave and proves access | Missed |
| 7 | T1048 Exfiltration Over Alternative Protocol | The operator demonstrates an exfiltration channel | Detected, after the objective |

At step 4, the SOC escalated the credential-access alert as a possible real intrusion. The
white cell deconflicted, confirmed it was the red team to the three trusted agents, and the
engagement continued. This is the emergency-stop and deconfliction path in Section 7 working
as intended.

## 9. The result

- Techniques executed: 7.
- Techniques detected: 3, which is a detection rate of about 43 percent.
- Techniques that led to a response: 1. The SOC detected the credential access at step 4 but
  did not contain it.
- The objective was reached at step 6 without detection.

The finding is not that Meridian has no detection. It is that detection was not followed by
response. The SOC saw enough to act at step 4 and did not. That gap, not the count of alerts,
is what the engagement exists to surface, and it maps directly to the Respond Function of the
NIST Cybersecurity Framework. The prioritized recommendation is to build a response playbook
tied to the credential-access alert that already fired.
