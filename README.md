# Red Team Program Charter

A worked example of how a red team program is designed and governed, written to demonstrate
program-design skill rather than a single technical finding. It is built around a fictional
cleared defense contractor, Meridian Defense Systems, and one worked engagement that shows the
charter's rules doing their job.

The organization is fictional. The frameworks, controls, and standards are real, and every
citation was checked against its primary source.

## What is here

- [docs/CHARTER.md](docs/CHARTER.md) is the twelve-section program charter: mission, authority,
  program type, scope, rules of engagement, engagement lifecycle, deconfliction, framework
  alignment, metrics, ethics and legal, team structure, and governance.
- [docs/ROE-OPERATION-IRON-THRESHOLD.md](docs/ROE-OPERATION-IRON-THRESHOLD.md) is a full rules-of-
  engagement document for one worked engagement, including the step-by-step attack path mapped
  to MITRE ATT&CK and what the defenders detected at each step.

## The worked engagement

Operation IRON THRESHOLD runs an adversary emulation from an external start to a crown-jewel
data enclave, while the security operations center is not told it is happening. Across seven
ATT&CK techniques the defenders detected three and responded to one. The objective was reached
undetected. The finding is that detection was not followed by response, which is a specific,
common, and fixable gap that maps to the Respond Function of the NIST Cybersecurity Framework.

## Frameworks referenced

NIST SP 800-53 Rev 5 (CA-8 Penetration Testing and CA-8(2) Red Team Exercises), NIST SP
800-115 (four-stage testing methodology), NIST Cybersecurity Framework 2.0 (six Functions),
MITRE ATT&CK and MITRE ATLAS, DoD Instruction 8585.01 (DoD Cyber Red Teams), CREST red team
certifications, and the Computer Fraud and Abuse Act. Primary-source links are in the charter.

## What this demonstrates

Standing up and governing a red team program: setting its authority and scope, writing rules of
engagement that hold up legally, running the deconfliction that keeps a test from being mistaken
for a real intrusion, mapping engagements to the frameworks an employer is audited against, and
reporting the result in a way an executive can act on.
