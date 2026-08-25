# Security program design

Seven written pieces about running a security function rather than performing a
technical task: how a program is chartered, what it reports upward, how work gets
prioritised, and how a capability moves from idea to production to retirement.

These are documents, not tools. They exist because the job of a senior person is
usually to design the process, not to run the scanner.

## The projects

| Project | What it does |
|---|---|
| [redteam-program-charter](redteam-program-charter/) | How a red team program is designed and governed, built around a worked fictional organisation. |
| [abuse-program-charter](abuse-program-charter/) | The same for a trust and safety abuse-detection program: scope, authority, escalation, and what it refuses to do. |
| [abuse-program-metrics](abuse-program-metrics/) | What such a program reports upward every month, and why those measures rather than the flattering ones. |
| [detection-engineering-lifecycle](detection-engineering-lifecycle/) | How a detection goes from idea to production to retirement: authoring, testing, tuning, measuring, deprecating. |
| [threat-intel-requirements](threat-intel-requirements/) | The management layer above analysis: who decides what gets collected, how source quality and analytic confidence are expressed. |
| [ransomware-readiness](ransomware-readiness/) | A readiness assessment: what an organisation needs in place before an incident, not after one. |
| [portfolio-map](portfolio-map/) | How the projects across this portfolio connect, and how many of them do not. |

## How to read these

Each charter is built around a fictional organisation so the scope, authority and
escalation paths are concrete rather than generic. The metrics piece is the one
worth reading first if you only read one, because it argues for reporting the
measures that make a program look worse and explains why that is the point.

`portfolio-map` is the odd one out. It is an audit of this portfolio itself,
including the projects that connect to nothing.

## What none of this claims

- These are worked examples, not documents from a real organisation. No employer
  process, policy, or internal document is reproduced here.
- The fictional organisations are fictional. Any resemblance to a real program's
  structure is because the structures are conventional, not because they were
  copied.
- Nothing here has been run against a real team, so none of it carries evidence
  that it survives contact with one.
