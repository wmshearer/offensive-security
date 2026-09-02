# WPA3 versus WPA2: what actually changed for offline password cracking

WPA3 was marketed as the fix for offline dictionary attacks against Wi-Fi
passwords. This project checks that claim against what the Wi-Fi Alliance's
own page says, what the peer-reviewed research that broke parts of WPA3
actually found, and what the two protocols' captured frames look like side by
side.

## Scope, stated up front

This is protocol and documentation analysis, not a live wireless assessment.
A job posting that prompted this work asks for live wireless assessments, and
this project does not do that. Live radio work (capturing traffic from a real
network, deauthentication, injection, WPS attacks, evil twin) was out of scope
for this environment on purpose: this machine has a `wlan0` interface
associated with a home network, and touching it, capturing from it, or
attacking any real network was never on the table. The question was narrowed
instead to what can be established from six published test captures
(distributed by the aircrack-ng project specifically for testing) and from
primary sources: the Wi-Fi Alliance's own security page, the Dragonblood
paper, NVD/MITRE's CVE records, and the original 2018 PMKID disclosure post.
That is a real, useful, and different skill from a live assessment, and this
README says so plainly rather than implying otherwise.

## The claim gap

The Wi-Fi Alliance's page (https://www.wi-fi.org/discover-wi-fi/security)
says WPA3-Personal users "receive increased protections from password
guessing attempts." That is a comparative claim against WPA2, not a claim
that offline cracking became impossible. The stronger language repeated
across vendor blogs and press coverage, that WPA3 closes offline cracking
outright, is not what the Alliance's own page says.

The Dragonblood paper (Vanhoef and Ronen, IEEE S&P 2020) found that specific
implementations of WPA3's SAE handshake leaked timing and cache side-channel
information that let an attacker recover the password anyway, offline, for
about $1 of cloud compute against a 10-billion-entry dictionary once the leak
narrowed the search space. Six CVEs came out of that disclosure
(CVE-2019-9494 through CVE-2019-9499), all confirmed here directly against
NVD, not against the paper's own text or a blog summary.

At the frame level, WPA3-Personal still runs WPA2's four-way handshake after
its SAE exchange completes. What changed is what feeds that handshake: SAE
derives a high-entropy shared secret from the password before the four-way
handshake starts, instead of feeding the password straight into it. That is a
real architectural improvement, and it is also a narrower claim than "offline
cracking is fixed."

Full detail, with every figure traced to a script or source: [FINDINGS.md](FINDINGS.md).

## Definitions

- **WPA2 / WPA3**: Wi-Fi Protected Access, the certification for securing
  Wi-Fi network traffic. WPA3 is the newer generation, certified starting
  2018.
- **Four-way handshake**: the four-message exchange a WPA2 client and access
  point use to prove they both know the network password and to derive a
  fresh encryption key for the session, without ever sending the password
  itself over the air.
- **Nonce**: a random number used once, so the same inputs never produce the
  same handshake twice. WPA2's handshake exchanges an ANonce (from the access
  point) and an SNonce (from the client).
- **MIC (Message Integrity Code)**: a short cryptographic checksum included
  in handshake messages 2 through 4, computed using key material derived from
  the password. Checking a guessed password against a captured MIC offline is
  the basis of the standard WPA2 cracking attack.
- **SAE (Simultaneous Authentication of Equals)**: the password-authenticated
  key exchange WPA3-Personal uses instead of feeding the password directly
  into the four-way handshake. Based on the Dragonfly protocol.
- **PMKID (Pairwise Master Key Identifier)**: an optional field some access
  points include in the first frame of the WPA2 handshake, originally meant
  to help clients roam between access points faster. If present and usable,
  it lets an attacker skip waiting for a client to connect.
- **Offline dictionary attack**: capturing a handshake once, then trying
  candidate passwords against it without touching the network again.

## Layout

```
README.md      This file: the claim gap, stated up front.
FINDINGS.md     Every figure traced to a script, evidence file, or primary source.
captures/       The six aircrack-ng test files this project analyzes, plus a README
                explaining how to re-fetch them if the directory is ever empty.
scripts/        Numbered, idempotent tshark scripts that produce the evidence/ files.
evidence/       Raw dissection output and fetched source text.
evidence/gui/   Real Wireshark 4.6.6 GUI screenshots of the handshakes and PMKID.
tests/          pytest suite. Skips (not fails) when a capture file is absent.
```

## Reproducing the analysis

```bash
cd wireless-protocol-analysis
bash scripts/01_dissect_wpa2_handshake.sh
bash scripts/02_dissect_wpa3_sae.sh
bash scripts/03_check_pmkid.sh
python3 -m pytest tests/ -v
```

All three scripts read from `captures/` and write to `evidence/`. If
`captures/` is empty, see `captures/README.md` for how to re-fetch just the
`test/` subtree of the aircrack-ng repository (sparse checkout, not the full
project).

## What this project does not do

No deauthentication, no beacon injection, no evil twin, no monitor mode, no
WPS attack, and no capture of live traffic from any network, including the
machine's own. No attack tooling was run against any interface. Everything
here reads static, published test files or fetches public documentation.
