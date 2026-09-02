# Findings: WPA3, offline cracking, and what actually changed

Every number and quote below is traced to a named script, evidence file, or
primary source. Nothing here comes from memory of a source or a summary of a
source; each claim was checked against the source text itself.

## 1. What the Wi-Fi Alliance actually says about WPA3-Personal

Source: https://www.wi-fi.org/discover-wi-fi/security, fetched 2026-08-28. The
WPA3 tab's body text, verbatim:

> WPA3 offers cutting-edge security protocols, simplifying Wi-Fi security,
> enabling more robust authentication, delivering increased cryptographic
> strength for highly sensitive data markets, and maintaining the resiliency
> of mission-critical networks.
>
> WPA3 is mandatory for Wi-Fi CERTIFIED devices and includes additional
> capabilities specifically for personal and enterprise networks. Users of
> WPA3-Personal receive increased protections from password guessing
> attempts, while WPA3-Enterprise users can now take advantage of
> higher-grade security protocols for sensitive data networks.
>
> WPA3 networks:
> - Use the latest security protocols
> - Disallow outdated legacy protocols
> - Require use of Protected Management Frames (PMF)

The page never claims WPA3 prevents offline cracking, is uncrackable, or
closes the gap that made WPA2 dictionary attacks practical. Its strongest
statement about the Personal mode is "increased protections from password
guessing attempts," a comparative claim (better than WPA2), not an absolute
one. The three "WPA3 networks" bullets describe protocol hygiene (current
ciphers, no legacy fallback, mandatory management frame protection), not a
specific claim about resisting offline dictionary attacks. The stronger
language repeated across vendor blogs and news coverage is not on this page.
It is an amplification that happened elsewhere.

Raw fetch: `evidence/wifi_alliance_security_page.txt`.

## 2. The Dragonblood paper's claims, and the CVE IDs checked against NVD

Source: Vanhoef, M. and Ronen, E., "Dragonblood: Analyzing the Dragonfly
Handshake of WPA3 and EAP-pwd," IEEE Symposium on Security and Privacy, 2020.
https://papers.mathyvanhoef.com/dragonblood.pdf

Read directly from the PDF:

- WPA3-SAE (Simultaneous Authentication of Equals, the password-authenticated
  key exchange WPA3-Personal uses instead of WPA2's PSK-only four-way
  handshake) is meant to prevent offline dictionary attacks and provide
  forward secrecy (Section 2.1).
- The paper finds timing and cache-access side channels in specific
  implementations of SAE and EAP-pwd (the enterprise variant of Dragonfly)
  that leak information usable to brute-force the password offline (Abstract,
  Sections 6 and 7).
- Estimated cost once the side channel narrows the search space: brute-forcing
  a dictionary of size 10^10 "requires less than $1 in Amazon EC2 instances"
  (Abstract).
- The paper does not list CVE numbers in its body text. It points to a
  CERT/CC advisory: reference [17], "Vulnerability Note VU#871675: Security
  issues with WPA3," https://www.kb.cert.org/vuls/id/871675.

CVE IDs, checked against the NVD REST API
(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`), fetched
2026-08-28, and cross-checked against the CERT/CC advisory text (both list the
same six IDs):

| CVE | NVD status | Covers |
|---|---|---|
| CVE-2019-9494 | confirmed | SAE timing/cache side channels in hostapd/wpa_supplicant enabling full password recovery |
| CVE-2019-9495 | confirmed | EAP-pwd cache-access side channel in hostapd/wpa_supplicant |
| CVE-2019-9496 | confirmed | SAE confirm-message state validation bug crashing hostapd (denial of service) |
| CVE-2019-9497 | confirmed | EAP-pwd scalar/element validation bypass, hostapd/wpa_supplicant (auth bypass) |
| CVE-2019-9498 | confirmed | Same validation-bypass class, hostapd EAP server, crypto-library-dependent |
| CVE-2019-9499 | confirmed | Same validation-bypass class, wpa_supplicant EAP peer, crypto-library-dependent |

All six IDs are real, assigned, and match CERT/CC's and NVD's descriptions.
CVE-2019-9494 is the one most relevant to the "WPA3 fixes offline cracking"
claim: it is a side channel in SAE itself (not the enterprise-only EAP-pwd),
and NVD's description says an attacker can use the leak "for full password
recovery." That is the direct rebuttal to "WPA3-Personal prevents offline
password recovery": in real implementations, it did not, because the
implementation leaked enough side-channel information to run the equivalent
of an offline attack against the narrowed password space.

Raw fetch: `evidence/nvd_cve_lookups.txt`.

## 3. The frame-level difference: what a WPA2 handshake exposes that WPA3-SAE does not

### WPA2 four-way handshake

Source: `captures/wpa2.eapol.cap` (4 EAPOL frames). Dissected with
`scripts/01_dissect_wpa2_handshake.sh`, output in
`evidence/wpa2_handshake_fields.txt`. GUI evidence:
`evidence/gui/01-wpa2-eapol-message1-anonce.png`,
`evidence/gui/02-wpa2-eapol-message2-snonce-mic.png`.

| Frame | Message | Nonce | MIC |
|---|---|---|---|
| 2 | 1 of 4 | ANonce (AP to station) | all-zero (no MIC computed yet) |
| 3 | 2 of 4 | SNonce (station to AP) | d5355382b8a9b806dcaf99cdaf564eb6 |
| 4 | 3 of 4 | ANonce repeated | 1e228672d2dee930714f688c5746028 |
| 5 | 4 of 4 | zeroed | 9dc81ca6c4c729648de7f00b436335c |

The MIC in messages 2 through 4 is what an offline dictionary attack targets.
An attacker who has captured this handshake guesses a candidate password,
derives the same key material the real client and AP derived from it plus the
two nonces, computes a MIC over the same handshake frame, and checks it
against the captured MIC. No further interaction with the network is
required. That is the standard WPA2 handshake-capture-and-crack attack, and
the reason a long, high-entropy WPA2 passphrase matters.

### WPA3 SAE Commit and Confirm

Source: `captures/wpa3-psk.pcap` (24 frames: beacon, probe, SAE Commit x2, SAE
Confirm x2, association, then a 4-way handshake). Dissected with
`scripts/02_dissect_wpa3_sae.sh`, output in `evidence/wpa3_sae_fields.txt`.
GUI evidence: `evidence/gui/03-wpa3-sae-commit.png`,
`evidence/gui/04-wpa3-sae-confirm.png`.

Frame 5 (SAE Commit, the first message) carries:

- Authentication Algorithm: Simultaneous Authentication of Equals (SAE)
- SAE Message Type: Commit
- Group Id: 256-bit random ECP group
- Scalar: 8080dbcb2b1f75d49e64a12e85cdfa3a325c2631f630cb49988487c0c41c39e5
- Finite Field Element:
  6a2ed8799140e2637b7e0fcf0ac8cf755b27b18071fa776388f9ad63b489683d71f020c4a83cf6b8a46df7f124803725c0e24dda0347f2e2b11e7b892460586f

There is no ANonce/SNonce/MIC structure here. The Scalar and Finite Field
Element are elliptic-curve values from the Dragonfly key exchange (Dragonblood
Section 2.1.2 and Figure 1 name these s_i and E_i). The password is folded
into the elliptic-curve point derivation ("hash-to-curve," Dragonblood Section
2.1.1) before any exchange happens, so confirming a password guess against a
captured Commit/Confirm pair requires either breaking the underlying
discrete-log problem or, per Dragonblood, exploiting an implementation-
specific side channel in that password-to-point derivation. That is the real
mechanism behind "WPA3 resists offline dictionary attacks against a captured
handshake," and it is exactly the mechanism Dragonblood shows breaking down in
specific implementations.

Frame 9 (SAE Confirm) carries a Confirm HMAC value
(2a9f898a9e6d80764926ba863e278134927ec29d125aeec7dadfd0a7b0a64042, called
tr in Dragonblood's notation) rather than a MIC computed the WPA2 way. It
proves both sides reached the same result; it is not a value directly
attackable offline the way a captured WPA2 MIC is.

After SAE succeeds, wpa3-psk.pcap shows the same four-message EAPOL exchange
WPA2 uses (frames 17-23), with the same nonce/MIC field structure (see
evidence/wpa3_sae_fields.txt). This is the detail marketing framing usually
skips: WPA3-Personal still runs WPA2's four-way handshake. What changed is
what feeds it. In WPA2, the pairwise master key is derived directly from the
password (PBKDF2 over the passphrase and SSID), so a captured handshake plus a
guessed password checks offline. In WPA3, SAE first derives a high-entropy
shared secret through the Dragonfly exchange, and that shared secret, not the
password, feeds the four-way handshake. The four-way handshake's frame format
is unchanged; its input key material is no longer directly derivable from a
password guess, provided SAE itself has no exploitable weakness, which is
exactly the assumption Dragonblood breaks in specific implementations.

## 4. The NCC Group PMKID / 802.11r claim: the pcap test does not reach it, the primary sources do

The task's secondary lead: "NCC Group published a claim that PMKID attacks do
NOT require 802.11r," to verify structurally against test-pmkid.pcap versus
pmkid-not-recognized.cap and against the original hashcat disclosure.

**The structural pcap comparison does not bear on the 802.11r question.** I
ran it anyway since the task asked for it, and it surfaced a different,
independently verifiable structural fact.

### What the two captures actually show

test-pmkid.pcap contains one EAPOL message-1 frame with:
- PMKID: c2ea9449c142e84a0479041702526532
- Key Descriptor Version: 2 (AES Cipher, HMAC-SHA1 MIC)

pmkid-not-recognized.cap (20,056 frames total) contains three EAPOL
message-1 frames (numbers 16798, 18420, 19945) that also carry a full 16-byte
PMKID KDE, but each has:
- Key Descriptor Version: 0 (Unknown)

Wireshark dissects both the same way; the PMKID bytes are present and
well-formed in all four frames. The difference is the Key Descriptor Version
field. Checked against aircrack-ng's own source (same commit as the test
captures, 115693aa2abf44616ed0272f8d450baa8793756c,
src/aircrack-ng/aircrack-ng.c, around line 1662):

```c
if (key_descriptor_version > 0
    && memcmp(ZERO, &p[pos], 16) != 0)
{
    // Got a PMKID value?!
    memcpy(st_cur->wpa.pmkid, &p[pos], 16);
    ...
}
```

aircrack-ng only accepts a PMKID when key_descriptor_version > 0. The
negative control's frames have version 0, so aircrack-ng's own parser skips
them regardless of the PMKID bytes being otherwise valid. That is what "not
recognized" means for this file: not "no PMKID present," but "present, and
rejected by this specific version check in this specific tool." Neither frame
set carries an FT information element or FT AKM suite, so this comparison
cannot speak to the 802.11r question either way. Evidence:
scripts/03_check_pmkid.sh, output in evidence/pmkid_comparison.txt. GUI
evidence: evidence/gui/05-pmkid-positive.png,
evidence/gui/06-pmkid-negative-control.png.

### What the primary sources say about 802.11r

**Atom's original 2018 hashcat.net disclosure**
(https://hashcat.net/forum/thread-7717.html, "New attack on WPA/WPA2 using
PMKID," posted by hashcat lead developer Jens "Atom" Steube), verbatim:

> At this time, we do not know for which vendors or for how many routers this
> technique will work, but we think it will work against all 802.11i/p/q/r
> networks with roaming functions enabled (most modern routers).

This is the origin of the 802.11r association, and reading it directly shows
it was never a strict requirement. Atom listed four amendments (802.11i, p, q,
r) together as roaming-related and hedged with "we think" and "at this time,
we do not know." The word "require" does not appear. The 802.11r-only version
of the advice hardened after this post; the post itself did not assert it.

**NCC Group**
(https://www.nccgroup.com/research/pmkid-attacks-debunking-the-80211r-myth/,
fetched 2026-08-28), verbatim from the introduction:

> Over time, a prevalent misconception has emerged, suggesting that the
> attack is feasible only on networks with 802.11r Fast Transition (FT)
> enabled. However, the actual vulnerability arises from the way an access
> point handles PMKID requests rather than the specific presence of 802.11r.

This lines up with what Atom's post actually said: an association with
roaming-capable networks in general, not a hard 802.11r dependency.

**Verdict: the core claim (PMKID attacks do not strictly require 802.11r) is
corroborated by the primary source it corrects.** Atom's own 2018 post never
made 802.11r a requirement. What I could NOT confirm from a primary source,
and report as unconfirmed, is NCC Group's more specific mechanism claim ("the
actual vulnerability arises from the way an access point handles PMKID
requests"). That is NCC Group's own analysis. I have not independently
verified it against the 802.11 standard text or a live access point, which
the hard constraints on this project rule out, and the structural pcap test
cannot speak to it because neither test capture contains an FT information
element. Treat that specific mechanism claim as NCC Group's assertion, not as
something this project independently confirmed.

## Scope

This analyzes six published, GPL-2.0-licensed test captures and three primary
sources (a vendor page, a peer-reviewed paper, and an original vulnerability
disclosure post). It performs no live wireless capture, deauthentication,
injection, or cracking against any real network. See README.md for the full
scope statement.
