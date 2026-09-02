# Captures

These six files come from the aircrack-ng project's `test/` directory, used here
under GPL-2.0 for protocol analysis (never for an attack against a live network).
Source: https://github.com/aircrack-ng/aircrack-ng, commit
`115693aa2abf44616ed0272f8d450baa8793756c`.

- `test-pmkid.pcap` — a single EAPOL frame carrying a usable PMKID.
- `pmkid-not-recognized.cap` — a 20,056-frame capture that includes PMKID KDE
  bytes aircrack-ng does not treat as usable (negative control; see
  FINDINGS.md for why).
- `wpa2.eapol.cap` — a WPA2 four-way handshake.
- `wpa3-psk.pcap` — a WPA3-SAE authentication exchange followed by the
  four-way handshake it feeds into.
- `wpa.cap`, `wpa2-psk-linksys.cap` — additional WPA/WPA2 reference captures,
  not otherwise cited in FINDINGS.md.

Total size is about 1.5 MB, small enough to commit directly, so these files
are tracked in git rather than gitignored.

## Re-fetching

If this directory is ever empty, pull just the `test/` subtree instead of the
full repository:

```bash
mkdir aircrack-sparse && cd aircrack-sparse
git init -q
git remote add origin https://github.com/aircrack-ng/aircrack-ng.git
git config core.sparseCheckout true
mkdir -p .git/info
echo "test/*" > .git/info/sparse-checkout
git fetch --depth 1 origin master
git checkout master
cp test/test-pmkid.pcap test/pmkid-not-recognized.cap test/wpa2.eapol.cap \
   test/wpa3-psk.pcap test/wpa.cap test/wpa2-psk-linksys.cap \
   /path/to/wireless-protocol-analysis/captures/
```
