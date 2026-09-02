# Confirming a finding is real before acting on it

A scanner naming three CVEs is a list of things to check, not a list of things
that are true. Sorting one from the other is most of the work.

This is a synthesis of what I already did across twelve penetration-testing
walkthroughs, not a framework I read and applied afterwards. Every claim below
cites the step that produced it, and a script checks those citations still point
where they say they do.

## The eight checks

### 1. Prove the primitive by hand before reaching for a module

Orion ran Yii, which parses an array with a class key as an object config. Before
using a Metasploit module for the rest of the chain, I sent one object-injection
POST pointed at `phpinfo()`. That confirms execution and nothing more.

The version banner said the CVE applied. Reaching `phpinfo()` proved it did.

Where the manual work stopped and the tool took over is stated in the walkthrough
rather than blended together, because those are different claims.

### 2. Get an out-of-band callback when there is no output

Abducted's print handler ran server side with no return channel. A blind
injection returns the same page whether it worked or not.

So the payload was a ping back to my own box with `tcpdump` watching for it. The
ICMP arriving is the proof. Nothing else about the target had to change, and no
shell was committed to until after the callback landed.

### 3. Check the precondition before spending effort on the exploit

The most common check in the set, appearing across five walkthroughs.

- Snapped: is snapd inside the vulnerable version range
- Support: is the machine account quota above zero, because RBCD needs to add a computer account
- Support: is this host actually the PDC, before building a path around that assumption
- Kobold: does a snap layout bind-mount exist at all

Every one of these is cheaper than the exploit it guards. That is the whole
argument for doing them.

### 4. Rule out the scanner's false positives

Kobold is the clearest case. linpeas named three CVEs. Two did not survive a
prerequisite check: no snap mount existed for the first, and the kernel modules
the second needed were not reachable in a way that held up. The third was real.

Firing all three would have found the same answer. Checking first meant one
exploit attempt instead of three, against a box where two of them could not have
worked.

### 5. Confirm the write actually took effect

TwoMillion's admin endpoint returned 200. A 200 means the request was accepted,
not that anything changed. Reading the state back returned `{"message": true}`,
which is what actually proved the privilege change.

Support does the same after configuring delegation, reading it back through both
the normal cmdlet and the raw attribute.

### 6. Confirm a recovered value two independent ways

Support recovered a credential by decompiling a binary. Static analysis can be
misread, so the same credential was watched going past on the wire during a real
LDAP bind under Wine.

Two structurally different methods produced the same value. If they had
disagreed, that disagreement would have been the finding.

### 7. Establish the baseline first

Helix controls a reactor. Before changing anything, I ran the command cold and
recorded what it said with the maintenance window closed.

Without that, a later success cannot be told apart from a starting condition that
was already true. Cap does the same thing more simply: download my own capture
first, so another user's capture is recognisable as someone else's.

### 8. Try the simple case before assuming the complicated one

Ghostlink's traversal filter got the naive `../` pattern first. It returned 403.
That result is what justified trying double encoding, rather than starting there
and never learning what the filter actually did.

TwoMillion checks whether access control works on a different endpoint before
concluding the settings bypass is a real bug. Cap tries anonymous FTP before
looking anywhere else.

## What this set does not show

Every validation moment across the twelve walkthroughs is preventive. Something
was checked before acting.

None of them is corrective. There is no moment where an assumption was made,
turned out wrong, and the approach changed as a result. Real engagements produce
those constantly. These do not, because a documented reconstruction of a solved
machine has the answer available throughout, which removes exactly the condition
that produces a wrong turn.

Out-of-band confirmation appears once, and only over ICMP. There is no DNS
callback anywhere in the set.

Scanner false positives are concentrated almost entirely in one walkthrough.

I would rather state that than imply a broader habit than the evidence supports.

## Scope

These are retired HackTheBox machines, reconstructed from the official published
solutions. The validation reasoning and the citations are real. The engagements
were lab work, not client assessments, and nothing here should be read as a claim
otherwise.

## Checking this page

`python3 src/verify_citations.py` reads every row in `docs/evidence.json`, opens
the case-study source, and confirms the cited lines contain the step title the
row claims. It exits non-zero if any row has drifted.

The research pass behind this page proposed 35 moments. Two did not survive that
check: one was a duplicate of another row filed under the wrong walkthrough, and
one carried a line number from a different case study. 23 rows are published
here, each one confirmed against the source.
