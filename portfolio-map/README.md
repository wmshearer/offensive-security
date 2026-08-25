# Portfolio map

How the projects in this portfolio actually connect, and how many do not.

## The result

```
56 projects on the site
21 verified connections between them
27 projects appear in at least one connection
28 appear in none
```

Eight of the twenty-one connections were verified by reading the import
statement or filesystem path that creates them. The other thirteen come from a
project's own stated description.

## The rule

An edge exists only if something checkable establishes it: an import, a path to a
sibling's data, a vendored file naming its source, or the project's own text.

Two projects being about the same topic is not a connection. Category membership
is already on the site and says nothing about whether work flows between them.

That rule is why the number is 21 and not 60. The temptation with a page like
this is to make the graph look dense, because a connected portfolio reads as a
body of work and a disconnected one reads as a pile.

## The longest chain

Four projects, three hops, with something real passing at each step:

```
ai-threat-intel-analysis
  -> atlas-coverage-map        16 documented cases, mapped to ATLAS techniques
  -> signal-stitching          the mapping rules, copied verbatim
  -> threat-intel-datamart     8 MISP exports, 8,591 indicators, read not copied
```

The middle hop is the interesting one. `signal-stitching/src/atlas_techniques.py`
copies the sibling's logic rather than importing it, and says why in the file: a
direct import would resolve against the wrong package because both projects
vendor a module at the same path.

## What connects to nothing

28 projects, including all twelve HackTheBox walkthroughs. None of the twelve
references another. The only thing reading across them is
`validation-methodology`, which treats them as a family rather than pairing with
any one of them.

Several standalone tools are also isolated: the OpenAPI analyzer, the cloud
coverage map, the supply chain audit. They were built to answer their own
question and they do not feed anything else.

## Running it

```
python3 src/report.py
python3 -m pytest tests/ -q
```

The counts are computed from the edge list rather than written down, so they
cannot drift from it. One test fails if the disconnected share ever drops below
40%, on the grounds that either the framing needs rewriting or an edge was added
without evidence.
