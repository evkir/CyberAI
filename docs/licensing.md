# Licensing

This document explains which licence applies to what, why the portfolio is not
uniform, and what happens to the rights when MASec Lab LLC is registered. It is
written for partners, reviewers and counsel rather than for developers.

*This is not legal advice.*

## 1. Current licences

| Project | Licence | Copyright holder |
|---|---|---|
| CyberAI | Apache-2.0 | Evgeny Kiriyak |
| mas-sentry-toolkit (MST) | AGPL-3.0 | Evgeny Kiriyak |

The difference is deliberate, not an oversight.

**CyberAI is offensive tooling.** Its value depends on being adopted, read and
audited by security teams, and a large share of enterprises block copyleft
licences by policy — including for internal use. Apache-2.0 maximises adoption
and adds an explicit patent grant, which matters because the project carries
original research (ABFP, HCAP, BTES) that may later be the subject of a patent
filing.

**MST is defensive tooling.** A customer installs it and runs it against their
own estate. The risk that someone wraps it as a competing hosted service is
real and copyleft is the appropriate answer there.

## 2. History: the change is not retroactive

CyberAI was distributed under the MIT License up to and including v1.5.0. Those
releases remain available under MIT permanently, on both GitHub and PyPI.
Nothing granted under MIT is withdrawn.

Starting with v1.6.0 the project is distributed under the Apache License,
Version 2.0. The `LICENSE` file holds the canonical Apache text, unmodified;
the copyright line lives in `NOTICE`.

## 3. Contributor License Agreement

Contributions require a signed CLA — see [CLA.md](../CLA.md). The contributor
grants a copyright licence, a patent licence, and the right for the maintainer
to relicense the contribution.

The relicensing clause is the point of the agreement. Without it, changing the
licence of any component later requires locating and obtaining consent from
every contributor individually, which in practice means the licence can never
change again. With it, the option stays open at no cost to anyone: releases
already made under Apache-2.0 stay under Apache-2.0 regardless.

Signatures are collected in the pull request description and recorded by the
maintainer before merge. No third-party bot is used: the widely deployed
CLA-assistant action was archived upstream in March 2026, and adding an
unmaintained workflow with write access to this repository would contradict
the supply-chain posture the project is built to test.

## 4. Planned transfer of rights to the LLC

Rights in the project currently belong to a natural person. After MASec Lab LLC
(United States) is registered, the rights will be transferred to the company
under a separate IP assignment agreement. The licence does not change as a
result: code released under Apache-2.0 remains under Apache-2.0, and the CLA
already names successor entities as licensors.

Copyright notices name the individual rather than the company, because a
copyright assigned to an entity that does not yet exist is legally empty.

## 5. What an open licence does not cover

Future commercial components may be released under separate terms. Candidates
named today: a managed/hosted edition, an HCAP implementation, and the
second-generation injection detector. Releasing those under a different licence
is not a relicensing of the core — the core stays Apache-2.0, and the split is
made per module rather than by flipping a switch across the whole project.

Anyone building on CyberAI can rely on the core remaining open.
