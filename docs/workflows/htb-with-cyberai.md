# Practice-Lab Dogfooding — CyberAI on HTB / OSCP-style Boxes

## Scope and authorization

This workflow is for **authorized practice targets only**: machines you own,
or intentionally vulnerable boxes on platforms that grant explicit permission
to attack them (Hack The Box, TryHackMe, PortSwigger, PWK/OSCP lab boxes, local
VMs). Never point CyberAI at a system you are not authorized to test. The lab
tooling here reads artifacts *you* produced during an authorized engagement; it
does not, by itself, attack anything.

## Overview

The `cyberai.lab` package turns the output of a solved practice box into a
structured, reviewable writeup. It is deliberately **offline**: it parses the
files you already collected — recon scans, exploit scripts, looted material —
detects captured flags, and renders a Markdown report. This lets you dogfood
CyberAI against your own lab history and keep consistent notes across machines.

A machine is just a directory. Layout is not enforced: both the tidy
`nmap/exploit/loot` convention and a flat dump of files at the machine root are
supported. Artifacts are categorised by directory name first, then by filename
extension.

## Components

    LabMachine.run(root)

    +-- collect_artifacts()  --> categorise files (nmap / exploit / loot / ...)
    |
    +-- detect_flags(root)   --> filename + content flag patterns
    |
    +-- LabResult            --> generate_writeup() --> Markdown

## Flag detection

The detector scans readable text files for both conventional flag filenames
(`proof.txt`, `local.txt`, `root.txt`, `user.txt`, `flag.txt`) and content
patterns:

- OSCP-style 32-character hex proof/local flags
- Brace formats: `HTB{...}`, `THM{...}`, `flag{...}`
- Any extra regexes you supply via `lab_flag_patterns` in the config

Oversized files (wordlists) and binaries are skipped. A malformed custom regex
is logged and ignored rather than aborting the scan.

## Usage

```python
from cyberai.lab.runner import run_machine
from cyberai.lab.writeup import generate_writeup

result = run_machine("~/oscp/machines/brainpan")
print("solved:", result.solved)
print(generate_writeup(result))
```

To add custom flag formats, pass extra patterns:

```python
result = run_machine(
    "~/oscp/machines/custom-box",
    extra_flag_patterns=[r"CTF-\d{4}-[A-Z]+"],
)
```

## Configuration

- `use_lab_dogfood` — off by default; gates the `/api/lab` dashboard routes
- `lab_flag_patterns` — extra flag regexes, empty by default
- `lab_machines_dir` — where the dashboard looks for machine folders

With `use_lab_dogfood` off, both `/api/lab` endpoints answer with a refusal
naming itself rather than with data. That refusal is distinct from an empty
list: enabled with no `lab_machines_dir` set is a configuration that has
nothing to show, while disabled is a feature that was never turned on.

The flag gates the dashboard, not the library. `run_machine` and
`generate_writeup` are importable and work regardless, as the usage above
shows — they read files off disk and answer, with no config in the path.

The lab tooling is standalone and is not part of the recon → intel → exploit →
report pipeline.
