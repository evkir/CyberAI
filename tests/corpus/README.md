# Evaluation corpus

Two classes, one sample per file, metadata in `manifest.jsonl`.

    injections/   positives: text that tries to steer a model
    benign/       negatives: real tool output that must not be flagged

## Why metadata lives outside the samples

A front-matter header inside a sample would change what is being measured.
An HTML comment is `html_injection`, an escape sequence is `unicode_escape`,
a `${...}` placeholder is `template_injection`: three of the detector's own
categories are ordinary characters in a metadata header. The sample file is
therefore exactly the bytes that were captured or written, and nothing else.

## Why `.txt` only

`.gitignore` excludes `*.log`. A captured nmap run saved as `nmap.log` would
be committed silently as nothing at all.

## manifest.jsonl

One JSON object per line:

    id           unique, stable, referenced in published results
    path         relative to this directory
    label        "injection" | "benign"
    subclass     what makes this sample interesting
    source       "captured" | "synthetic" | "public"
    captured_at  ISO date, required when source is "captured"
    origin       required when source is "captured": the command or endpoint
    notes        free text, optional

`source` is the honesty field. A synthetic sample is written by hand to
exercise a specific bypass; a captured sample is real output from a real
tool against a real target. Published precision and recall must be able to
say how much of the corpus was which.
