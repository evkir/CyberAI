# Detector Evaluation

**recall 90.9% — false positives 3.8%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-10-09T19:38:50Z |
| engine version | CyberAI 1.7.0 |
| corpus | tests/corpus |
| threshold | 50 |
| layers | L1+L2 (fast-coder:latest) |
| injections | 55 |
| benign | 105 |

## Overall

| metric | value |
| --- | --- |
| true positives | 50 |
| false negatives | 5 |
| false positives | 4 |
| true negatives | 101 |
| precision | 92.6% |
| recall | 90.9% |
| f1 | 91.7% |
| false positive rate | 3.8% |

## Per-subclass breakdown

A slice holding no positives has no precision, and one holding no negatives has no false-positive rate. Those cells carry a dash. Percentages are only printed where the question has a subject.

| subclass | n | flagged | precision | recall | FP rate |
| --- | --- | --- | --- | --- | --- |
| api_json | 11 | 0 | -- | -- | 0.0% |
| cli_table | 7 | 0 | -- | -- | 0.0% |
| code_context | 2 | 2 | 100.0% | 100.0% | -- |
| config_json | 1 | 0 | -- | -- | 0.0% |
| container_logs | 3 | 0 | -- | -- | 0.0% |
| context_forgery | 3 | 3 | 100.0% | 100.0% | -- |
| direct | 4 | 4 | 100.0% | 100.0% | -- |
| encoded | 3 | 2 | 100.0% | 66.7% | -- |
| exfil | 6 | 6 | 100.0% | 100.0% | -- |
| homoglyph | 3 | 3 | 100.0% | 100.0% | -- |
| html_body | 3 | 0 | -- | -- | 0.0% |
| http_headers | 6 | 0 | -- | -- | 0.0% |
| mcp_metadata | 4 | 4 | 100.0% | 100.0% | -- |
| multilingual | 5 | 5 | 100.0% | 100.0% | -- |
| paraphrase | 5 | 5 | 100.0% | 100.0% | -- |
| roleplay | 3 | 3 | 100.0% | 100.0% | -- |
| scanner_text | 8 | 0 | -- | -- | 0.0% |
| scanner_xml | 1 | 0 | -- | -- | 0.0% |
| server_card | 60 | 4 | -- | -- | 6.7% |
| service_json | 2 | 0 | -- | -- | 0.0% |
| smuggling | 4 | 4 | 100.0% | 100.0% | -- |
| social | 3 | 3 | 100.0% | 100.0% | -- |
| split | 2 | 2 | 100.0% | 100.0% | -- |
| stacktrace | 3 | 0 | -- | -- | 0.0% |
| stative | 4 | 0 | -- | 0.0% | -- |
| structured | 2 | 2 | 100.0% | 100.0% | -- |
| template | 2 | 2 | 100.0% | 100.0% | -- |

## Blind subclasses

Every sample in these scored below the threshold. This is what an overall recall figure cannot show, and it is the argument for a layer that is not a list of regular expressions.

- `stative` — 0 of 4 flagged
