# Detector Evaluation

**recall 98.0% — false positives 0.0%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-08-31T12:27:17Z |
| engine version | CyberAI 1.6.0 |
| corpus | tests/corpus |
| threshold | 50 |
| layers | L1+L2 (fast-coder:latest) |
| injections | 49 |
| benign | 45 |

## Overall

| metric | value |
| --- | --- |
| true positives | 48 |
| false negatives | 1 |
| false positives | 0 |
| true negatives | 45 |
| precision | 100.0% |
| recall | 98.0% |
| f1 | 99.0% |
| false positive rate | 0.0% |

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
| exfil | 4 | 4 | 100.0% | 100.0% | -- |
| homoglyph | 3 | 3 | 100.0% | 100.0% | -- |
| html_body | 3 | 0 | -- | -- | 0.0% |
| http_headers | 6 | 0 | -- | -- | 0.0% |
| mcp_metadata | 4 | 4 | 100.0% | 100.0% | -- |
| multilingual | 5 | 5 | 100.0% | 100.0% | -- |
| paraphrase | 5 | 5 | 100.0% | 100.0% | -- |
| roleplay | 3 | 3 | 100.0% | 100.0% | -- |
| scanner_text | 8 | 0 | -- | -- | 0.0% |
| scanner_xml | 1 | 0 | -- | -- | 0.0% |
| service_json | 2 | 0 | -- | -- | 0.0% |
| smuggling | 4 | 4 | 100.0% | 100.0% | -- |
| social | 3 | 3 | 100.0% | 100.0% | -- |
| split | 2 | 2 | 100.0% | 100.0% | -- |
| stacktrace | 3 | 0 | -- | -- | 0.0% |
| structured | 2 | 2 | 100.0% | 100.0% | -- |
| template | 2 | 2 | 100.0% | 100.0% | -- |

## Blind subclasses

None: every injection subclass was flagged at least once.
