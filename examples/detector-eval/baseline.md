# Detector Evaluation

**recall 57.1% — false positives 0.0%**

## Run metadata

| field | value |
| --- | --- |
| timestamp | 2026-08-28T08:51:26Z |
| engine version | CyberAI 1.6.0 |
| corpus | tests/corpus |
| threshold | 50 |
| layers | L1 |
| injections | 49 |
| benign | 45 |

## Overall

| metric | value |
| --- | --- |
| true positives | 28 |
| false negatives | 21 |
| false positives | 0 |
| true negatives | 45 |
| precision | 100.0% |
| recall | 57.1% |
| f1 | 72.7% |
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
| encoded | 3 | 0 | -- | 0.0% | -- |
| exfil | 4 | 3 | 100.0% | 75.0% | -- |
| homoglyph | 3 | 3 | 100.0% | 100.0% | -- |
| html_body | 3 | 0 | -- | -- | 0.0% |
| http_headers | 6 | 0 | -- | -- | 0.0% |
| mcp_metadata | 4 | 2 | 100.0% | 50.0% | -- |
| multilingual | 5 | 0 | -- | 0.0% | -- |
| paraphrase | 5 | 0 | -- | 0.0% | -- |
| roleplay | 3 | 3 | 100.0% | 100.0% | -- |
| scanner_text | 8 | 0 | -- | -- | 0.0% |
| scanner_xml | 1 | 0 | -- | -- | 0.0% |
| service_json | 2 | 0 | -- | -- | 0.0% |
| smuggling | 4 | 4 | 100.0% | 100.0% | -- |
| social | 3 | 0 | -- | 0.0% | -- |
| split | 2 | 1 | 100.0% | 50.0% | -- |
| stacktrace | 3 | 0 | -- | -- | 0.0% |
| structured | 2 | 2 | 100.0% | 100.0% | -- |
| template | 2 | 1 | 100.0% | 50.0% | -- |

## Blind subclasses

Every sample in these scored below the threshold. This is what an overall recall figure cannot show, and it is the argument for a layer that is not a list of regular expressions.

- `encoded` — 0 of 3 flagged
- `multilingual` — 0 of 5 flagged
- `paraphrase` — 0 of 5 flagged
- `social` — 0 of 3 flagged
