# NVD API key setup

Free API key from NIST. Bumps NVD rate limit from 5 req / 30s to 50 req / 30s.

## Get a key

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Submit email + organisation (any). Key arrives via email within minutes.

## Configure

Add to `.env` at repo root:    
NVD_API_KEY=your-key-here

`.env` is gitignored — the key never leaves your machine.

## Verify

```bash
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('key set:' , bool(os.getenv('NVD_API_KEY')))"
```

Expected: `key set: True`.

The NVD client (`cyberai/agents/intel/nvd_client.py`) reads the key from env,
sends it as the `apiKey` header, and picks the 50-req limiter automatically.
No code changes needed.

## Without a key

Everything still works — the client falls back to the 5 req / 30s limit and
the retry layer handles 429/503 with exponential backoff. Scans are slower.
