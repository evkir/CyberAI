# CyberAI Usage Examples

## CLI
cyberai scan 10.10.10.1 --scope 10.10.10.0/24 --output ./reports/
cyberai scan target.htb --dry-run
cyberai scan 10.10.10.1 -v

## Full pipeline
import asyncio
from cyberai.core.pipeline import AsyncPipeline

async def main():
    result = await AsyncPipeline().run("10.10.10.1")
    if result.success:
        print(result.intel.get("cves", []))
        print(f"Done in {result.duration_seconds:.1f}s")

asyncio.run(main())

## Web API
curl -X POST http://127.0.0.1:8888/api/session \
  -H "Content-Type: application/json" \
  -d '{"target": "10.10.10.1"}'

curl http://127.0.0.1:8888/api/session/<session_id>
