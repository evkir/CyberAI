# CyberAI Agent API

## AsyncPipeline
from cyberai.core.pipeline import AsyncPipeline
result = AsyncPipeline.execute("10.10.10.1")
print(result.success, result.recon, result.intel, result.exploit)

## AsyncReconAgent
from cyberai.agents.recon.async_agent import AsyncReconAgent
result = await AsyncReconAgent().run("10.10.10.1")

## AsyncIntelAgent
from cyberai.agents.recon.async_agent import AsyncIntelAgent
result = await AsyncIntelAgent().run(recon_result)

## AsyncExploitAgent
from cyberai.agents.recon.async_agent import AsyncExploitAgent
result = await AsyncExploitAgent().run(intel_result)

## Safety
from cyberai.core.safety import InputSanitizer, ScopeValidator, ScopeConfig
clean = InputSanitizer.sanitize(untrusted_string)
