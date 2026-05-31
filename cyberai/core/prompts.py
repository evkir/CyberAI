"""
Prompt templates for CyberAI agents.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class PromptTemplate:
    system: str
    user_template: str

    def render(self, **kwargs) -> Dict[str, str]:
        return {
            "system": self.system,
            "user": self.user_template.format(**kwargs),
        }


EXPLOIT_PROMPT = PromptTemplate(
    system=(
        "You are an offensive security researcher performing authorized "
        "penetration testing. Analyze CVEs and attack paths, then provide "
        "a structured assessment of the most viable exploitation routes. "
        "Be precise and technical. Output JSON-compatible structured data."
    ),
    user_template=(
        "Target CVEs:\n{cves}\n\n"
        "Attack context:\n{context}\n\n"
        "Rank the top 3 attack paths by success probability. "
        "For each path explain: vector, complexity, likely impact, "
        "and recommended Metasploit module if applicable."
    ),
)
