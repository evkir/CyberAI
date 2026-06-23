"""Deliberately-vulnerable benchmark apps. NOT for production use.

Each app is a minimal single-file Flask service exposing exactly one
vulnerability class, served only inside an ephemeral benchmark container.
They exist solely so CyberAI can measure its own engine against known-good
targets. Never import these into the scanning pipeline.
"""
