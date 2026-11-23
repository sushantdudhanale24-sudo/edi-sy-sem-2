"""PhishSentry research edition: analyzers and evaluation code behind both papers.

Modules
  sms             six heuristic detectors, Naive Bayes, transformer layer, fusion
  email_analyzer  SPF / DKIM / DMARC / alignment checks + content scoring
  web.features    website analyzers over a saved page snapshot
  web.aggregate   critical/minor signals, diminishing returns, trust decay
  web.llm         vision-LLM override (replace or bounded) with response cache
  baselines       URL-feature Random Forest, blacklist lookup helper
  metrics         shared metric helpers
"""
__version__ = "0.1.0"
