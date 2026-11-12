# Optional AI-assisted investigation

A local language model (Ollama) can write an investigation note for an incident: a summary,
possible causes, correlations, uncertainty and defensive next steps. It is **off by default**
(`llm.enabled: false`) and nothing else depends on it: detection, incidents and notifications
work identically without a model, without a GPU, and when the model is unreachable.

## Enable

```bash
docker compose --profile live --profile llm up -d
docker compose exec ollama ollama pull llama3.2:3b     # about 2 GB; needs ~4 GB RAM free
# configs/live.yaml: llm.enabled: true, then restart live-dashboard
```

Then use **Investigate** in an incident's detail view. On a 2 GB VPS, leave it off.

## Safety controls (enforced in code, tested)

| Risk | Control |
|---|---|
| Log content is attacker-controlled (user names, paths, user agents) | Evidence is sanitized (control characters removed, secrets redacted, lengths capped) and placed in a JSON block between unpredictable delimiters. The system prompt says it is data, not instructions. |
| Prompt injection ("ignore previous instructions...") | Lines that look like instructions are flagged and shown to the analyst. The model's output cannot change anything, so obeying the injection has no effect (tested with a model that "obeys"). |
| Fabricated evidence | The model may cite only evidence ids it was given (`E1`, `E2`, ...). Causes and correlations citing an unknown id, or none, are dropped and counted. Kept citations link to the stored events in the dashboard. |
| Dangerous advice | Suggested steps that look like instructions or pipe a download into a shell are dropped. |
| Automatic action | None exists. The note is stored as advisory text. Nothing executes commands, blocks addresses, edits configuration or changes incident status. |
| Over-confidence | The note is labeled "AI-generated and unverified"; the prompt requires distinguishing unusual, suspected and confirmed. |

The model runs locally; no incident data is sent to a third-party service.
