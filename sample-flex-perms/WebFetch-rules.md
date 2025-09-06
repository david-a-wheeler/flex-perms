# WebFetch Rules

## Deny Rules  
- `^https?://169\.254\.169\.254` - Blocks cloud metadata service (AWS/GCP/Azure SSRF vector)

Pattern matches exact IP with http/https. This endpoint often contains credentials in cloud environments.

## Adding Rules
Create `.rule` files with INI format:
- `deny/WebFetch/name.rule`
- `ask/WebFetch/name.rule`  
- `allow/WebFetch/name.rule`
