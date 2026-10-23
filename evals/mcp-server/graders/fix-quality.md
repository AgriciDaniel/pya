---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture is a TypeScript MCP server over Streamable HTTP. It pins @modelcontextprotocol/sdk
1.31.0, creates session tokens with Math.random(), and creates one transport at module scope that
every client shares.

PASS if the report has findings for all three, with these fixes: upgrade the SDK to 1.32.0 or
later; generate tokens with crypto.randomUUID() or crypto.randomBytes(); create one transport per
session keyed by session ID so clients cannot see each other's messages.

FAIL if any of the three is missed, if the Math.random() fix suggests another non-cryptographic
source, or if severities are wildly off (for example the shared transport rated INFO).
