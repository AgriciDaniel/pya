#!/usr/bin/env bash
# Scaffold for the mcp-server eval case: a TypeScript MCP server over
# Streamable HTTP with an old SDK pin, Math.random() session tokens and one
# transport shared by every client. Lockfile integrity values are random.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

mkdir -p src

cat > package.json <<'EOF'
{
  "name": "notes-mcp-server",
  "version": "0.3.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "1.31.0",
    "express": "5.1.0",
    "zod": "3.25.76"
  },
  "devDependencies": {
    "typescript": "5.9.3"
  }
}
EOF

cat > package-lock.json <<'EOF'
{
  "name": "notes-mcp-server",
  "version": "0.3.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "notes-mcp-server",
      "version": "0.3.0",
      "dependencies": {
        "@modelcontextprotocol/sdk": "1.31.0",
        "express": "5.1.0",
        "zod": "3.25.76"
      }
    },
    "node_modules/@modelcontextprotocol/sdk": {
      "version": "1.31.0",
      "resolved": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.31.0.tgz",
      "integrity": "sha512-2cWGaqtncfVIFOp4kO19C2pjKnVX1Vs5cxUuorcDgQZVGGwtb0QuZYbdgo1FlbC7s3qqUA9sV5EM2OZOWiSjYg==",
      "license": "MIT"
    },
    "node_modules/express": {
      "version": "5.1.0",
      "resolved": "https://registry.npmjs.org/express/-/express-5.1.0.tgz",
      "integrity": "sha512-8/JUB/x6Ia4yJq1g6+jy3totB7BrK9w/WMOzQM7f3kAA5vU6fdC4obZ8xnb9dd2JdWYwTIdtK/rko1jk9xr2vA==",
      "license": "MIT"
    },
    "node_modules/zod": {
      "version": "3.25.76",
      "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.76.tgz",
      "integrity": "sha512-v3wqqCSnLil5XnHtjZB9gYj4BkfncCMXB/T1TFklA/AxjAi9AYXw2F0ss7b7OobKTgeZlE+qZ1gvMzl5ceHUFQ==",
      "license": "MIT"
    }
  }
}
EOF

cat > src/server.ts <<'EOF'
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const notes = new Map<string, string[]>();
const sessions = new Map<string, string>();

function newSessionToken(): string {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

const server = new McpServer({ name: "notes", version: "0.3.0" });

server.tool("add_note", { user: z.string(), text: z.string() }, async ({ user, text }) => {
  notes.set(user, [...(notes.get(user) ?? []), text]);
  return { content: [{ type: "text", text: "saved" }] };
});

server.tool("list_notes", { user: z.string() }, async ({ user }) => ({
  content: [{ type: "text", text: (notes.get(user) ?? []).join("\n") }],
}));

// One transport for the whole process; every client connects through it.
const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => newSessionToken(),
});
await server.connect(transport);

const app = express();
app.use(express.json());

app.post("/login", (req, res) => {
  const token = newSessionToken();
  sessions.set(token, String(req.body?.user ?? "anonymous"));
  res.json({ token });
});

app.all("/mcp", async (req, res) => {
  await transport.handleRequest(req, res, req.body);
});

app.listen(3333);
EOF

cat > tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "strict": true
  },
  "include": ["src"]
}
EOF
