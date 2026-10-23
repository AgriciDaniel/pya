#!/usr/bin/env bash
# Scaffold for the nextjs-lock eval case: a Next.js app whose lockfile resolves
# next 16.4.0 and, through it, sharp 0.34.3. Integrity values are random, so
# npm ci would stop with EINTEGRITY before installing anything.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

mkdir -p app

cat > package.json <<'EOF'
{
  "name": "storefront",
  "version": "1.4.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "16.4.0",
    "react": "19.2.0",
    "react-dom": "19.2.0"
  }
}
EOF

cat > package-lock.json <<'EOF'
{
  "name": "storefront",
  "version": "1.4.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "storefront",
      "version": "1.4.0",
      "dependencies": {
        "next": "16.4.0",
        "react": "19.2.0",
        "react-dom": "19.2.0"
      }
    },
    "node_modules/next": {
      "version": "16.4.0",
      "resolved": "https://registry.npmjs.org/next/-/next-16.4.0.tgz",
      "integrity": "sha512-7rlQe0aItdxaZI6Gk6nVMDWDFCET8uxYapAZ7kbgYED2IJFc247O/FnDHpR/jLFfN2BsZ+w2zp1v1wRhLTWl5w==",
      "license": "MIT",
      "dependencies": {
        "sharp": "^0.34.3"
      }
    },
    "node_modules/react": {
      "version": "19.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-19.2.0.tgz",
      "integrity": "sha512-PKfuZ+nccktkQ4iEK6/i6uVgG9frm22Dk2bwk/HVDVRFgfcz0gCpO71uvw5xzqHmE8bZVwcikbE8AHmTxZFOCQ==",
      "license": "MIT"
    },
    "node_modules/react-dom": {
      "version": "19.2.0",
      "resolved": "https://registry.npmjs.org/react-dom/-/react-dom-19.2.0.tgz",
      "integrity": "sha512-+LdQk3FAttTW9QPUprp1ZWIghml/+nks5vd5FtGjzTzCkSsa0jqFyuE2rIWiulrjIjyT33WOJ7R8sn9bFl0DZg==",
      "license": "MIT"
    },
    "node_modules/sharp": {
      "version": "0.34.3",
      "resolved": "https://registry.npmjs.org/sharp/-/sharp-0.34.3.tgz",
      "integrity": "sha512-JYtg5v3nDxsu8WwrM/csQr1FduS6vjQ3u6+2GRbglJK0RzSUKHzKECOnaoaBeENf1EvRVRhCB/hlNmMLmNZ4tA==",
      "license": "Apache-2.0"
    }
  }
}
EOF

cat > next.config.js <<'EOF'
/** @type {import('next').NextConfig} */
module.exports = {
  images: {
    remotePatterns: [{ protocol: "https", hostname: "cdn.example.invalid" }],
  },
};
EOF

cat > app/page.js <<'EOF'
import Image from "next/image";

export default function Home() {
  return (
    <main>
      <h1>Storefront</h1>
      <Image src="https://cdn.example.invalid/hero.png" alt="Hero" width={1200} height={600} />
    </main>
  );
}
EOF

cat > app/layout.js <<'EOF'
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
EOF
