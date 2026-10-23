# Kubernetes Security Patterns

## Critical Misconfigurations

| Pattern | Risk | Severity | Fix |
|---------|------|----------|-----|
| `privileged: true` | Full host access, container escape | CRITICAL | Remove, use specific capabilities |
| `hostNetwork: true` | Access host network stack | HIGH | Remove unless system pod |
| `hostPID: true` / `hostIPC: true` | Namespace escape | HIGH | Remove |
| Missing `resources.limits` | Resource exhaustion, DoS | MEDIUM | Set CPU/memory limits |
| `runAsUser: 0` | Root in container | HIGH | Use non-root UID (65534) |
| Secrets in plain YAML | Credentials in git | CRITICAL | Use SealedSecrets/ExternalSecrets/Vault |
| Missing NetworkPolicy | All-to-all pod communication | HIGH | Implement default-deny |
| `automountServiceAccountToken: true` | Unnecessary K8s API access | MEDIUM | Set false unless pod needs API |
| Default service account used | Over-permissioned | MEDIUM | Create dedicated ServiceAccount |
| Missing `readOnlyRootFilesystem: true` | Writable container FS | MEDIUM | Enable + emptyDir for temp |
| `allowPrivilegeEscalation: true` | Privilege escape path | HIGH | Set false |
| Image tag `:latest` | Unpinned, unpredictable | MEDIUM | Use specific version or digest |

## SecurityContext Patterns

### Dangerous (missing hardening)

```yaml
# No securityContext = all defaults (dangerous)
spec:
  containers:
    - name: app
      image: myapp:latest
```

### Secure (hardened)

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp@sha256:abc123
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          memory: "256Mi"
          cpu: "500m"
        requests:
          memory: "128Mi"
          cpu: "250m"
```

## Secrets Management

### CRITICAL: Secrets in Plain YAML

```yaml
# NEVER do this: secrets are only base64 encoded, NOT encrypted
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
data:
  password: cGFzc3dvcmQxMjM=  # "password123" in base64, NOT secure!
```

### Safe Alternatives

- **SealedSecrets**: Encrypt at client, decrypt only in cluster
- **External Secrets Operator**: Sync from Vault/AWS SM/GCP SM
- **HashiCorp Vault**: Dynamic secrets with TTL
- **SOPS**: Encrypt YAML values with KMS

## NetworkPolicy

### Default-Deny (Baseline)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}  # All pods
  policyTypes:
    - Ingress
    - Egress
```

### Missing NetworkPolicy = All pods can talk to all pods

This means a compromised pod can reach any service, database, or internal API.

## RBAC Security Patterns

| Pattern | Risk | Fix |
|---------|------|-----|
| ClusterRoleBinding to `cluster-admin` for app | Full cluster access | Create minimal ClusterRole |
| `verbs: ["*"]` in Role | All operations allowed | Specify exact verbs needed |
| `resources: ["*"]` in Role | All resource types | Specify exact resources |
| `create pods/exec` permission | Escape to any namespace | Restrict to specific namespaces |
| ServiceAccount with cluster-wide access | Lateral movement | Namespace-scoped roles only |

## Pod Security Standards (PSS)

| Level | Use For | Key Restrictions |
|-------|---------|-----------------|
| **Privileged** | System pods only (kube-system) | No restrictions |
| **Baseline** | General workloads | No privileged, no hostNetwork/PID/IPC, no dangerous capabilities |
| **Restricted** | Security-sensitive workloads | Must run as non-root, drop ALL capabilities, read-only root FS, seccomp enforced |

## Exposed SMB and Kernel File-Sharing Services

| Pattern | Report when | Severity | Source |
|---|---|---|---|
| SMB exposed | `Service` of type `LoadBalancer` or `NodePort` with port 445 or 139, `hostPort: 445`, or `hostNetwork` pods listening on 445 | HIGH | D§17 (ksmbd unauthenticated RCE reports on port 445): https://threatlandscape.io/blog/ksmbd-zdi-can-33774-33549-unpatched-rce |
| In-kernel SMB server enabled from a workload | Privileged DaemonSets or init containers that install `ksmbd-tools`, run `modprobe ksmbd`, or start `ksmbd.mountd` | HIGH | same; ksmbd stays off unless ksmbd-tools is installed and started (D§17) |
| Rootful runtime for untrusted images | Node bootstrap scripts or CI jobs using `sudo podman run` / rootful podman for third-party images | HIGH | D§16: https://github.com/containers/podman/security/advisories/GHSA-2cvf-wqm6-wr9g |

```yaml
# DANGEROUS: SMB published to the network
apiVersion: v1
kind: Service
spec:
  type: LoadBalancer
  ports:
    - port: 445
      targetPort: 445
# SAFE: ClusterIP only, reached through a VPN or not at all
spec:
  type: ClusterIP
  ports:
    - port: 445
```

## Container Escape Classes

Version matching for these lives in the feed and osv-scanner results; this table is for the patterns that make an escape reachable.

| Example CVE | Escape class | Configuration that enables it | Source |
|-----|--------|-----------|--------|
| CVE-2025-23266 (NVIDIAScape) | GPU container toolkit hook | NVIDIA runtime on nodes running untrusted images | https://nvd.nist.gov/vuln/detail/CVE-2025-23266 |
| CVE-2024-21626 (Leaky Vessels) | runc file-descriptor leak via working directory | Untrusted images or `workingDir` from untrusted specs | https://nvd.nist.gov/vuln/detail/CVE-2024-21626 |
| Any runtime escape | Privileged pods, `hostPID`, `hostPath: /`, writable `/proc` or `/sys` | Turns a runtime bug into node compromise | n/a (configuration) |

## Detection Checklist

- [ ] No privileged containers
- [ ] All pods run as non-root
- [ ] Resource limits set on all containers
- [ ] NetworkPolicies enforce segmentation
- [ ] Secrets not stored in plain YAML
- [ ] ServiceAccounts are workload-specific
- [ ] Images pinned to digest
- [ ] ReadOnlyRootFilesystem enabled
- [ ] Capabilities dropped (ALL)
- [ ] SecurityContext defined on all pods
- [ ] RBAC follows least-privilege
- [ ] No wildcard permissions in Roles
- [ ] No SMB (445/139) exposed outside the cluster; no ksmbd from workloads
