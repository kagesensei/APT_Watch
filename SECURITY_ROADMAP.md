# Security to-do

Status: planned requirements, not a claim that these controls are implemented
or that the application is certified. Apply them across the web app, APIs,
analyst notebooks, custom agents, shared work, and deployment infrastructure.

- [ ] Harden and extend federated sign-in: Google, Facebook, and other chosen
  identity providers, using their supported authentication protocols. Use
  OpenID Connect for identity where supported and OAuth for delegated access;
  include secure authorization flows, token validation, minimal scopes,
  session protection, logout/revocation, and MFA/passkey support or enforcement
  through the chosen identity provider.
- [ ] Support PKI-backed identities and certificate authentication where
  appropriate. Treat this as a separate capability from social sign-in:
  signing in with Google does not give the application a user's client
  certificate. Plan certificate issuance, trust, renewal, and revocation.
- [ ] Design access around zero-trust architecture: explicitly authenticate
  users, devices, and workloads; enforce least privilege and per-resource
  authorization; deny access by default; and reassess access as identity,
  device posture, or risk changes. Network location alone must not grant trust.
- [ ] Include endpoint security for both analyst devices and server/workload
  hosts: device identity and posture checks, patching, endpoint protection,
  hardening, and access restrictions for compromised or unmanaged devices.
- [ ] Use HTTPS/TLS for data in transit, including browser sessions, APIs,
  notebook connections, and outbound provider integrations. Use mTLS for
  controlled service-to-service and agent connections, and managed client
  endpoints where appropriate; plan certificate lifecycle management.
- [ ] Encrypt sensitive data at rest, including databases, notebooks, reports,
  chat history, provider credentials, and backups. Use managed key storage,
  separate keys from data, limit access, and support rotation and recovery.
  Encryption at rest and in transit is mandatory whether or not PQC is feasible.
- [ ] Evaluate NIST-standardized post-quantum cryptography where supported by
  the actual libraries, TLS stack, identity/certificate infrastructure, and
  deployment endpoints: FIPS 203 (ML-KEM, key establishment), FIPS 204
  (ML-DSA, signatures), and FIPS 205 (SLH-DSA, signatures). Assess interoperability
  and performance, including supported hybrid deployments. If PQC is not yet
  viable, retain strong conventional cryptography and document a migration path.
  Distinguish using a standardized algorithm from using a FIPS-validated
  cryptographic module; verify validation requirements separately.
- [ ] Isolate users' notebook kernels and custom agents, with scoped service
  identities, resource and network limits, and explicit sharing permissions.
  Keep each user's AI-provider credentials private; sharing a notebook must not
  implicitly share credentials or grant access to another user's data.
- [ ] Add security audit trails, monitoring, and revocation workflows, and
  verify the design with threat modeling and security tests covering identity,
  authorization, tenant isolation, endpoint policy, and encryption boundaries.

Completion target: demonstrate these controls in the intended deployment and
record residual gaps before treating the application as hardened for shared use.

## Reference terminology

The requested PQC standards are **FIPS 203, 204, and 205** (interpreting
"2033-205" as a typo). They cover key establishment and digital signatures;
they do not replace bulk data encryption or endpoint security.

- [NIST approval of FIPS 203, 204, and 205](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [Google OpenID Connect authentication](https://developers.google.com/identity/openid-connect/openid-connect)

Related work: [analyst workspace to-do](notebooks/README.md).
