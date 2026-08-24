# Sample: Binding a Web App to an Attested Nitro Enclave with HPKE

A design pattern demonstrating how a web browser can verify the identity of an
**AWS Nitro Enclave** and establish an **end-to-end encrypted channel** to it using
Hybrid Public Key Encryption (HPKE, RFC 9180) — without trusting any intermediary.

The browser obtains a cryptographic attestation from the enclave, verifies it locally
(COSE signature, certificate chain to the pinned AWS Nitro Enclaves root, PCRs, nonce),
extracts the enclave's public key from the verified document, and seals its input with
HPKE so that only the attested enclave can open it.

## Documentation

**The full documentation — architecture, attestation flow, HPKE, security model, CI/CD,
CDK infrastructure, API reference, and the deployment guide — lives in
[`docs/index.html`](docs/index.html)** (an interactive site with diagrams; published via
GitHub Pages when enabled).

Start there for everything below:

- Architecture and trust boundaries
- The attestation flow and HPKE encryption
- Deployment (AWS CDK + CodePipeline) and the API reference
- Security model, including the intentionally-HTTP in-VPC hop and its mitigation

## Layout

| Path | What it is |
|------|------------|
| `frontend/` | React + Vite single-page app (attestation verifier, HPKE, X.509 parser) |
| `enclave/` | Nitro Enclave application (NSM attestation, HPKE decryption) + vsock proxy |
| `proxies/` | TCP-to-vsock proxy that fronts the enclave on the parent instance |
| `cdk/` | AWS CDK infrastructure (VPC, EC2, API Gateway, Cognito, Amplify, pipeline) |
| `deploy/`, `systemd/`, `scripts/` | CodeDeploy hooks, service units, and helper scripts |
| `docs/` | The documentation site |


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the MIT-0 License. See [LICENSE](LICENSE) for details.
