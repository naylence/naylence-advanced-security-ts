[![Join our Discord](https://img.shields.io/badge/Discord-Join%20Chat-blue?logo=discord)](https://discord.gg/nwZAeqdv7y)

# Naylence Advanced Security (TypeScript)

**Naylence Advanced Security** is a high-assurance extension for the [Naylence Agentic Fabric](https://github.com/naylence) that delivers advanced cryptographic and policy-driven protections for multi-agent systems. It mirrors the capabilities of the Python reference implementation while integrating seamlessly with the Naylence TypeScript runtime.

At its core, Naylence already provides a zero-trust, message-oriented backbone for federated agents. This package extends that foundation with **sealed overlay encryption**, **SPIFFE/X.509 workload identities**, **secure sticky sessions**, and **secure load balancing** that keep systems resilient in complex, federated, and regulated deployments.

---

## Key Features

* **Overlay end-to-end encryption (E2EE) & sealed channels**  
  Adds a cryptographic layer on top of transport (TLS). Messages remain encrypted and authenticated across multiple hops, even if intermediate sentinels or networks are compromised.

* **Envelope signing & identity assurance**  
  Uses **X.509/SPIFFE-style identities (SVIDs)** so every envelope is verifiable to its origin—enabling tamper-resistant audit trails and fine-grained policy enforcement.

* **Secure sticky sessions & load balancing**  
  Cryptographically binds long-running conversations to the initiating security context, enabling identity-aware load balancing without sacrificing end-to-end protections.

* **Durable cross-domain trust**  
  Enables secure federation across orgs or clouds, where **policies—not perimeter assumptions—** determine who can talk to whom.

---

## Security Profiles

The **`@naylence/runtime`** package bundles the following profiles:

* **`open`** – minimal controls suitable for local/dev.
* **`gated`** – OAuth2/JWT-gated admission (authn/authz at the edge).
* **`overlay`** – message **signing** for provenance and tamper-evidence.

This Advanced Security package enables and implements:

* **`strict-overlay`** – maximum assurance profile combining:
  * **SPIFFE/X.509 workload identities (SVIDs)**
  * **sealed overlay encryption** (true end-to-end, multi-hop confidentiality)
  * **identity-aware, secure load balancing** and **secure sticky sessions**

Install **Naylence Advanced Security** alongside the runtime to unlock **`strict-overlay`** and the capabilities above.

---

## Why Advanced Security?

Agent orchestration introduces unique risks:

* Messages often cross **multiple hops** and **administrative domains**.
* Long-running jobs and sticky sessions can span **hours or days**.
* Agents may be **mobile, ephemeral, or untrusted** in their deployment context.

Advanced Security ensures that **security travels with the message**, not the perimeter—making zero-trust the default posture.

---

## Use Cases

* **Federated AI agent systems** — secure orchestration across departments or partner orgs.
* **Cross-cloud workflows** — durable, encrypted communication across cloud providers and trust boundaries.
* **Regulated environments** — fine-grained, auditable controls for healthcare, finance, or defense.
* **Multi-tenant platforms** — strong tenant isolation and policy-based routing in agent platforms.

---

## Getting Started

```bash
npm install @naylence/advanced-security
```

After installation, register the factories before bootstrapping your application:

```ts
import { registerRuntimeFactories } from '@naylence/runtime';
import { registerAdvancedSecurityFactories } from '@naylence/advanced-security';

registerRuntimeFactories();
registerAdvancedSecurityFactories();

// proceed to create channels/connectors as usual
```

For browser usage, build the browser bundle (`npm run build:browser`) or consume the prebuilt file from `dist/browser/index.js`.

---

## Links

* **TypeScript Advanced Security (this repo):** https://github.com/naylence/naylence-advanced-security-ts
* **Python reference implementation:** https://github.com/naylence/naylence-advanced-security-python
* **Runtime (TypeScript):** https://github.com/naylence/naylence-runtime-ts
* **Runtime (Python):** https://github.com/naylence/naylence-runtime-python
* **Agent SDKs & Examples:** https://github.com/naylence

---

## License

This package is distributed under the **Apache-2.0** license. See [`LICENSE`](./LICENSE) for full terms.
