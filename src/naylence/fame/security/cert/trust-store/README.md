# Trust Store Providers

Trust store resolution is now routed through `TrustStoreProvider` implementations. Providers expose two key capabilities:

- `getRoots()` returns the parsed trust anchors used for validation.
- `getTrustStorePem()` returns the PEM chain that matches the anchors. Consumers must favour this API instead of reading environment variables directly.

The default factories wire the appropriate provider for each runtime:

- `EnvTrustStoreProviderFactory` (Node): honours the existing `FAME_CA_CERTS` semantics including inline PEM, file paths, data URIs, and HTTPS bundles.
- `BrowserTrustStoreProviderFactory`: fetches bundles from HTTPS endpoints on demand, enforces pins/TOFU policy, and caches results for repeat calls.

Runtime code should request a provider through `TrustStoreProviderFactory.createTrustStoreProvider()` rather than duplicating lookup logic. This ensures both browser and Node builds share the same configuration sources.
