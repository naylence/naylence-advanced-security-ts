# Naylence Advanced Security (TypeScript)

The TypeScript implementation of Naylence's advanced security components for the Fame
runtime. This package mirrors the Python edition while providing first-class support for
Node.js and modern browser environments. It is designed to layer on top of
[`naylence-runtime-ts`](../naylence-runtime-ts) and [`naylence-core-ts`](../naylence-core-ts),
exposing encryption, certificate management, and service-level security helpers.

## Project Status

> **Work in progress** – this repository currently contains project scaffolding while the
> code is being ported from the Python implementation. Expect breaking changes until the
> initial stable release.

## Getting Started

```bash
npm install
npm run build
```

## Useful Scripts

- `npm run build` – Generate CJS, ESM, and browser bundles.
- `npm run generate:factory-manifest` – Rebuild the auto-discovered factory manifest. This runs automatically before `npm run build` and `npm run dev`.
- `npm test` – Execute the Jest test suite.
- `npm run lint` – Run ESLint over the TypeScript sources.
- `npm run format` – Apply Prettier formatting to the source tree.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for details.
