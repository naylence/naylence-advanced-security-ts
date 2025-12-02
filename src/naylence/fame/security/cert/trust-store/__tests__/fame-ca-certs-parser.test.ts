import { describe, expect, it } from "@jest/globals";

import { parseFameCaCerts } from "../fame-ca-certs-parser.js";

const PEM_ONE = `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----`;
const PEM_TWO = `-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----`;

describe("parseFameCaCerts", () => {
  it("treats a multi-line PEM string as a single inline source", () => {
    const result = parseFameCaCerts(PEM_ONE);

    expect(result).toEqual([
      {
        type: "INLINE_PEM",
        pem: PEM_ONE,
      },
    ]);
  });

  it("extracts each PEM block when multiple bundles are provided", () => {
    const combined = `${PEM_ONE}\n\n${PEM_TWO}`;

    const result = parseFameCaCerts(combined);

    expect(result).toEqual([
      {
        type: "INLINE_PEM",
        pem: PEM_ONE,
      },
      {
        type: "INLINE_PEM",
        pem: PEM_TWO,
      },
    ]);
  });

  it("preserves non-PEM entries alongside inline certificates", () => {
    const combined = `${PEM_ONE}\nfile:///tmp/roots.pem`;

    const result = parseFameCaCerts(combined);

    expect(result).toEqual([
      {
        type: "INLINE_PEM",
        pem: PEM_ONE,
      },
      {
        type: "FILE",
        path: "/tmp/roots.pem",
      },
    ]);
  });

  it("does not split data URIs that contain commas", () => {
    const dataUri = "data:application/x-pem-file;base64,QUJD";

    const result = parseFameCaCerts(`${dataUri}\n${PEM_ONE}`);

    expect(result).toEqual([
      {
        type: "DATA_PEM",
        dataUri,
      },
      {
        type: "INLINE_PEM",
        pem: PEM_ONE,
      },
    ]);
  });
});
