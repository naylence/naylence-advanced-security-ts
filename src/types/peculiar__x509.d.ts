declare module "@peculiar/x509" {
  export class X509Certificate {
    constructor(rawData: ArrayBufferView | ArrayBuffer | string);
    readonly notAfter: Date;
  }
}
