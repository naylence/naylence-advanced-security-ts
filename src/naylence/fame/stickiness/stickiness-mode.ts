export enum StickinessMode {
  STRICT = "strict",
  SIGNED_OPTIONAL = "signed-optional",
  SID_ONLY = "sid-only",
}

export function normalizeStickinessMode(value: string | StickinessMode): StickinessMode {
  switch (value) {
    case StickinessMode.STRICT:
    case "strict":
      return StickinessMode.STRICT;
    case StickinessMode.SIGNED_OPTIONAL:
    case "signed-optional":
    case "signed_optional":
      return StickinessMode.SIGNED_OPTIONAL;
    case StickinessMode.SID_ONLY:
    case "sid-only":
    case "sid_only":
      return StickinessMode.SID_ONLY;
    default:
      throw new Error(`Unknown stickiness mode: ${value}`);
  }
}
