package com.slaunchx.plutus.sdk;

/** Explicit wire protocol selection. No automatic fallback after signature failure. */
public enum ProtocolProfile {
    REQUEST_BOUND_V1,
    PRODUCT_V1
}
