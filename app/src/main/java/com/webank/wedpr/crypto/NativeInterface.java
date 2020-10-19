// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.crypto;


/** Native interface for Crypto client. */
public class NativeInterface {
    static {
        System.loadLibrary("ffi_java_crypto");
    }

    // JNI function section.
    public static native CryptoResult secp256k1EciesEncrypt(String pubKey, String plaintext);

    public static native CryptoResult secp256k1EciesDecrypt(String priKey, String ciphertext);

    public static native CryptoResult secp256k1GenKeyPair();

    public static native CryptoResult keccak256Hash(String message);

    public static native CryptoResult secp256k1Sign(String priKey, String messageHash);

    public static native CryptoResult secp256k1Verify(String pubKey, String messageHash, String signature);
}
