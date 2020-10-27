// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.crypto;

/** Native interface for Crypto client. */
public class NativeInterface {

  // TODO: Check this path.
  static {
    System.loadLibrary("ffi_java_crypto");
  }

  // JNI function section.
  public static native CryptoResult secp256k1EciesEncrypt(String publicKey, String message);

  public static native CryptoResult secp256k1EciesDecrypt(String privateKey, String encryptedData);

  public static native CryptoResult secp256k1GenKeyPair();

  public static native CryptoResult secp256k1Sign(String privateKey, String messageHash);

  public static native CryptoResult secp256k1Verify(
      String publicKey, String messageHash, String signature);

  public static native CryptoResult keccak256Hash(String message);
}
