// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.ktb.hdk;

import java.io.IOException;

/** Native interface for HDK client. */
public class NativeInterface {

  static {
    System.loadLibrary("ffi_java_ktb");
  }

  // JNI function section.
  public static native HdkResult createMnemonicEn(int wordCount);

  public static native HdkResult createMasterKeyEn(String password, String mnemonic);

  public static native HdkResult deriveExtendedKey(String masterKey, int purposeType, int assetType, int account, int change, int addressIndex);
}
