// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.vcl;


/** Native interface for VCL client. */
public class NativeInterface {
    static {
        System.loadLibrary("ffi_java_vcl");
    }

    // JNI function section.
    public static native VclResult makeCredit(long value);

    public static native VclResult proveSumBalance(String c1Secret, String c2Secret, String c3Secret);

    public static native VclResult verifySumBalance(
            String c1Credit, String c2Credit, String c3Credit, String proof);

    public static native VclResult proveProductBalance(
            String c1Secret, String c2Secret, String c3Secret);

    public static native VclResult verifyProductBalance(
            String c1Credit, String c2Credit, String c3Credit, String proof);

    public static native VclResult proveRange(String ownerSecret);

    public static native VclResult verifyRange(String confidentialCredit, String proof);
}
