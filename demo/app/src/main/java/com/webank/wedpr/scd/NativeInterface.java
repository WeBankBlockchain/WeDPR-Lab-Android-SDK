// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.scd;

/** Native interface for Crypto client. */
public class NativeInterface {

  // TODO: Check this path.
  static {
    System.loadLibrary("ffi_java_scd");
  }

  // JNI function section.
  public static native IssuerResult issuerMakeCertificateTemplate(String schema);

  public static native IssuerResult issuerSignCertificate(
      String certificateTemplate,
      String templatePrivateKey,
      String signRequest,
      String userId,
      String userNonce);

  public static native UserResult userFillCertificate(
      String attributeDict, String certificateTemplate);

  public static native UserResult userBlindCertificateSignature(
      String certificateSignature,
      String attributeDict,
      String certificateTemplate,
      String userPrivateKey,
      String certificateSecretsBlindingFactors,
      String issuerNonce);

  public static native UserResult userProveSelectiveDisclosure(
      String ruleSet,
      String certificateSignature,
      String attributeDict,
      String certificateTemplate,
      String userPrivateKey,
      String verificationNonce);

  public static native VerifierResult verifierVerifySelectiveDisclosure(
      String ruleSet, String verifyRequest);

  public static native VerifierResult verifierGetRevealedAttributes(String verifyRequest);

  public static native VerifierResult verifierGetVerificationNonce();
}
