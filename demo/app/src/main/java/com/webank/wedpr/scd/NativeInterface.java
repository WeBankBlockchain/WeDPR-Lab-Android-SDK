// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.scd;

/** Native interface for Crypto client. */
public class NativeInterface {

  // TODO: Check this path.
  static {
    System.loadLibrary("ffi_java_scd");
  }

  // JNI function section.
  public static native IssuerResult issuerMakeCertificateTemplate(String attributeTemplate);

  public static native IssuerResult issuerSignCertificate(
          String credentialTemplate,
          String templateSecretKey,
          String credentialRequest,
          String userId,
          String nonce);

  public static native UserResult userFillCertificate(
          String credentialInfo, String credentialTemplate);

  public static native UserResult userBlindCertificateSignature(
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String userPrivateKey,
          String credentialSecretsBlindingFactors,
          String nonceCredential);

  public static native UserResult userProveSelectiveDisclosure(
          String verificationPredicateRule,
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String userPrivateKey,
          String verificationNonce);

  public static native VerifierResult verifierVerifySelectiveDisclosure(
          String verificationPredicateRule, String verificationRequest);

  public static native VerifierResult verifierGetRevealedAttrsFromVerifyRequest(
          String verificationRequest);

  public static native VerifierResult verifierGetVerificationNonce();
}
