// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.selectivedisclosure;

/** Native interface for Crypto client. */
public class NativeInterface {

  // TODO: Check this path.
  static {
    System.loadLibrary("ffi_java_selective_disclosure");
  }

  // JNI function section.
  public static native IssuerResult issuerMakeCredentialTemplate(String attributeTemplate);

  public static native IssuerResult issuerSignCredential(
          String credentialTemplate,
          String templateSecretKey,
          String credentialRequest,
          String userId,
          String nonce);

  public static native UserResult userMakeCredential(
          String credentialInfo, String credentialTemplate);

  public static native UserResult userBlindCredentialSignature(
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String masterSecret,
          String credentialSecretsBlindingFactors,
          String nonceCredential);

  public static native UserResult userProveCredentialInfo(
          String verificationPredicateRule,
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String masterSecret);

  public static native VerifierResult verifierVerifyProof(
          String verificationPredicateRule, String verificationRequest);

  public static native VerifierResult verifierGetRevealedAttrsFromVerificationRequest(
          String verificationRequest);
}
