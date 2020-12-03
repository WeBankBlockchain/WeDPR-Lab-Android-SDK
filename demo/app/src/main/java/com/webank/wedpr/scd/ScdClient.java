// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.scd;

import com.google.protobuf.Message;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.scd.proto.AttributeDict;
import com.webank.wedpr.scd.proto.CertificateSchema;
import com.webank.wedpr.scd.proto.StringToStringPair;
import java.util.List;
import java.util.Map;

/**
 * Client class used by selective disclosure. This is the main interface class for Java apps using
 * selective disclosure functions.
 */
public class ScdClient {
  /**
   * Issuer make credential template.
   *
   * @param attributeTemplate attribute Template for selective disclosure solution.
   * @return IssuerResult containing credential template and template secret key for issuer.
   * @throws WedprException if any error occurred.
   */
  public IssuerResult issuerMakeCertificateTemplate(String attributeTemplate) throws WedprException {
    return NativeInterface.issuerMakeCertificateTemplate(attributeTemplate).expectNoError();
  }

  /**
   * Issuer sign credential made by users.
   *
   * @param credentialTemplate credential template generated by issuer.
   * @param templateSecretKey template secret key generated by issuer..
   * @param credentialRequest credential request generated by user
   * @param userId user id generated by issuer.
   * @param nonce random blinding factors generated by user.
   * @return IssuerResult containing credential signature for user and issuer nonce for issuer.
   * @throws WedprException if any error occurred.
   */
  public IssuerResult issuerSignCertificate(
          String credentialTemplate,
          String templateSecretKey,
          String credentialRequest,
          String userId,
          String nonce)
          throws WedprException {
    return NativeInterface.issuerSignCertificate(
            credentialTemplate, templateSecretKey, credentialRequest, userId, nonce)
            .expectNoError();
  }

  /**
   * User make credential request
   *
   * @param credentialInfo user's credential info
   * @param credentialTemplate credential template generated by issuer.
   * @return UserResult containing credential signature request, master secret, credential secrets
   *     blinding factors and user nonce.
   * @throws WedprException if any error occurred.
   */
  public UserResult userFillCertificate(String credentialInfo, String credentialTemplate)
          throws WedprException {
    return NativeInterface.userFillCertificate(credentialInfo, credentialTemplate).expectNoError();
  }

  /**
   * User blind credential signature signed by issuer.
   *
   * @param credentialSignature credential signature signed by issuer.
   * @param credentialInfo user's credential info.
   * @param credentialTemplate credential template generated by issuer.
   * @param userPrivateKey user's master key.
   * @param credentialSecretsBlindingFactors user's bling factors.
   * @param nonceCredential user's nonce.
   * @return UserResult containing a new credential signature.
   * @throws WedprException if any error occurred.
   */
  public UserResult userBlindCertificateSignature(
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String userPrivateKey,
          String credentialSecretsBlindingFactors,
          String nonceCredential)
          throws WedprException {
    return NativeInterface.userBlindCertificateSignature(
            credentialSignature,
            credentialInfo,
            credentialTemplate,
            userPrivateKey,
            credentialSecretsBlindingFactors,
            nonceCredential)
            .expectNoError();
  }

  /**
   * User prove credential for verifier.
   *
   * @param verificationPredicateRule verification predicate rule make by verifier.
   * @param credentialSignature user's credential signature.
   * @param credentialInfo user's credential info.
   * @param credentialTemplate credential template generated by issuer.
   * @param userPrivateKey user's master key.
   * @return UserResult containing verification request to verifier.
   * @throws WedprException if any error occurred.
   */
  public UserResult userProveSelectiveDisclosure(
          String verificationPredicateRule,
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String userPrivateKey,
          String verificationNonce)
          throws WedprException {
    return NativeInterface.userProveSelectiveDisclosure(
            verificationPredicateRule,
            credentialSignature,
            credentialInfo,
            credentialTemplate,
            userPrivateKey,
            verificationNonce)
            .expectNoError();
  }

  /**
   * Verifier verify proof made by user with issuer's credential template.
   *
   * @param verificationPredicateRule verification predicate rule made by Verifier.
   * @param verificationRequest verification request generated by user.
   * @return VerifierResult containing verify result.
   * @throws WedprException if any error occurred.
   */
  public VerifierResult verifierVerifySelectiveDisclosure(String verificationPredicateRule, String verificationRequest)
          throws WedprException {
    return NativeInterface.verifierVerifySelectiveDisclosure(
            verificationPredicateRule, verificationRequest)
            .expectNoError();
  }

  /**
   * Verifier check revealed attribution.
   *
   * @param verificationRequest verification request generated by user.
   * @return VerifierResult containing revealed attribute info.
   * @throws WedprException if any error occurred.
   */
  public VerifierResult verifierGetRevealedAttrsFromVerifyRequest(String verificationRequest)
          throws WedprException {
    return NativeInterface.verifierGetRevealedAttrsFromVerifyRequest(verificationRequest)
            .expectNoError();
  }

  public VerifierResult verifierGetVerificationNonce() throws WedprException {
    return NativeInterface.verifierGetVerificationNonce().expectNoError();
  }

  public String issuerMakeCertificateSchema(List<String> attrs) {
    CertificateSchema certificateSchema =
            CertificateSchema.newBuilder().addAllAttributeName(attrs).build();
    return protoToEncodedString(certificateSchema);
  }

  public String userMakeAttributeDict(Map<String, String> attrs) {
    AttributeDict attributeDict = AttributeDict.getDefaultInstance();
    for (Map.Entry<String, String> entry : attrs.entrySet()) {
      StringToStringPair pair =
              StringToStringPair.newBuilder().setKey(entry.getKey()).setValue(entry.getValue()).build();
      attributeDict = attributeDict.toBuilder().addPair(pair).build();
    }
    return protoToEncodedString(attributeDict);
  }

  /**
   * Protobuf object transferred to encoded String.
   *
   * @param message
   * @return
   */
  public static String protoToEncodedString(Message message) {
    return Utils.bytesToString(message.toByteArray());
  }
}
