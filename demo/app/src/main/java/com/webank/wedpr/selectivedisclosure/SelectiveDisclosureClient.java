// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.selectivedisclosure;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.selectivedisclosure.proto.*;

import java.util.*;

/** Client class used by selective disclosure. This is the main interface class for Java apps using selective disclosure functions. */
public class SelectiveDisclosureClient {
  /**
   * Issuer make credential template.
   *
   * @param attributeTemplate attribute Template for selective disclosure solution.
   * @return IssuerResult containing credential template and template secret key for issuer.
   * @throws WedprException if any error occurred.
   */
  public IssuerResult makeCredentialTemplate(String attributeTemplate) throws WedprException {
    return NativeInterface.issuerMakeCredentialTemplate(attributeTemplate).expectNoError();
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
  public IssuerResult signCredential(
          String credentialTemplate,
          String templateSecretKey,
          String credentialRequest,
          String userId,
          String nonce) throws WedprException {
    return NativeInterface.issuerSignCredential(credentialTemplate, templateSecretKey, credentialRequest, userId, nonce).expectNoError();
  }

  /**
   * User make credential request
   *
   * @param credentialInfo user's credential info
   * @param credentialTemplate credential template generated by issuer.
   * @return UserResult containing credential signature request, master secret, credential secrets blinding factors and user nonce.
   * @throws WedprException if any error occurred.
   */
  public UserResult makeCredential(
          String credentialInfo, String credentialTemplate) throws WedprException {
    return NativeInterface.userMakeCredential(credentialInfo, credentialTemplate).expectNoError();
  }

  /**
   * User blind credential signature signed by issuer.
   *
   * @param credentialSignature credential signature signed by issuer.
   * @param credentialInfo user's credential info.
   * @param credentialTemplate credential template generated by issuer.
   * @param masterSecret user's master key.
   * @param credentialSecretsBlindingFactors user's bling factors.
   * @param nonceCredential user's nonce.
   * @return UserResult containing a new credential signature.
   * @throws WedprException if any error occurred.
   */
  public UserResult blindCredentialSignature(
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String masterSecret,
          String credentialSecretsBlindingFactors,
          String nonceCredential)  throws WedprException {
    return NativeInterface.userBlindCredentialSignature(credentialSignature, credentialInfo, credentialTemplate, masterSecret, credentialSecretsBlindingFactors, nonceCredential).expectNoError();
  }

  /**
   * User prove credential for verifier.
   *
   * @param verificationPredicateRule verification predicate rule make by verifier.
   * @param credentialSignature user's credential signature.
   * @param credentialInfo user's credential info.
   * @param credentialTemplate credential template generated by issuer.
   * @param masterSecret user's master key.
   * @return UserResult containing verification request to verifier.
   * @throws WedprException if any error occurred.
   */
  public UserResult proveCredentialInfo(
          String verificationPredicateRule,
          String credentialSignature,
          String credentialInfo,
          String credentialTemplate,
          String masterSecret)  throws WedprException {
    return NativeInterface.userProveCredentialInfo(verificationPredicateRule, credentialSignature, credentialInfo, credentialTemplate, masterSecret).expectNoError();
  }

  /**
   * Verifier verify proof made by user with issuer's credential template.
   *
   * @param verificationPredicateRule verification predicate rule made by Verifier.
   * @param verificationRequest verification request generated by user.
   * @return VerifierResult containing verify result.
   * @throws WedprException if any error occurred.
   */
  public VerifierResult verifyProof(
          String verificationPredicateRule, String verificationRequest)  throws WedprException {
    return NativeInterface.verifierVerifyProof(verificationPredicateRule, verificationRequest).expectNoError();
  }

  /**
   *Verifier check revealed attribution.
   *
   * @param verificationRequest verification request generated by user.
   * @return VerifierResult containing revealed attribute info.
   * @throws WedprException if any error occurred.
   */
  public VerifierResult getRevealedAttrsFromVerificationRequest(
          String verificationRequest)  throws WedprException {
    return NativeInterface.verifierGetRevealedAttrsFromVerificationRequest(verificationRequest).expectNoError();
  }

  public String makeAttributeTemplate(List<String> attrs) {
    AttributeTemplate attributeTemplate = AttributeTemplate.getDefaultInstance();
    for(String attr: attrs) {
      attributeTemplate = attributeTemplate.toBuilder().addAttributeKey(attr).build();
    }
    return protoToEncodedString(attributeTemplate);
  }

  public String makeCredentialInfo(Map<String, String> attrs) {
    CredentialInfo credentialInfo = CredentialInfo.getDefaultInstance();
    for(Map.Entry<String, String> entry: attrs.entrySet()) {
      StringToStringPair pair = StringToStringPair.newBuilder().setKey(entry.getKey()).setValue(entry.getValue()).build();
      credentialInfo = credentialInfo.toBuilder().addAttributePair(pair).build();
    }
    return protoToEncodedString(credentialInfo);
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
