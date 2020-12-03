// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedprdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import com.google.protobuf.InvalidProtocolBufferException;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.crypto.CryptoClient;
import com.webank.wedpr.crypto.CryptoResult;
import com.webank.wedpr.scd.IssuerResult;
import com.webank.wedpr.scd.PredicateType;
import com.webank.wedpr.scd.ScdClient;
import com.webank.wedpr.scd.UserResult;
import com.webank.wedpr.scd.VerifierResult;
import com.webank.wedpr.scd.proto.Predicate;
import com.webank.wedpr.vcl.VclClient;
import com.webank.wedpr.vcl.VclResult;
import com.webank.wedpr.scd.proto.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

// TODO: Rename the package name to demo.
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        CryptoClient cryptoClient = new CryptoClient();
        VclClient vclClient = new VclClient();
        ScdClient scdClient = new ScdClient();
        CryptoResult cryptoResult = null;
        try {
            cryptoDemo(cryptoClient);
            vclDemo(vclClient, 2, 2, 4);
            vclDemo(vclClient, 3, 4, 12);
            vclDemo(vclClient, 1, 2, 3);
            vclDemo(vclClient, 3, 4, 5);
            vclDemo(vclClient, -1, 4, 3);
            ScdDemo(scdClient);
        } catch (WedprException e) {
            e.printStackTrace();
        }
        catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }
    }

    private static void vclDemo(VclClient vclClient, long c1Value, long c2Value, long c3Value)
            throws WedprException {
        System.out.println("\n*******\nVCL PROOF RUN\n*******");
        System.out.println(
                "c1_value = " + c1Value + ", c2_value = " + c2Value + ", c3_value = " + c3Value + "\n");

        if (c1Value < 0 || c2Value < 0 || c3Value < 0) {
            System.out.println(
                    "[WARNING] Non-positive value detected.\n"
                            + "All the balance proofs (sum and product) will fail intentionally.\n");
        }

        // Create confidential credit records for those values.
        VclResult c1Result = vclClient.makeCredit(c1Value);
        System.out.println("c1_credit (publicly verifiable) = " + c1Result.confidentialCredit);
        System.out.println("c1_secret (only known by the owner) = " + c1Result.ownerSecret);

        VclResult c2Result = vclClient.makeCredit(c2Value);
        System.out.println("c2_credit (publicly verifiable) = " + c2Result.confidentialCredit);
        System.out.println("c2_secret (only known by the owner) = " + c2Result.ownerSecret);

        VclResult c3Result = vclClient.makeCredit(c3Value);
        System.out.println("c3_credit (publicly verifiable) = " + c3Result.confidentialCredit);
        System.out.println("c3_secret (only known by the owner) = " + c3Result.ownerSecret);

        // Prove c1_value + c2_value = c3_value.
        VclResult sumResult =
                vclClient.proveSumBalance(c1Result.ownerSecret, c2Result.ownerSecret, c3Result.ownerSecret);
        System.out.println(
                "\nproof of " + c1Value + " + " + c2Value + " =? " + c3Value + ":\n" + sumResult.proof);

        VclResult verifySumResult =
                vclClient.verifySumBalance(
                        c1Result.confidentialCredit,
                        c2Result.confidentialCredit,
                        c3Result.confidentialCredit,
                        sumResult.proof);
        if (verifySumResult.verificationResult) {
            System.out.println(">> Pass: " + c1Value + " + " + c2Value + " == " + c3Value);
        } else {
            System.out.println("<< Fail: " + c1Value + " + " + c2Value + " != " + c3Value);
        }

        // Prove c1_value * c2_value = c3_value.
        VclResult productResult =
                vclClient.proveProductBalance(
                        c1Result.ownerSecret, c2Result.ownerSecret, c3Result.ownerSecret);
        System.out.println(
                "\nproof of " + c1Value + " * " + c2Value + " =? " + c3Value + ":\n" + productResult.proof);

        VclResult verifyMultiResult =
                vclClient.verifyProductBalance(
                        c1Result.confidentialCredit,
                        c2Result.confidentialCredit,
                        c3Result.confidentialCredit,
                        productResult.proof);
        if (verifyMultiResult.verificationResult) {
            System.out.println(">> Pass: " + c1Value + " * " + c2Value + " == " + c3Value);
        } else {
            System.out.println("<< Fail: " + c1Value + " * " + c2Value + " != " + c3Value);
        }

        // Prove c1_value in [0, 2^32-1].
        VclResult rangeResult = vclClient.proveRange(c1Result.ownerSecret);
        System.out.println("\nproof of " + c1Value + " in [0, 2^32-1]:\n" + productResult.proof);

        VclResult verifyRangeResult =
                vclClient.verifyRange(c1Result.confidentialCredit, rangeResult.proof);
        if (verifyRangeResult.verificationResult) {
            System.out.println(">> Pass: " + c1Value + " in [0, 2^32-1]");
        } else {
            System.out.println("<< Fail: " + c1Value + " not in [0, 2^32-1]");
        }
    }

    private static void cryptoDemo(CryptoClient cryptoClient)
            throws WedprException {
        System.out.println("\n*******\nCRYPTO TOOL RUN\n*******");

        CryptoResult cryptoResult = cryptoClient.secp256k1GenKeyPair();
        String publicKey = cryptoResult.publicKey;
        String privateKey = cryptoResult.privateKey;
        System.out.println("public key = " + publicKey);
        System.out.println("private key = " + privateKey);

        // Base64 encoding for "WeDPR Demo", which is currently required to pass bytes input to API.
        // TODO: Allow non-encoded UTF8 input.
        String message = "V2VEUFIgRGVtbw==";
        String messageHash = cryptoClient.keccak256Hash(message).hash;
        System.out.println("messageHash = " + messageHash);

        String signature = cryptoClient.secp256k1Sign(privateKey, messageHash).signature;
        System.out.println("signature = " + signature);

        boolean result = cryptoClient.secp256k1Verify(publicKey, messageHash, signature).booleanResult;
        System.out.println("signature verify result = " + result);

        String encryptedData = cryptoClient.secp256k1EciesEncrypt(publicKey, messageHash).encryptedData;
        System.out.println("encryptedData = " + encryptedData);

        String decryptedData = cryptoClient.secp256k1EciesDecrypt(privateKey, encryptedData).decryptedData;
        System.out.println("decryptedData = " + decryptedData);
    }

    private static void ScdDemo(ScdClient scdClient)
            throws WedprException, InvalidProtocolBufferException {
        System.out.println("\n*******\nSELECTIVE DISCLOSURE RUN\n*******");

        // issuer make template
        ArrayList<String> attributes = new ArrayList<String>();
        attributes.add("name");
        attributes.add("age");
        attributes.add("gender");
        attributes.add("time");
        String encodeAttributeTemplate = scdClient.issuerMakeCertificateSchema(attributes);
        System.out.println("Encoded attributeTemplate = " + encodeAttributeTemplate);

        IssuerResult issuerResult =
                scdClient.issuerMakeCertificateTemplate(encodeAttributeTemplate);

        String credentialTemplate = issuerResult.certificateTemplate;
        String templateSecretKey = issuerResult.templatePrivateKey;
        System.out.println("Encoded credentialTemplate = " + credentialTemplate);
        System.out.println("Encoded templateSecretKey = " + templateSecretKey);

        // User fill template
        Map<String, String> maps = new HashMap<String, String>();
        maps.put("name", "123");
        maps.put("age", "18");
        maps.put("gender", "1");
        maps.put("time", "12345");
        String credentialInfo = scdClient.userMakeAttributeDict(maps);
        UserResult userResult =
                scdClient.userFillCertificate(credentialInfo, credentialTemplate);

        String signatureRequest = userResult.signCertificateRequest;
        String userPrivateKey = userResult.userPrivateKey;
        String credentialSecretsBlindingFactors = userResult.certificateSecretsBlindingFactors;
        String userNonce = userResult.userNonce;
        System.out.println("Encoded signatureRequest = " + signatureRequest);
        System.out.println("Encoded userPrivateKey = " + userPrivateKey);
        System.out.println(
                "Encoded credentialSecretsBlindingFactors = " + credentialSecretsBlindingFactors);
        System.out.println("Encoded userNonce = " + userNonce);

        // Issuer sign user's request to generate credential
        issuerResult =
                scdClient.issuerSignCertificate(
                        credentialTemplate, templateSecretKey, signatureRequest, "id1", userNonce);

        String credentialSignature = issuerResult.certificateSignature;
        String issuerNonce = issuerResult.issuerNonce;
        System.out.println("Encoded credentialSignature = " + credentialSignature);
        System.out.println("Encoded issuerNonce = " + issuerNonce);

        // User generate new credentialSignature
        userResult =
                scdClient.userBlindCertificateSignature(
                        credentialSignature,
                        credentialInfo,
                        credentialTemplate,
                        userPrivateKey,
                        credentialSecretsBlindingFactors,
                        issuerNonce);

        String credentialSignatureNew = userResult.certificateSignature;
        System.out.println("Encoded credentialSignatureNew = " + credentialSignatureNew);

        // Verifier set verification rules
        VerificationRuleSet verificationRuleSet = VerificationRuleSet.getDefaultInstance();
        Predicate predicate =
                Predicate.newBuilder()
                        .setAttributeName("age")
                        .setPredicateType(PredicateType.GT.name())
                        .setPredicateValue(17)
                        .build();
        verificationRuleSet = verificationRuleSet.toBuilder().addAttributePredicate(predicate).build();

        predicate =
                Predicate.newBuilder()
                        .setAttributeName("gender")
                        .setPredicateType(PredicateType.EQ.name())
                        .setPredicateValue(1)
                        .build();
        verificationRuleSet = verificationRuleSet.toBuilder().addAttributePredicate(predicate).build();

        String verificationRuleStr =
                ScdClient.protoToEncodedString(verificationRuleSet);
        System.out.println("Encoded verificationRuleStr = " + verificationRuleStr);

        // User prove by verification rules
        String verificationNonce =
                scdClient.verifierGetVerificationNonce().verificationNonce;
        userResult =
                scdClient.userProveSelectiveDisclosure(
                        verificationRuleStr,
                        credentialSignatureNew,
                        credentialInfo,
                        credentialTemplate,
                        userPrivateKey,
                        verificationNonce);

        String verificationRequest = userResult.verifyRequest;
        System.out.println("Encoded verificationRequest = " + verificationRequest);

        // Verifier verify proof
        VerifierResult verifierResult =
                scdClient.verifierVerifySelectiveDisclosure(verificationRuleStr, verificationRequest);
        System.out.println("result = " + verifierResult.boolResult);

        verifierResult =
                scdClient.verifierGetRevealedAttrsFromVerifyRequest(verificationRequest);
        String revealedAttributeDict = verifierResult.revealedAttributeDict;
        AttributeDict attributeDict =
                AttributeDict.parseFrom(Utils.stringToBytes(revealedAttributeDict));
        System.out.println("revealedAttributeDict =" + attributeDict);
    }
}