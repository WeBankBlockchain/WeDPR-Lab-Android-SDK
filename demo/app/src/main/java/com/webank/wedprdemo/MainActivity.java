// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedprdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import com.webank.wedpr.common.Utils;
import com.webank.wedpr.crypto.CryptoClient;
import com.webank.wedpr.crypto.CryptoResult;
import com.webank.wedpr.scd.*;
import com.webank.wedpr.scd.proto.Predicate;
import com.webank.wedpr.vcl.VclClient;
import com.webank.wedpr.vcl.VclResult;
import com.webank.wedpr.scd.proto.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// TODO: Rename the package name to demo.
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            // Crypto demo.
            CryptoClient cryptoClient = new CryptoClient();
            cryptoDemo(cryptoClient);

            // VCL demo.
            VclClient vclClient = new VclClient();
            vclDemo(vclClient, 2, 2, 4);
            vclDemo(vclClient, 3, 4, 12);
            vclDemo(vclClient, 1, 2, 3);
            vclDemo(vclClient, 3, 4, 5);
            vclDemo(vclClient, -1, 4, 3);

            // SCD demo.
            IssuerClient issuerClient = new IssuerClient();
            UserClient userClient = new UserClient();
            VerifierClient verifierClient = new VerifierClient();
            scdDemo(issuerClient, userClient, verifierClient);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void cryptoDemo(CryptoClient cryptoClient)
        throws Exception {
        System.out.println("\n*******\nCRYPTO DEMO RUN\n*******");

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

    private static void vclDemo(VclClient vclClient, long c1Value, long c2Value, long c3Value)
            throws Exception {
        System.out.println("\n*******\nVCL DEMO RUN\n*******");
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

    private static final String NAME = "name";
    private static final String AGE = "age";
    private static final String GENDER = "gender";
    private static final String ISSUE_TIME = "issue_time";
    private static final String DEFAULT_USER_ID = "default_user_id";

    public static void scdDemo(
        IssuerClient issuerClient, UserClient userClient, VerifierClient verifierClient)
        throws Exception {
        System.out.println("\n*******\nSCD DEMO RUN\n*******");

        // An issuer defines the certificate schema and generates the certificate template.
        List<String> schema = Arrays.asList(NAME, AGE, GENDER, ISSUE_TIME);
        System.out.println("Encoded schema = " + schema);

        IssuerResult issuerResult = issuerClient.makeCertificateTemplate(schema);

        String certificateTemplate = issuerResult.certificateTemplate;
        String templatePrivateKey = issuerResult.templatePrivateKey;
        System.out.println("Encoded certificateTemplate = " + certificateTemplate);
        System.out.println("Encoded templatePrivateKey = " + templatePrivateKey);

        // A user fills the certificate template and prepares a request for the issuer to sign.
        Map<String, String> certificateDataInput = new HashMap<>();
        // TODO: Add a utility function to convert any string to a decimal string.
        // Before this utility function is implemented, the attribute value can only be a decimal
        // string.
        certificateDataInput.put(NAME, "123");
        certificateDataInput.put(AGE, "19");
        certificateDataInput.put(GENDER, "1");
        certificateDataInput.put(ISSUE_TIME, "12345");
        String certificateData = userClient.encodeAttributeDict(certificateDataInput);
        UserResult userResult = userClient.fillCertificate(certificateData, certificateTemplate);

        String signCertificateRequest = userResult.signCertificateRequest;
        String userPrivateKey = userResult.userPrivateKey;
        String certificateSecretsBlindingFactors = userResult.certificateSecretsBlindingFactors;
        String userNonce = userResult.userNonce;
        System.out.println("Encoded signCertificateRequest = " + signCertificateRequest);
        System.out.println("Encoded userPrivateKey = " + userPrivateKey);
        System.out.println(
            "Encoded certificateSecretsBlindingFactors = " + certificateSecretsBlindingFactors);
        System.out.println("Encoded userNonce = " + userNonce);

        // The issuer verifies the certificate signing request from the user and signs the certificate.
        issuerResult =
            issuerClient.signCertificate(
                certificateTemplate,
                templatePrivateKey,
                signCertificateRequest,
                DEFAULT_USER_ID,
                userNonce);

        String certificateSignature = issuerResult.certificateSignature;
        String issuerNonce = issuerResult.issuerNonce;
        System.out.println("Encoded certificateSignature = " + certificateSignature);
        System.out.println("Encoded issuerNonce = " + issuerNonce);

        // The user blinds the received certificateSignature to prevent the issuer to track the
        // certificate usage.
        userResult =
            userClient.blindCertificateSignature(
                certificateSignature,
                certificateData,
                certificateTemplate,
                userPrivateKey,
                certificateSecretsBlindingFactors,
                issuerNonce);

        String blindedCertificateSignature = userResult.certificateSignature;
        System.out.println("Encoded blindedCertificateSignature = " + blindedCertificateSignature);

        // A verifier sets a verification rule to:
        // Check AGE > 18 and,
        VerificationRuleSet.Builder verificationRuleSetBuilder = VerificationRuleSet.newBuilder();
        Predicate predicate =
            Predicate.newBuilder()
                .setAttributeName(AGE)
                .setPredicateType(PredicateType.GT.name())
                .setPredicateValue(18)
                .build();
        verificationRuleSetBuilder.addAttributePredicate(predicate);
        // Reveal the ISSUE_TIME attribute.
        verificationRuleSetBuilder.addRevealedAttributeName(ISSUE_TIME);

        String encodedVerificationRuleSet =
            verifierClient.protoToEncodedString(verificationRuleSetBuilder.build());
        System.out.println("Encoded verificationRuleSet = " + encodedVerificationRuleSet);

        String verificationNonce = verifierClient.getVerificationNonce().verificationNonce;

        // The user proves the signed certificate data satisfying the verification rules and does not
        // reveal any extra data.
        userResult =
            userClient.proveSelectiveDisclosure(
                encodedVerificationRuleSet,
                blindedCertificateSignature,
                certificateData,
                certificateTemplate,
                userPrivateKey,
                verificationNonce);

        String verifyRequest = userResult.verifyRequest;
        System.out.println("Encoded verifyRequest = " + verifyRequest);

        // The verifier verifies the required verification rule is satisfied and extracts the required
        // attribute.
        // This verification should be done before calling revealedAttributeDict.
        VerifierResult verifierResult =
            verifierClient.verifySelectiveDisclosure(encodedVerificationRuleSet, verifyRequest);
        System.out.println("Proof verification result = " + verifierResult.boolResult);

        verifierResult = verifierClient.getRevealedAttributes(verifyRequest);
        String encodedRevealedCertificateData = verifierResult.revealedAttributeDict;
        AttributeDict revealedCertificateData =
            AttributeDict.parseFrom(Utils.stringToBytes(encodedRevealedCertificateData));
        System.out.println("revealedCertificateData =" + revealedCertificateData);
    }
}