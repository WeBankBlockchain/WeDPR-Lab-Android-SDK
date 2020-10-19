// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedprdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.crypto.CryptoClient;
import com.webank.wedpr.crypto.CryptoResult;
import com.webank.wedpr.vcl.VclClient;
import com.webank.wedpr.vcl.VclResult;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        CryptoClient cryptoClient = new CryptoClient();
        VclClient vclClient = new VclClient();
        CryptoResult cryptoResult = null;
        try {
            runCryptoDemo(cryptoClient);
            runVclProofs(vclClient, 2, 2, 4);
            runVclProofs(vclClient, 3, 4, 12);
            runVclProofs(vclClient, 1, 2, 3);
            runVclProofs(vclClient, 3, 4, 5);
            runVclProofs(vclClient, -1, 4, 3);
        } catch (WedprException e) {
            e.printStackTrace();
        }
    }

    private static void runVclProofs(VclClient vclClient, long c1Value, long c2Value, long c3Value)
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

    private static void runCryptoDemo(CryptoClient cryptoClient)
            throws WedprException {
        System.out.println("\n*******\nWeDPR CRYPTO RUN\n*******");
        System.out.println(
                "Generate EC keyPair" + "\n");

        CryptoResult cryptoResult = cryptoClient.secp256k1GenKeyPair();
        String publicKey = cryptoResult.publicKey;
        String privateKey = cryptoResult.privateKey;
        System.out.println("public key = " + publicKey);
        System.out.println("private key = " + privateKey);

        String message = "V2VEUFIgQ3J5cHRvIERlbW8=";
        System.out.println(
                "Hash message = " + message + " with keccak256" + "\n");
        String messageHash = cryptoClient.keccak256Hash(message).hash;
        System.out.println(
                "messageHash = " + messageHash);


        System.out.println(
                "Sign data with message hash = " + messageHash + " by EC keyPair private key" + "\n");

        String signature = cryptoClient.secp256k1Sign(privateKey, messageHash).signature;

        System.out.println(
                "Signature = " + signature);

        System.out.println(
                "Verify Signature with message hash = " + messageHash + " by EC keyPair public key" + "\n");
        boolean result = cryptoClient.secp256k1Verify(publicKey, messageHash, signature).booleanResult;
        System.out.println(
                "result = " + result);

        System.out.println(
                "Encrypt data with messageHash = " + messageHash + " by EC keyPair public key" + "\n");
        String cipherData = cryptoClient.secp256k1EciesEncrypt(publicKey, messageHash).encryptedData;
        System.out.println(
                "cipherData = " + cipherData);

        System.out.println(
                "Decrypt data by EC keyPair private key" + "\n");
        String plainData = cryptoClient.secp256k1EciesDecrypt(privateKey, cipherData).decryptedData;
        System.out.println(
                "plainData = " + plainData);
    }
}