// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

package com.webank.wedpr.crypto;

import com.webank.wedpr.common.WedprException;

/** Client class used by WeDPR crypto. This is the main interface class for Java apps using VCL functions. */
public class CryptoClient {
    /**
     * Encrypts the message into ciphertext using the public key
     * by ECIES(elliptic curve integrate encrypt scheme),
     * where secp256k1 is the elliptic curve used by ECIES.
     * @param pubKey the public key used for encrypt.
     * @param plaintext the string to be encrypted.
     * @return CryptoResult the string obtained after encrypting the plaintext.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult secp256k1EciesEncrypt(String pubKey, String plaintext) throws WedprException {
        return NativeInterface.secp256k1EciesEncrypt(pubKey, plaintext).expectNoError();
    }

    /**
     * Decrypts the ciphertext into a message using the private key
     * by ECIES(elliptic curve integrate encrypt scheme),
     * where secp256k1 is the elliptic curve used by ECIES.
     * @param priKey the private key used for decrypt.
     * @param ciphertext the string to be decrypted.
     * @return CryptoResult the string obtained after decrypting the ciphertext.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult secp256k1EciesDecrypt(String priKey, String ciphertext) throws WedprException {
        return NativeInterface.secp256k1EciesDecrypt(priKey, ciphertext).expectNoError();
    }

    /**
     * Generates a pair of keys for encryption and signature algorithm,
     * where secp256k1 is the elliptic curve used by key generation algorithm.
     * @return CryptoResult a pair of keys used for encryption and signature algorithm.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult secp256k1GenKeyPair() throws WedprException {
        return NativeInterface.secp256k1GenKeyPair().expectNoError();
    }

    /**
     * Hashes a string using the elliptic curve keccak256.
     * @param message the string to be hashed.
     * @return CryptoResult the hash of message.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult keccak256Hash(String message) throws WedprException {
        return NativeInterface.keccak256Hash(message).expectNoError();
    }

    /**
     * Signs the message into signature using the private key,
     * where secp256k1 is the elliptic curve used by signature.
     * @param priKey the private key used for sign.
     * @param messageHash the string to be signed.
     * @return CryptoResult the signature of the messageHash.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult secp256k1Sign(String priKey, String messageHash) throws WedprException {
        return NativeInterface.secp256k1Sign(priKey,messageHash).expectNoError();
    }

    /**
     * Verifies whether the signature obtained by secp256k1Sign signing message
     * matches the message.
     * @param pubKey the public key used for verifing a signature.
     * @param messageHash the string has been signed.
     * @param signature the signed string of the messageHash.
     * @return CryptoResult the result of verifing a signature,
     * bool = ture means the signature is indeed the result of
     * using secp256k1Sign to sign the messageHash,
     * otherwise the signature and the messageHash do not match.
     * @throws WedprException if any error occurred.
     */
    public CryptoResult secp256k1Verify(String pubKey, String messageHash, String signature) throws WedprException {
        return NativeInterface.secp256k1Verify(pubKey, messageHash, signature).expectNoError();
    }

    // TODO: Add a getVclConfig function to expose the value of RANGE_SIZE_IN_BITS.
}
