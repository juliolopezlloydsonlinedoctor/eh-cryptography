package com.experthealth.cryptography.lib;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

public class AsymmetricSigningService {

    /**
     *  Create a signature for a message using a private key stored on Cloud KMS
     *
     * Example keyName:
     *   "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
     */
    public static byte[] signAsymmetric(String keyName, byte[] message)
            throws IOException, NoSuchAlgorithmException {
        // Create the Cloud KMS client.
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {

            // Note: some key algorithms will require a different hash function
            // For example, EC_SIGN_P384_SHA384 requires SHA-384
            byte[] messageHash = MessageDigest.getInstance("SHA-256").digest(message);

            AsymmetricSignRequest request = AsymmetricSignRequest.newBuilder()
                    .setName(keyName)
                    .setDigest(Digest.newBuilder().setSha256(ByteString.copyFrom(messageHash)))
                    .build();

            AsymmetricSignResponse response = client.asymmetricSign(request);
            return response.getSignature().toByteArray();
        }
    }
}
