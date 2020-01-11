package com.experthealth.cryptography.ms;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AsymmetricSigningService {

    /**
     *  Create a signature for a message using a private key stored on Cloud KMS
     *
     * Example keyName:
     *   "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
     */
    public static byte[] signAsymmetric(String keyName, byte[] message)
            throws IOException, NoSuchAlgorithmException {
        InputStream inputStream = new ClassPathResource("video-doctor-development-bc0f06865450.json").getInputStream();
        GoogleCredentials credentials = GoogleCredentials.fromStream(inputStream);

        KeyManagementServiceSettings keyManagementServiceSettings = KeyManagementServiceSettings
                .newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                .build();

        try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {

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
