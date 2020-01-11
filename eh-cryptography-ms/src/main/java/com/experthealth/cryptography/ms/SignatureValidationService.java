package com.experthealth.cryptography.ms;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.common.io.BaseEncoding;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class SignatureValidationService {
    /**
     * Verify the validity of an 'EC_SIGN_P256_SHA256' signature for the
     * specified message
     *
     * Example keyName:
     *   "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
     */
    public static boolean verifySignatureEC(String keyName, byte[] message, byte[] signature)
            throws IOException, GeneralSecurityException {
        InputStream inputStream = new ClassPathResource("video-doctor-development-bc0f06865450.json").getInputStream();
        GoogleCredentials credentials = GoogleCredentials.fromStream(inputStream);

        KeyManagementServiceSettings keyManagementServiceSettings = KeyManagementServiceSettings
                .newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                .build();

        // Create the Cloud KMS client.
        try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {
            // Get the public key
            com.google.cloud.kms.v1.PublicKey pub = client.getPublicKey(keyName);
            String pemKey = pub.getPem();
            pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
            pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
            pemKey = pemKey.replaceAll("\\s", "");
            byte[] derKey = BaseEncoding.base64().decode(pemKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
            PublicKey ecKey = KeyFactory.getInstance("EC").generatePublic(keySpec);

            // Verify the 'EC_SIGN_P256_SHA256' signature
            // For other key algorithms:
            // http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
            Signature ecVerify = Signature.getInstance("SHA256withECDSA");
            ecVerify.initVerify(ecKey);
            ecVerify.update(message);
            return ecVerify.verify(signature);
        }
    }
}
