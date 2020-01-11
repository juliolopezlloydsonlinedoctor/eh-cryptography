package com.experthealth.cryptography.ms.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;

import static com.experthealth.cryptography.ms.AsymmetricSigningService.signAsymmetric;
import static com.experthealth.cryptography.ms.SignatureValidationService.verifySignatureEC;

@RestController
public class SigningController {

    private byte[] lastSignature;
    private final String KEY_NAME =
            "projects/video-doctor-development/locations/europe-west2/keyRings/demo-ring/cryptoKeys/demo-key/cryptoKeyVersions/1";

    @GetMapping(value = "/sign/{message}")
    public String sign(@PathVariable String message) throws Exception {
        byte[] signedMessage = signAsymmetric(KEY_NAME, message.getBytes(StandardCharsets.UTF_8));
        this.lastSignature = signedMessage;
        String result = new String(signedMessage);
        System.out.println("signed!!!! with signature: " + result);
        return result;
    }

    @GetMapping(value = "/verify/{message}")
    public Boolean verify(@PathVariable String message) throws Exception {
        String keyName = "projects/video-doctor-development/locations/europe-west2/keyRings/demo-ring/cryptoKeys/demo-key/cryptoKeyVersions/1";
        boolean verfied = verifySignatureEC(KEY_NAME, message.getBytes(StandardCharsets.UTF_8), this.lastSignature);
        System.out.println("verified!!! result = " + verfied);
        return verfied;
    }
}
