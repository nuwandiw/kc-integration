package com.calendar.frontendapp.security.oauth2.dpop;

import java.security.KeyPair;

import org.jboss.logging.Logger;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.util.DPoPGenerator;

public class DPoPService {

    private static final Logger log = Logger.getLogger(DPoPService.class);

    private static final String SSH_PRIVATE_KEY_PATH = "ssh/id_rsa";
    private static final String SSH_PUBLIC_KEY_PATH = "ssh/id_rsa.pub";

    private KeyPair keyPair;

    public DPoPService() {
        try {
            loadSSHKeyPair();
        } catch (Exception ex) {
            log.warn("Failed to load SSH keypair, will generate new one: " + ex.getMessage());
        }
    }

    public String generateDPoP(String httpMethod, String endpointUrl, String accessToken) {
        if (keyPair == null) {
            generateKeys();
        }
        return DPoPGenerator.generateRsaSignedDPoPProof(keyPair, httpMethod, endpointUrl, accessToken);
    }
    private void loadSSHKeyPair() throws Exception {
        try {
            keyPair = KeyPairLoader.loadKeyPair(SSH_PRIVATE_KEY_PATH, SSH_PUBLIC_KEY_PATH);
            log.info("DPoP RSA KeyPair loaded from SSH files successfully.");
        } catch (Exception ex) {
            log.error("Failed to load SSH KeyPair: " + ex.getMessage(), ex);
            throw ex;
        }
    }

    private void generateKeys() {
        keyPair = KeyUtils.generateRsaKeyPair(2048);
        log.info("New DPoP RSA keyPair generated.");
    }
}