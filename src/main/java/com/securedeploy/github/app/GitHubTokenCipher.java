package com.securedeploy.github.app;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class GitHubTokenCipher {
    private final GitHubAppProperties properties;
    public GitHubTokenCipher(GitHubAppProperties properties) { this.properties = properties; }
    public String encrypt(long userId, String token) {
        byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce) + "." + Base64.getEncoder().encodeToString(
                crypt(Cipher.ENCRYPT_MODE, userId, nonce, token.getBytes(StandardCharsets.UTF_8)));
    }
    public String decrypt(long userId, String encrypted) {
        try {
            String[] parts = encrypted.split("\\.", -1);
            if (parts.length != 2) throw new IllegalArgumentException();
            return new String(crypt(Cipher.DECRYPT_MODE, userId, Base64.getDecoder().decode(parts[0]),
                    Base64.getDecoder().decode(parts[1])), StandardCharsets.UTF_8);
        } catch (RuntimeException failure) { throw GitHubAppException.reconnect(); }
    }
    private byte[] crypt(int mode, long userId, byte[] nonce, byte[] input) {
        try {
            byte[] key = Base64.getDecoder().decode(properties.getEncryptionKey());
            if (key.length != 32 || nonce.length != 12) throw new IllegalArgumentException();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(("securedeploy-github-user:" + userId).getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(input);
        } catch (Exception failure) { throw GitHubAppException.notConfigured(); }
    }
}
