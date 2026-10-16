package com.securedeploy.github.app;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "securedeploy.github.app")
public class GitHubAppProperties {
    private boolean enabled;
    private long appId;
    private String clientId = "";
    private String clientSecret = "";
    private String slug = "";
    private String privateKeyFile = "";
    private String encryptionKey = "";
    private String callbackUrl = "http://localhost:5173/";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean value) { enabled = value; }
    public long getAppId() { return appId; }
    public void setAppId(long value) { appId = value; }
    public String getClientId() { return clientId; }
    public void setClientId(String value) { clientId = value; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String value) { clientSecret = value; }
    public String getSlug() { return slug; }
    public void setSlug(String value) { slug = value; }
    public String getPrivateKeyFile() { return privateKeyFile; }
    public void setPrivateKeyFile(String value) { privateKeyFile = value; }
    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String value) { encryptionKey = value; }
    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String value) { callbackUrl = value; }

    public void requireConfigured() {
        try {
            URI uri = URI.create(callbackUrl);
            boolean local = "http".equals(uri.getScheme()) && "localhost".equals(uri.getHost());
            if (!enabled || appId <= 0 || !clientId.matches("[a-zA-Z0-9._-]{1,100}") || clientSecret.isBlank()
                    || !slug.matches("[a-zA-Z0-9-]+") || privateKeyFile.isBlank()
                    || java.util.Base64.getDecoder().decode(encryptionKey).length != 32
                    || (!"https".equals(uri.getScheme()) && !local) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException();
            }
        } catch (RuntimeException invalid) { throw GitHubAppException.notConfigured(); }
    }
}
