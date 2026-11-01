package com.securedeploy.editing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** No host fallback. A verified OS-isolated execution adapter is not available in this release. */
@Component
public class NpmTreeExecutor {
    public record Output(byte[] manifest, byte[] lockfile, String npmVersion, String nodeVersion) { }
    public NpmTreeExecutor(ObjectMapper json,
            @Value("${securedeploy.editing.npm-executable:/opt/homebrew/bin/npm}") String executable) { }
    public boolean available() { return false; }
    public Output generate(byte[] manifest, byte[] lockfile, String section, String root, String candidate) throws Exception {
        throw new IllegalStateException("NPM_ISOLATION_UNAVAILABLE");
    }
}
