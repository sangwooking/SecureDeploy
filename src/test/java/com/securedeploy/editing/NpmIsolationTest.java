package com.securedeploy.editing;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NpmIsolationTest {
    @TempDir Path temp;
    @Test void enabledLegacyFlagsAndExecutableCannotBypassAbsentIsolation()throws Exception {
        var marker=temp.resolve("started");var executable=temp.resolve("npm");
        Files.writeString(executable,"#!/bin/sh\n: > '"+marker+"'\n");executable.toFile().setExecutable(true);
        var json=new ObjectMapper();var legacy=new NpmUpdateGenerator(json,true,executable.toString());
        var tree=new NpmTreeExecutor(json,executable.toString());
        assertFalse(legacy.enabled());assertFalse(tree.available());
        // These benign local canaries must never reach npm or metadata HTTP, even before parsing.
        for(String text:new String[]{"{}","{\"scripts\":{\"install\":\"owned-canary\"}}",
                "{\"dependencies\":{\"x\":\"file:../outside\"}}",
                "{\"dependencies\":{\"x\":\"git+https://example.invalid/x\"}}",
                "{\"dependencies\":{\"x\":\"http://127.0.0.1:1/x\"}}"}){
            byte[] input=text.getBytes(StandardCharsets.UTF_8);
            assertEquals("NPM_ISOLATION_UNAVAILABLE",assertThrows(IllegalStateException.class,
                    ()->tree.generate(input,input,"dependencies","x","1.0.1")).getMessage());
            assertEquals("NPM_ISOLATION_UNAVAILABLE",assertThrows(IllegalStateException.class,
                    ()->legacy.generate(input,input,"x","1.0.0","1.0.1",true)).getMessage());
        }
        assertFalse(Files.exists(marker));
    }
}
