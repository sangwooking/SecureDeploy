package com.securedeploy.editing;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EditingGitLeaseTest {
    @TempDir Path temp;
    @Test void activeLeaseSurvivesSweepAndClosedLeaseRemovesSources() throws Exception {
        Path root;
        try(var lease=EditingGitLease.open(temp)) {
            root=lease.root(); Files.writeString(root.resolve("synthetic-source"),"fixture");
            EditingGitLease.cleanup(temp); assertTrue(Files.exists(root.resolve("synthetic-source")));
            try(var second=EditingGitLease.open(temp)){assertTrue(Files.isDirectory(root));}
        }
        assertFalse(Files.exists(root));
    }
    @Test void restartRemovesUnleasedSourcesWithoutTouchingUnrelatedFiles() throws Exception {
        Path stale=Files.createDirectory(temp.resolve("editing-github-stale")); Files.writeString(stale.resolve("synthetic-source"),"fixture");
        Path unrelated=Files.writeString(temp.resolve("existing-user-file"),"keep");
        EditingGitLease.cleanup(temp); assertFalse(Files.exists(stale)); assertTrue(Files.exists(unrelated));
    }
    @Test void neverFollowsStaleSymlink() throws Exception {
        Path original=Files.createDirectory(temp.resolve("unrelated")); Files.writeString(original.resolve("keep"),"keep");
        Files.createSymbolicLink(temp.resolve("editing-github-link"),original);
        assertThrows(java.io.IOException.class,()->EditingGitLease.cleanup(temp)); assertTrue(Files.exists(original.resolve("keep")));
    }
    @Test void zipOnlyStartupDoesNotCreateImplicitDiskState() throws Exception {
        EditingGitLease.cleanup(temp);
        try(var paths=Files.list(temp)){assertEquals(0,paths.count());}
    }
}
