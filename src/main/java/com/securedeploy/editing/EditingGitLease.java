package com.securedeploy.editing;

import java.io.IOException;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;

/** Cross-process leases keep startup cleanup from deleting another live acquisition. */
final class EditingGitLease implements AutoCloseable {
    private static final Object MUTEX = new Object();
    private final Path base, root;
    private final FileChannel channel;
    private final FileLock lease;
    private EditingGitLease(Path base, Path root, FileChannel channel, FileLock lease) {
        this.base=base; this.root=root; this.channel=channel; this.lease=lease;
    }
    Path root() { return root; }
    static EditingGitLease open(Path base) throws IOException {
        synchronized (MUTEX) {
            prepare(base);
            try (var manager=control(base); var ignored=manager.lock()) {
                sweep(base);
                Path root=Files.createTempDirectory(base,"editing-github-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                FileChannel channel=null;
                try {
                    channel=control(root);
                    return new EditingGitLease(base,root,channel,channel.lock());
                } catch (Exception failure) { if(channel!=null)channel.close(); remove(root); throw failure; }
            }
        }
    }
    static void cleanup(Path base) throws IOException {
        synchronized (MUTEX) {
            if (!Files.exists(base,LinkOption.NOFOLLOW_LINKS)) return;
            prepare(base);
            try(var entries=Files.newDirectoryStream(base,"editing-github-*")){if(!entries.iterator().hasNext())return;}
            try(var manager=control(base); var ignored=manager.lock()){sweep(base);}
        }
    }
    private static void prepare(Path base) throws IOException {
        Files.createDirectories(base);
        if (!Files.isDirectory(base,LinkOption.NOFOLLOW_LINKS)) throw new IOException("Unsafe temporary root");
    }
    private static FileChannel control(Path path) throws IOException {
        return FileChannel.open(path.resolve(".editing-lease"),java.util.Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }
    private static void sweep(Path base) throws IOException {
        try(var entries=Files.newDirectoryStream(base,"editing-github-*")) {
            int count=0;
            for(var path:entries) {
                if(++count>1000)throw new IOException("Too many stale acquisitions");
                if(!Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS))throw new IOException("Unsafe stale acquisition");
                boolean stale=false;
                try(var channel=control(path)) {
                    try(var lock=channel.tryLock()){stale=lock!=null;}
                    catch(OverlappingFileLockException active){ /* Another request in this JVM owns the source. */ }
                }
                if(stale)remove(path);
            }
        }
    }
    private static void remove(Path path) throws IOException {
        try(var paths=Files.walk(path)) { for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p); }
    }
    @Override public void close() throws IOException {
        synchronized(MUTEX) {
            try(var manager=control(base); var ignored=manager.lock()) {
                lease.release(); channel.close(); remove(root);
            }
        }
    }
}
