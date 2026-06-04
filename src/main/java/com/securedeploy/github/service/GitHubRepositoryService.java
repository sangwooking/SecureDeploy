package com.securedeploy.github.service;

import com.securedeploy.github.model.ClonedRepository;
import com.securedeploy.global.config.FileStorageProperties;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.global.util.FileUtils;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.TransportException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class GitHubRepositoryService {

    private static final Pattern GITHUB_PATH_PATTERN = Pattern.compile("^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\\.git)?/?$");

    private final FileStorageProperties storageProperties;

    public GitHubRepositoryService(FileStorageProperties storageProperties) {
        this.storageProperties = storageProperties;
    }

    public ClonedRepository clonePublicRepository(String repositoryUrl) {
        String normalizedUrl = validateAndNormalizeUrl(repositoryUrl);
        String repositoryName = resolveRepositoryName(normalizedUrl);
        Path workspacePath = null;

        try {
            Path baseDir = Path.of(storageProperties.getTempDir()).toAbsolutePath().normalize();
            workspacePath = Files.createDirectories(baseDir.resolve("github-" + UUID.randomUUID()));
            Path repositoryRoot = workspacePath.resolve(repositoryName).normalize();

            cloneRepository(normalizedUrl, repositoryRoot);
            return new ClonedRepository(repositoryName, normalizedUrl, workspacePath, repositoryRoot);
        } catch (IOException exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "GitHub 저장소 분석용 임시 디렉터리를 생성할 수 없습니다.");
        } catch (RuntimeException exception) {
            FileUtils.deleteRecursively(workspacePath);
            throw exception;
        }
    }

    private String validateAndNormalizeUrl(String repositoryUrl) {
        if (repositoryUrl == null || repositoryUrl.isBlank()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "GitHub Repository URL은 필수입니다.");
        }

        String trimmedUrl = repositoryUrl.strip();
        URI uri;
        try {
            uri = new URI(trimmedUrl);
        } catch (URISyntaxException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "잘못된 GitHub Repository URL입니다.");
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        String path = uri.getPath();
        if (!"https".equalsIgnoreCase(scheme)
                || host == null
                || uri.getUserInfo() != null
                || uri.getQuery() != null
                || uri.getFragment() != null
                || !"github.com".equalsIgnoreCase(host)
                || path == null
                || !GITHUB_PATH_PATTERN.matcher(path).matches()) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "https://github.com/{owner}/{repository}.git 형식의 공개 저장소 URL만 지원합니다.");
        }

        String normalizedPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return "https://github.com" + normalizedPath;
    }

    private String resolveRepositoryName(String normalizedUrl) {
        String repositoryName = normalizedUrl.substring(normalizedUrl.lastIndexOf('/') + 1);
        if (repositoryName.toLowerCase(Locale.ROOT).endsWith(".git")) {
            repositoryName = repositoryName.substring(0, repositoryName.length() - 4);
        }
        return repositoryName.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private void cloneRepository(String repositoryUrl, Path repositoryRoot) {
        try (Git ignored = Git.cloneRepository()
                .setURI(repositoryUrl)
                .setDirectory(repositoryRoot.toFile())
                .setCloneAllBranches(false)
                .setTimeout(30)
                .call()) {
            // JGit closes repository resources through try-with-resources.
        } catch (InvalidRemoteException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "잘못된 GitHub 저장소 URL입니다.");
        } catch (TransportException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "GitHub 저장소에 접근할 수 없습니다. URL, 공개 저장소 여부, 네트워크 상태를 확인해 주세요.");
        } catch (GitAPIException exception) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST, "GitHub 저장소를 가져오는 중 오류가 발생했습니다. 저장소 URL을 확인한 뒤 다시 시도해 주세요.");
        }
    }
}
