package com.securedeploy.github.app;

import com.securedeploy.persistence.entity.UserEntity;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "github_connections")
public class GitHubConnectionEntity {
    @Id @Column(name = "user_id") private Long userId;
    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id", insertable = false, updatable = false) private UserEntity user;
    @Column(nullable = false) private long githubUserId;
    @Column(nullable = false, length = 100) private String githubLogin;
    @com.fasterxml.jackson.annotation.JsonIgnore
    @Column(nullable = false, columnDefinition = "TEXT") private String encryptedAccessToken;
    @Column(nullable = false) private Instant expiresAt;
    @Column(nullable = false) private Instant connectedAt;
    protected GitHubConnectionEntity() { }
    public GitHubConnectionEntity(UserEntity user, long githubUserId, String login, String ciphertext, Instant expiresAt) {
        this.user = user; this.userId = user.getId(); this.githubUserId = githubUserId;
        this.githubLogin = login; this.encryptedAccessToken = ciphertext; this.expiresAt = expiresAt; this.connectedAt = Instant.now();
    }
    public Long getUserId() { return userId; }
    public long getGithubUserId() { return githubUserId; }
    public String getGithubLogin() { return githubLogin; }
    public String getEncryptedAccessToken() { return encryptedAccessToken; }
    public Instant getExpiresAt() { return expiresAt; }
}
