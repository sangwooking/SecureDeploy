package com.securedeploy.github.app;

import org.springframework.data.jpa.repository.JpaRepository;

public interface GitHubConnectionRepository extends JpaRepository<GitHubConnectionEntity, Long> { }
