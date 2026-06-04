package com.example.vulnerable.controller;

import com.example.vulnerable.repository.VulnerableUserRepository;
import java.util.List;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin("*")
public class VulnerableController {

    private final VulnerableUserRepository vulnerableUserRepository;

    public VulnerableController(VulnerableUserRepository vulnerableUserRepository) {
        this.vulnerableUserRepository = vulnerableUserRepository;
    }

    @GetMapping("/users/search")
    public List<?> searchUsers(@RequestParam String name) {
        return vulnerableUserRepository.searchByNameNativeQuery(name);
    }

    @GetMapping("/users/raw")
    public List<String> rawSearch(@RequestParam String name) {
        return vulnerableUserRepository.searchByRawStatement(name);
    }
}
