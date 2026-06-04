package com.example.secure.controller;

import com.example.secure.repository.UserRepository;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/search")
    public ResponseEntity<List<UserSummary>> search(@RequestParam String email) {
        List<UserSummary> result = userRepository.findByEmail(email)
                .map(user -> List.of(new UserSummary(user.getId(), user.getEmail(), user.getDisplayName())))
                .orElseGet(List::of);

        return ResponseEntity.ok(result);
    }

    public record UserSummary(Long id, String email, String displayName) {
    }
}
