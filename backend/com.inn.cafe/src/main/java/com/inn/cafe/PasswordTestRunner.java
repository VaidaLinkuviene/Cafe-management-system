package com.inn.cafe;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordTestRunner implements CommandLineRunner {

    private final PasswordEncoder passwordEncoder;

    public PasswordTestRunner(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        boolean matches = passwordEncoder.matches(
                "123456",
                "$2a$10$2PdGvmQNJ2QvGYbd2rP/PeHQMMl.hRatLkCVsnUlwZvkm2BFS7ILm"
        );
        System.out.println("Password matches: " + matches);
    }
}

