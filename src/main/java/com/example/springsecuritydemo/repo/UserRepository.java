package com.example.springsecuritydemo.repo;

import com.example.springsecuritydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
