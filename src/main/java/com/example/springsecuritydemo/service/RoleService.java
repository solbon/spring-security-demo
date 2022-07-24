package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.model.Role;
import com.example.springsecuritydemo.repo.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;

    public Optional<Role> getRole(Long id) {
        return roleRepository.findById(id);
    }

    public List<Role> getRoles() {
        return roleRepository.findAll();
    }

    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }
}
