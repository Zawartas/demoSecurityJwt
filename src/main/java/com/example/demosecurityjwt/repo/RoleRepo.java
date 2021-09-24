package com.example.demosecurityjwt.repo;

import com.example.demosecurityjwt.domain.Role;
import com.example.demosecurityjwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
