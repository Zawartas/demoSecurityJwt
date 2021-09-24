package com.example.demosecurityjwt.service;

import com.example.demosecurityjwt.domain.Role;
import com.example.demosecurityjwt.domain.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);

    Role saveRole(Role user);

    void addRoleToUser(String username, String role);

    User getUser(String username);

    List<User> getUsers();
}
