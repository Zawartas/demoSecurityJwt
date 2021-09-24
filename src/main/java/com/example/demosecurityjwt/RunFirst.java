package com.example.demosecurityjwt;

import com.example.demosecurityjwt.domain.Role;
import com.example.demosecurityjwt.domain.User;
import com.example.demosecurityjwt.service.UserService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
@AllArgsConstructor
public class RunFirst implements CommandLineRunner {

    UserService userService;

    @Override
    public void run(String... args) {
        userService.saveRole(new Role(null, "ROLE_USER"));
        userService.saveRole(new Role(null, "ROLE_MANAGER"));
        userService.saveRole(new Role(null, "ROLE_ADMIN"));
        userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

        userService.saveUser(new User(null, "John Travolta", "john", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Will Smith", "will", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Jan Kowalski", "jan", "1234", new ArrayList<>()));
        userService.saveUser(new User(null, "Zbigniew Bogucki", "zbigniew", "1234", new ArrayList<>()));

        userService.addRoleToUser("john", "ROLE_USER");
        userService.addRoleToUser("will", "ROLE_MANAGER");
        userService.addRoleToUser("jan", "ROLE_ADMIN");
        userService.addRoleToUser("zbigniew", "ROLE_SUPER_ADMIN");
    }
}
