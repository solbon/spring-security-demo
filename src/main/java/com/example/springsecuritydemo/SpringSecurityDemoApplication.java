package com.example.springsecuritydemo;

import com.example.springsecuritydemo.model.Role;
import com.example.springsecuritydemo.model.User;
import com.example.springsecuritydemo.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityDemoApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(Role.builder().name("ROLE_USER").build());
			userService.saveRole(Role.builder().name("ROLE_MANAGER").build());
			userService.saveRole(Role.builder().name("ROLE_ADMIN").build());
			userService.saveRole(Role.builder().name("ROLE_SUPER_ADMIN").build());

			userService.saveUser(User.builder().name("Bob").username("bob").password("123").roles(new ArrayList<>()).build());
			userService.saveUser(User.builder().name("Adam").username("adamuś").password("123").roles(new ArrayList<>()).build());
			userService.saveUser(User.builder().name("Piotr").username("łysy").password("123").roles(new ArrayList<>()).build());
			userService.saveUser(User.builder().name("Damian").username("praszwagier").password("123").roles(new ArrayList<>()).build());

			userService.addRoleToUser("bob", "ROLE_USER");
			userService.addRoleToUser("adamuś", "ROLE_MANAGER");
			userService.addRoleToUser("łysy", "ROLE_ADMIN");
			userService.addRoleToUser("praszwagier", "ROLE_USER");
			userService.addRoleToUser("praszwagier", "ROLE_MANAGER");
			userService.addRoleToUser("praszwagier", "ROLE_ADMIN");
			userService.addRoleToUser("praszwagier", "ROLE_SUPER_ADMIN");

		};
	}

}
