package com.example.springsecuritydemo.security;

import com.example.springsecuritydemo.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Autowired
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username: {}", username);
        log.info("Password: {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        log.info("successful Authentication: {}", authentication);
        User user = (User) authentication.getPrincipal();

        String accessToken = JwtUtil.generateToken(user.getUsername(),
            request.getRequestURL().toString(),
            new Date(System.currentTimeMillis() + 10 * 60 * 1000),
            user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
            );
        String refreshToken = JwtUtil.generateToken(user.getUsername(),
            request.getRequestURL().toString(),
            new Date(System.currentTimeMillis() + 30 * 60 * 1000),
            user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
            );

        response.setHeader("access_token", accessToken);
        response.setHeader("refresh_token", refreshToken);

        JwtUtil.addTokensToResponse(response, accessToken, refreshToken);
    }
}
