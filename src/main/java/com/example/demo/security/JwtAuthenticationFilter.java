package com.example.demo.security;

import java.util.ArrayList;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// security/jwt/JwtAuthenticationFilter.java
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setFilterProcessesUrl("/auth/login"); // Override default login URL
    }

    @Override
    public Authentication attemptAuthentication(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws AuthenticationException {
        try {
            // Parse email/password from request body
            SignInRequest credentials = new ObjectMapper()
                .readValue(request.getInputStream(), SignInRequest.class);

            return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    credentials.getEmail(),
                    credentials.getPassword(),
                    new ArrayList<>()
                )
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain,
        Authentication authResult
    ) throws IOException {
        // Generate JWT token
        String token = JwtUtils.generateToken(authResult.getName());
        response.addHeader("Authorization", "Bearer " + token);
    }
}