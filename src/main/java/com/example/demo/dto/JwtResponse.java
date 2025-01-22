package com.example.demo.dto;

import java.util.Collection;

public class JwtResponse {
    private String token;
    private String refreshToken;
    private long expiresIn; // Expiration time in seconds
    private String username;
    private Collection<String> roles;

    // Constructor
    public JwtResponse(String token, String refreshToken, long expiresIn, String username, Collection<String> roles) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.username = username;
        this.roles = roles;
    }

    // Getters
    public String getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public String getUsername() {
        return username;
    }

    public Collection<String> getRoles() {
        return roles;
    }
}