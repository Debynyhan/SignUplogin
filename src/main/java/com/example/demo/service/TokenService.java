package com.example.demo.service;

import com.example.demo.dto.JwtResponse;
import com.example.demo.security.JwtUtils;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtUtils jwtUtils;

    public TokenService(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    public JwtResponse generateTokens(UserDetails userDetails) {
        // Generate access token
        String accessToken = jwtUtils.generateToken(userDetails);

        // Generate refresh token
        String refreshToken = jwtUtils.generateRefreshToken(userDetails);

        // Extract roles
        Collection<String> roles = userDetails.getAuthorities().stream()
            .map(grantedAuthority -> grantedAuthority.getAuthority())
            .collect(Collectors.toList());

        // Create and return JwtResponse
        return new JwtResponse(
            accessToken,
            refreshToken,
            jwtUtils.getExpirationInSeconds(accessToken), // Expiration time in seconds
            userDetails.getUsername(),
            roles
        );
    }
}