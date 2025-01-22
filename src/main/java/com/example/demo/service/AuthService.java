package com.example.demo.service;

import com.example.demo.dto.JwtResponse;
import com.example.demo.dto.LoginRequestDto;
import com.example.demo.dto.SignUpRequestDto;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.CustomUserDetails;
import com.example.demo.security.CustomUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       TokenService tokenService, AuthenticationManager authenticationManager,
                       CustomUserDetailsService customUserDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.customUserDetailsService = customUserDetailsService;
    }

    public JwtResponse signUp(SignUpRequestDto signUpRequestDto) {
        // Create a new User entity
        User user = new User();
        user.setUsername(signUpRequestDto.getUsername());
        user.setPassword(passwordEncoder.encode(signUpRequestDto.getPassword()));
        user.setEmail(signUpRequestDto.getEmail());
        user.setRoles(Collections.singletonList("ROLE_USER")); // Default role
        userRepository.save(user);

        // Generate tokens
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(user.getUsername());
        return tokenService.generateTokens(userDetails);
    }

    public JwtResponse login(LoginRequestDto loginRequestDto) {
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword())
        );

        // Generate tokens
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return tokenService.generateTokens(userDetails);
    }
}