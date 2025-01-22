package com.example.demo.service;


import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.security.CustomUserDetails;
import com.example.demo.dto.JwtResponse;
import com.example.demo.dto.LoginRequestDto;
import com.example.demo.dto.RefreshTokenRequestDto;
import com.example.demo.dto.SignUpRequestDto;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.JwtUtil;


@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
   

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthenticationManager authenticationManager, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
    }

    public ResponseEntity<?> signUp(SignUpRequestDto signUpRequest) {
        // Validate and save user
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setEmail(signUpRequest.getEmail());
        userRepository.save(user);
        
        // Generate a token using UserDetails
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtUtil.generateToken(userDetails);

        // Send verification email (domain logic)
        emailService.sendVerificationEmail(user.getEmail(), token);

        return ResponseEntity.ok("User registered successfully. Please check your email for verification.");

    }

    

    public JwtResponse login(LoginRequestDto loginRequest) {
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequest.getPassword())
        );

        // Generate JWT using UserDetails
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    public ResponseEntity<?> refreshToken(RefreshTokenRequestDto refreshTokenRequest) {
        // Validate refresh token and issue new JWT
        String newJwt = jwtUtil.refreshToken(refreshTokenRequest.getRefreshToken());
        return ResponseEntity.ok(new JwtResponse(newJwt));
    }
}