package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.demo.dto.JwtResponse;
import com.example.demo.dto.LoginRequestDto;
import com.example.demo.dto.RefreshTokenRequestDto;
import com.example.demo.dto.SignUpRequestDto;
import com.example.demo.service.AuthService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<JwtResponse> signUp(@RequestBody SignUpRequestDto signUpRequestDto) {
        JwtResponse jwtResponse = authService.signUp(signUpRequestDto);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginRequestDto loginRequestDto) {
        JwtResponse jwtResponse = authService.login(loginRequestDto);
        return ResponseEntity.ok(jwtResponse);
    }

     @PostMapping("/refresh-token")
     public ResponseEntity<JwtResponse> refreshToken(@RequestBody RefreshTokenRequestDto refreshTokenRequestDto) {
        JwtResponse jwtResponse = authService.refreshToken(refreshTokenRequestDto);
        return ResponseEntity.ok(jwtResponse);
    }
}