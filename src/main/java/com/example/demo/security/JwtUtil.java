package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${jwt.expiration-ms}")
    private long JWT_EXPIRATION_MS;

    @Value("${jwt.refresh-token.expiration-ms}")
    private long REFRESH_TOKEN_EXPIRATION_MS;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userDetails.getUsername()); // Subject (username)
        claims.put("roles", userDetails.getAuthorities()); // User roles
        claims.put("userId", ((CustomUserDetails) userDetails).getUserId()); // Custom claim: userId

        return Jwts.builder()
            .claims(claims) // Use the modern claims method
            .subject(userDetails.getUsername()) // Subject (username)
            .issuedAt(Date.from(Instant.now())) // Issued at (current time)
            .expiration(Date.from(Instant.now().plusMillis(JWT_EXPIRATION_MS))) // Expiration time
            .signWith(generateKey()) // Sign with SecretKey
            .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(generateKey()) // Verify with SecretKey
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Collection<? extends GrantedAuthority> extractRoles(String token) {
        return extractClaim(token, claims -> (Collection<? extends GrantedAuthority>) claims.get("roles"));
    }

    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

}