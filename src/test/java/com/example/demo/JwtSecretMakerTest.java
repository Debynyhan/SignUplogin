package com.example.demo;

import io.jsonwebtoken.Jwts;

import jakarta.xml.bind.DatatypeConverter;

import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

public class JwtSecretMakerTest {

    @Test
    public void generateSecretKey() {
        SecretKey key = Jwts.SIG.HS512.key().build();
        String encodedKey = DatatypeConverter.printHexBinary(key.getEncoded());
        System.out.printf("\nkey = [%s]\n", encodedKey);
    }

}
