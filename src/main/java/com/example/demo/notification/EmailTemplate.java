package com.example.demo.notification;

public class EmailTemplate {

    public static String getVerificationEmailContent(String token) {
        return "Click the link to verify your email: http://yourapp.com/verify?token=" + token;
    }
}