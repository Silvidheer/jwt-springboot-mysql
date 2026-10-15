package com.example.jwtdemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @GetMapping("/profile")
    public String profile(Authentication authentication) {
        return "Hello " + authentication.getName() + ", this is protected USER data.";
    }
}
