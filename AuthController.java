package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.demo.Repository.StudentRepository;
import com.example.demo.model.Student;
import com.example.demo.payload.AuthRequest;
import com.example.demo.payload.AuthResponse;

import com.example.demo.security.JwtTokenProvider;

@RestController
@CrossOrigin(origins = "*")

@RequestMapping("/auth")
public class AuthController {

  @Autowired
  private AuthenticationManager authManager;

  @Autowired
  private JwtTokenProvider jwtProvider;

  @Autowired
  private StudentRepository studentRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody AuthRequest request) {
    try {
      Authentication auth = authManager.authenticate(
          new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
      String token = jwtProvider.generateToken(auth.getName());
      return ResponseEntity.ok(new AuthResponse(token));
    } catch (Exception e) {
      e.printStackTrace(); // ✅ Log the actual error
      return ResponseEntity.status(401).body("Login failed: " + e.getMessage());
    }
  }

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestBody Student student) {
    // Encode the password before saving
    student.setPassword(passwordEncoder.encode(student.getPassword()));
    studentRepository.save(student);
    return ResponseEntity.ok("Student registered successfully");
  }
}