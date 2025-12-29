package com.example.demo.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;



import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

  @Value("${jwt.secret}")
  private String secret;

  private Key key;
  private final long jwtExpiration = 86400000;

  @jakarta.annotation.PostConstruct
  public void init() {
      System.out.println("JWT secret length: " + secret.length()); // should be ≥ 64
      key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }


  public String generateToken(String email) {
    return Jwts.builder()
      .setSubject(email)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
      .signWith(key, SignatureAlgorithm.HS512)
      .compact();
  }

  public String getEmailFromToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
      return true;
    } catch (Exception e) {
      return false;
    }
  }
}