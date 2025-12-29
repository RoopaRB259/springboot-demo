package com.example.demo.security;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.Repository.StudentRepository;
import com.example.demo.model.Student;

@Service
public class StudentDetailsService implements UserDetailsService {
  @Autowired
  private StudentRepository studentRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    Student student = studentRepository.findByEmail(email)
      .orElseThrow(() -> new UsernameNotFoundException("Student not found"));
    return new org.springframework.security.core.userdetails.User(
      student.getEmail(),
      student.getPassword(),
      Collections.singletonList(new SimpleGrantedAuthority("ROLE_STUDENT"))

    );
  }
}

