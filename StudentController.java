package com.example.demo.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.demo.Repository.StudentRepository;
import com.example.demo.model.Student;

@RestController
@CrossOrigin("*")
@RequestMapping("/students")
public class StudentController {

  @Autowired
  private StudentRepository studentRepository;

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  // 🔐 Get all students (protected)
  @GetMapping("/")
  @PreAuthorize("hasRole('STUDENT')")
  public List<Student> getAll() {
    return studentRepository.findAll();
  }

  // 🔐 Get student by ID (protected)
  @GetMapping("/{id}")
  @PreAuthorize("hasRole('STUDENT')")
  public Student getById(@PathVariable Long id) {
    return studentRepository.findById(id).orElse(null);
  }

  // 🔐 Update student (protected)
  @PutMapping("/{id}")
  @PreAuthorize("hasRole('STUDENT')")
  public Student update(@PathVariable Long id, @RequestBody Student student) {
    Optional<Student> existing = studentRepository.findById(id);
    if (existing.isPresent()) {
      Student s = existing.get();
      s.setName(student.getName());
      s.setEmail(student.getEmail());
      if (!student.getPassword().equals(s.getPassword())) {
        s.setPassword(passwordEncoder.encode(student.getPassword()));
      }
      return studentRepository.save(s);
    }
    return null;
  }

  // 🔐 Delete student (protected)
  @DeleteMapping("/{id}")
  @PreAuthorize("hasRole('STUDENT')")
  public void delete(@PathVariable Long id) {
    studentRepository.deleteById(id);
  }
}