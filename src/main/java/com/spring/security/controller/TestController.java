package com.spring.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

	@GetMapping(value = "/all")
	public String allAccess() {
		return "Public Content";
	}

	@GetMapping(value = "/user")
	@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	public String userAccess() {
		return "User Content";
	}

	@GetMapping(value = "/mod")
	@PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
	public String moderatorAccess() {
		return "Moderator Content";
	}

	@GetMapping(value = "/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return "Admin Content";
	}
}
