package com.bezkoder.spring.security.postgresql.controllers;

import java.util.HashSet;
import java.io.*;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.servlet.http.HttpServletRequest;
import javax.mail.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.data.repository.query.Param;
import com.bezkoder.spring.security.postgresql.models.ERole;
import com.bezkoder.spring.security.postgresql.models.Role;
import com.bezkoder.spring.security.postgresql.models.User;
import com.bezkoder.spring.security.postgresql.payload.request.LoginRequest;
import com.bezkoder.spring.security.postgresql.payload.request.SignupRequest;
import com.bezkoder.spring.security.postgresql.payload.response.JwtResponse;
import com.bezkoder.spring.security.postgresql.payload.response.MessageResponse;
import com.bezkoder.spring.security.postgresql.repository.RoleRepository;
import com.bezkoder.spring.security.postgresql.repository.UserRepository;
import com.bezkoder.spring.security.postgresql.security.jwt.JwtUtils;
import com.bezkoder.spring.security.postgresql.security.services.UserDetailsImpl;
import com.bezkoder.spring.security.postgresql.security.services.UserDetailsServiceImpl;



import java.io.Console;  


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@Autowired
     UserDetailsServiceImpl service;

	
	
	
	@PostMapping("/signup")
		public  ResponseEntity<?> processRegister(@Valid @RequestBody SignupRequest signUpRequest, HttpServletRequest request)
				throws UnsupportedEncodingException, MessagingException {


			if (userRepository.existsByUsername(signUpRequest.getUsername())) {
				return ResponseEntity
						.badRequest()
						.body(new MessageResponse("Error: Username is already taken!"));
			}

			if (userRepository.existsByEmail(signUpRequest.getEmail())) {
				return ResponseEntity
						.badRequest()
						.body(new MessageResponse("Error: Email is already in use!"));
			}


			User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));
			
			Set<String> strRoles = signUpRequest.getRole();
			Set<Role> roles = new HashSet<>();

			if (strRoles == null) {
				Role userRole = roleRepository.findByName(ERole.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
				roles.add(userRole);
			} else {
				strRoles.forEach(role -> {
					switch (role) {
					case "admin":
						Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(adminRole);

						break;
					case "mod":
						Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(modRole);

						break;
					default:
						Role userRole = roleRepository.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(userRole);
					}
				});
			}

			user.setRoles(roles);
			userRepository.save(user);

			service.register(user, getSiteURL(request));


			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(), signUpRequest.getPassword()));

			SecurityContextHolder.getContext().setAuthentication(authentication);
			String jwt = jwtUtils.generateJwtToken(authentication);
			
			UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
			List<String> rolees = userDetails.getAuthorities().stream()
					.map(item -> item.getAuthority())
					.collect(Collectors.toList());
			// String message = new String("User registered successfully! Please check your mailbox");

			return ResponseEntity.ok(new JwtResponse(jwt, 
													userDetails.getId(), 
													userDetails.getUsername(), 
													userDetails.getEmail(), 
													rolees));


			// return ResponseEntity.ok(new MessageResponse("User registered successfully! Please check your mailbox"));
		}
		
	private String getSiteURL(HttpServletRequest request) {
		String siteURL = request.getRequestURL().toString();
		return siteURL.replace(request.getServletPath(), "");
	}  

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse(jwt, 
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail(), 
												 roles));
	}

	@GetMapping("/verify")
	public String verifyUser(@Valid @Param("code") String code) {

		Console c=System.console();    
		System.out.println("Enter password: "+ code);     
		if (service.verify(code)) {
			return "verify_success";
		} else {
			return "your email verify failed.";
		}
	}

	// @PostMapping("/signup")
	// public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
	// 	if (userRepository.existsByUsername(signUpRequest.getUsername())) {
	// 		return ResponseEntity
	// 				.badRequest()
	// 				.body(new MessageResponse("Error: Username is already taken!"));
	// 	}

	// 	if (userRepository.existsByEmail(signUpRequest.getEmail())) {
	// 		return ResponseEntity
	// 				.badRequest()
	// 				.body(new MessageResponse("Error: Email is already in use!"));
	// 	}

	// 	// Create new user's account
	// 	User user = new User(signUpRequest.getUsername(), 
	// 						 signUpRequest.getEmail(),
	// 						 encoder.encode(signUpRequest.getPassword()));

	// 	Set<String> strRoles = signUpRequest.getRole();
	// 	Set<Role> roles = new HashSet<>();

	// 	if (strRoles == null) {
	// 		Role userRole = roleRepository.findByName(ERole.ROLE_USER)
	// 				.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	// 		roles.add(userRole);
	// 	} else {
	// 		strRoles.forEach(role -> {
	// 			switch (role) {
	// 			case "admin":
	// 				Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
	// 						.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	// 				roles.add(adminRole);

	// 				break;
	// 			case "mod":
	// 				Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
	// 						.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	// 				roles.add(modRole);

	// 				break;
	// 			default:
	// 				Role userRole = roleRepository.findByName(ERole.ROLE_USER)
	// 						.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
	// 				roles.add(userRole);
	// 			}
	// 		});
	// 	}

	// 	user.setRoles(roles);
	// 	userRepository.save(user);

	// 	return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	// }
}
