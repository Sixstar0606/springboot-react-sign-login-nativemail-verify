package com.bezkoder.spring.security.postgresql.security.services;
// package net.bytebuddy.utility.RandomString;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bezkoder.spring.security.postgresql.models.User;
import com.bezkoder.spring.security.postgresql.repository.UserRepository;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import javax.mail.MessagingException;
import net.bytebuddy.utility.RandomString;
import java.io.*;
import javax.mail.*;
import javax.mail.internet.*;
import org.springframework.mail.javamail.MimeMessageHelper;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  @Autowired
    private JavaMailSender mailSender;
 
  // @Autowired
  //   private PasswordEncoder passwordEncoder;
   
     
    private void sendVerificationEmail(User user, String siteURL)
            throws MessagingException, UnsupportedEncodingException {
        String toAddress = user.getEmail();
        String fromAddress = "prodev0128@gmail.com";
        String senderName = "Your company name";
        String subject = "Please verify your registration";
        String content = "Dear [[name]],<br>"
                + "Please click the link below to verify your registration:<br>"
                + "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>"
                + "Thank you,<br>"
                + "Your company name.";
        
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        
        helper.setFrom(fromAddress, senderName);
        helper.setTo(toAddress);
        helper.setSubject(subject);
        
        content = content.replace("[[name]]", user.getUsername());
        String verifyURL = "http://localhost:8080" + "/verify/" + user.getVerificationCode();
        
        content = content.replace("[[URL]]", verifyURL);
        
        helper.setText(content, true);
        
        mailSender.send(message);
        
    }

    public void register(User user, String siteURL)
            throws UnsupportedEncodingException, MessagingException {
        // String encodedPassword = passwordEncoder.encode(user.getPassword());
        String encodedPassword = user.getPassword();
        user.setPassword(encodedPassword);
        
        String randomCode = RandomString.make(64);
        user.setVerificationCode(randomCode);
        // user.setEnabled(false);
        
        userRepository.save(user);
        
        sendVerificationEmail(user, siteURL);
    }

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }

  public boolean verify(String verificationCode) {
    User user = userRepository.findByVerificationCode(verificationCode);
    
    if (user == null || user.isEnabled()) {
        return false;
    } else {
        user.setVerificationCode(null);
        user.setEnabled(true);
        userRepository.save(user);
         
        return true;
    }
     
}

}
