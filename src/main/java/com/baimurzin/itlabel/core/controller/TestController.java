package com.baimurzin.itlabel.core.controller;

import com.baimurzin.itlabel.core.domain.UserAccount;
import com.baimurzin.itlabel.core.repository.UserAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @Autowired
    private UserAccountRepository userAccountRepository;

    @RequestMapping("/test")
    @Secured({ "ROLE_USER" })
    public UserAccount getUser(Principal principal) {
        return userAccountRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + principal.getName()));
    }

    @RequestMapping("/html")
    public String getHtml() {
        return "index";
    }
}
