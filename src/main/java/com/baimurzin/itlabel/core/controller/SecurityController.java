package com.baimurzin.itlabel.core.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;

@RestController
public class SecurityController {



    @RequestMapping({ "/user", "/me" })
    @ResponseBody
    public Principal user(Principal principal) {
        return principal;
    }

    @RequestMapping("/unauthenticated")
    public ResponseEntity unauthenticated(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new HashMap<String, Object>(){{
            put("message", "login please");
        }});
    }

}
