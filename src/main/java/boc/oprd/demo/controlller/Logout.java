package boc.oprd.demo.controlller;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Logout {
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) throws ServletException{
        request.logout();
        return "logout success!";
    }
}