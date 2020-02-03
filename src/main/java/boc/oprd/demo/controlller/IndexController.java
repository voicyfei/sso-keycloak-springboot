package boc.oprd.demo.controlller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @RequestMapping("/")
    public String Index() {
        return "来了";
    }

    @PreAuthorize("hasRole('USER')") 
    @RequestMapping("/test")
    public String test() {
        return "test rest info";
    }
}