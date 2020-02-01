package boc.oprd.demo.controlller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @RequestMapping("/")
    public String Index() {
        return "来了";
    }

    @RequestMapping("/test")
    @Secured("ROLE_TEST")
    public String test() {
        return "test rest info";
    }
}