package boc.oprd.demo.controlller;

import java.security.Principal;
import java.util.HashMap;
import java.util.Set;

import org.jboss.logging.Logger;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {
    private Logger log = Logger.getLogger(TestController.class);

    /**
     * 
     * @param map
     * @return
     */
    @RequestMapping("/hello")
    @PreAuthorize("hasRole('ADMIN')") 
    public String hello(HashMap<String, Object> map,Principal principal) {
        map.put("hello", "你追我，如果你要追到我，我就");


        return "/hello";
    }


}