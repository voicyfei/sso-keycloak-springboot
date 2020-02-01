package boc.oprd.demo.controlller;

import java.security.Principal;
import java.util.HashMap;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.representations.AccessToken;
import org.springframework.security.access.annotation.Secured;
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
    @Secured("ROLE_ADMIN")
    public String hello(HashMap<String, Object> map,Principal principal) {
        map.put("hello", "你追我，如果你要追到我，我就");

        if (principal instanceof KeycloakPrincipal) {
            AccessToken accessToken = ((KeycloakPrincipal) principal).getKeycloakSecurityContext().getToken();
            String preferredUsername = accessToken.getPreferredUsername();
            AccessToken.Access realmAccess = accessToken.getRealmAccess();
            Set<String> roles = realmAccess.getRoles();
            log.infof("username : {}, role: {}", preferredUsername, roles);
            map.put("userinfo",preferredUsername+","+roles);
        }

        return "/hello";
    }


}