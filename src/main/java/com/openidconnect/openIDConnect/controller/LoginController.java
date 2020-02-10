package com.openidconnect.openIDConnect.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.security.Principal;
import java.util.Map;

@RestController("/user")
public class LoginController {
    private final OAuth2AuthorizedClientService authorizedClientService;

    public LoginController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }
    @RolesAllowed("USER")
    @RequestMapping("/**")
   public String getUser(){
       return "Welcome , user";
   }
   @RolesAllowed("ADMIN")
   @RequestMapping("/admin")
   public String getAdmin(){
        return "Welcome , admin";
   }
    @RequestMapping("/*")
    public String getUserInfo(Principal user){
        StringBuffer userInfo= new StringBuffer();

        if(user instanceof UsernamePasswordAuthenticationToken){
            userInfo.append(getUsernamePasswordLoginInfo(user));
        }
        else if(user instanceof OAuth2AuthenticationToken){
            userInfo.append(getOauth2LoginInfo(user));
        }
        return userInfo.toString();
    }
    private StringBuffer getUsernamePasswordLoginInfo(Principal user)
    {
        StringBuffer usernameInfo = new StringBuffer();

        UsernamePasswordAuthenticationToken token = ((UsernamePasswordAuthenticationToken) user);
        if(token.isAuthenticated()){
            User u = (User) token.getPrincipal();
            usernameInfo.append("Welcome, " + u.getUsername());
        }
        else{
            usernameInfo.append("NA");
        }
        return usernameInfo;
    }
    private StringBuffer getOauth2LoginInfo(Principal user){

        StringBuffer protectedInfo = new StringBuffer();

        OAuth2User principal = ((OAuth2AuthenticationToken) user).getPrincipal();

            OidcIdToken idToken = getIdToken(principal);


            if(idToken != null) {

                protectedInfo.append("idToken value: " + idToken.getTokenValue()+"<br><br>");
                protectedInfo.append("Token mapped values <br><br>");

                Map<String, Object> claims = idToken.getClaims();

                for (String key : claims.keySet()) {
                    protectedInfo.append("  " + key + ": " + claims.get(key)+"<br>");
                }
            }

        else{
            protectedInfo.append("NA");
        }
        return protectedInfo;

    }

    private OidcIdToken getIdToken(OAuth2User principal){

        if(principal instanceof DefaultOidcUser) {
            DefaultOidcUser oidcUser = (DefaultOidcUser)principal;
            return oidcUser.getIdToken();
        }
        return null;
    }

}
