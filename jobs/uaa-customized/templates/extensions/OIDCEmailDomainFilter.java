package org.cloudfoundry.identity.uaa.extensions;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OIDCEmailDomainFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(OIDCEmailDomainFilter.class);
    
    public OIDCEmailDomainFilter() {
        logger.error("OIDCEmailDomainFilter CONSTRUCTOR CALLED - Filter instantiated");
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        logger.error("OIDCEmailDomainFilter called for URI: {}", request.getRequestURI());
        
        // Log every request to see if filter is active
        if (request.getRequestURI().contains("login") || 
            request.getRequestURI().contains("oauth") || 
            request.getRequestURI().contains("callback")) {
            logger.error("OIDCEmailDomainFilter - Processing auth-related request: {}", request.getRequestURI());
        }
        
        // Only check after successful authentication
        if (request.getRequestURI().contains("/oauth/authorize/callback") || 
            request.getRequestURI().contains("/login/callback")) {
            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (auth instanceof UaaAuthentication) {
                UaaAuthentication uaaAuth = (UaaAuthentication) auth;
                
                // Check if this is a Login.gov user by origin
                if (uaaAuth.getPrincipal() != null && 
                    "login.gov".equalsIgnoreCase(uaaAuth.getPrincipal().getOrigin())) {
                    
                    String email = uaaAuth.getPrincipal().getEmail();
                    
                    if (email != null && !isValidEmailDomain(email)) {
                        logger.warn("Blocking Login.gov authentication for non-gov/mil email: {}", email);
                        
                        // Clear the authentication
                        SecurityContextHolder.clearContext();
                        if (request.getSession(false) != null) {
                            request.getSession().invalidate();
                        }
                        
                        // Redirect with error
                        response.sendRedirect("/login?error=invalid_email_domain");
                        return;
                    }
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isValidEmailDomain(String email) {
        return email.matches(".*\\.(gov|mil)$");
    }
}