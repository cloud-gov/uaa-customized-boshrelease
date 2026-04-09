package org.cloudfoundry.identity.uaa.extensions;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

// Use jakarta instead of javax
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OIDCEmailDomainFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(OIDCEmailDomainFilter.class);
    
    @Autowired
    private IdentityProviderProvisioning identityProviderProvisioning;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        // Only check after successful authentication
        if (request.getRequestURI().contains("/oauth/authorize/callback")) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            if (auth instanceof UaaAuthentication) {
                UaaAuthentication uaaAuth = (UaaAuthentication) auth;
                String origin = uaaAuth.getAuthContextClassRef() != null ? 
                    uaaAuth.getAuthContextClassRef().iterator().next() : null;
                
                // Check if this is Login.gov
                if (origin != null && isLoginGovProvider(origin)) {
                    String email = uaaAuth.getPrincipal().getEmail();
                    
                    if (email != null && !isValidEmailDomain(email)) {
                        logger.warn("Blocking Login.gov authentication for non-gov/mil email: {}", email);
                        
                        // Clear the authentication
                        SecurityContextHolder.clearContext();
                        request.getSession().invalidate();
                        
                        // Redirect with error
                        response.sendRedirect("/login?error=invalid_email_domain");
                        return;
                    }
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isLoginGovProvider(String origin) {
        try {
            IdentityProvider provider = identityProviderProvisioning.retrieveByOrigin(
                origin, IdentityZoneHolder.get().getId());
            return provider != null && 
                   "oidc1.0".equals(provider.getType()) &&
                   provider.getConfig().getRelyingPartyId() != null &&
                   provider.getConfig().getRelyingPartyId().contains("login-gov");
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isValidEmailDomain(String email) {
        return email.matches(".*\\.(gov|mil)$");
    }
}