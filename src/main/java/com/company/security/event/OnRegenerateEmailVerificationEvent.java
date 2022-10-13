package com.company.security.event;

import com.company.security.model.User;
import com.company.security.model.token.EmailVerificationToken;
import org.springframework.context.ApplicationEvent;
import org.springframework.web.util.UriComponentsBuilder;

public class OnRegenerateEmailVerificationEvent extends ApplicationEvent {

    private transient UriComponentsBuilder redirectUrl;
    private User user;
    private transient EmailVerificationToken token;

    public OnRegenerateEmailVerificationEvent(User user, UriComponentsBuilder redirectUrl, EmailVerificationToken token) {
        super(user);
        this.user = user;
        this.redirectUrl = redirectUrl;
        this.token = token;
    }

    public UriComponentsBuilder getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(UriComponentsBuilder redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public EmailVerificationToken getToken() {
        return token;
    }

    public void setToken(EmailVerificationToken token) {
        this.token = token;
    }
}
