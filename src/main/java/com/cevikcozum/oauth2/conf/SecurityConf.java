package com.cevikcozum.oauth2.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityConf extends WebSecurityConfigurerAdapter {

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "/connect**", "/webjars/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .logout()
                .logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    private javax.servlet.Filter ssoFilter() {

        CompositeFilter filter = new CompositeFilter();
        List<javax.servlet.Filter> filters = new ArrayList<>();

        OAuth2ClientAuthenticationProcessingFilter facebookFilter = facebookFilter();
        OAuth2ClientAuthenticationProcessingFilter googleFilter = filter("/connect/google", google(), googleResource());
        OAuth2ClientAuthenticationProcessingFilter linkedInFilter = filter("/connect/linkedIn", linkedIn(), linkedInResource());
        OAuth2ClientAuthenticationProcessingFilter twitterFilter = filter("/connect/twitter", twitter(), twitterResource());

        filters.add(facebookFilter);
        filters.add(googleFilter);
        filters.add(linkedInFilter);
        filters.add(twitterFilter);

        filter.setFilters(filters);

        return filter;
    }

    private OAuth2ClientAuthenticationProcessingFilter filter(String s, AuthorizationCodeResourceDetails google, ResourceServerProperties resourceServerProperties) {
        UserInfoTokenServices tokenServices;
        OAuth2ClientAuthenticationProcessingFilter googleFilter = new OAuth2ClientAuthenticationProcessingFilter(
                s);
        OAuth2RestTemplate googleTemplate = new OAuth2RestTemplate(google, oauth2ClientContext);
        googleFilter.setRestTemplate(googleTemplate);
        tokenServices = new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(), google.getClientId());
        tokenServices.setRestTemplate(googleTemplate);
        googleFilter.setTokenServices(tokenServices);
        return googleFilter;
    }

    private OAuth2ClientAuthenticationProcessingFilter facebookFilter() {
        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter(
                "/connect/facebook");
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
        facebookFilter.setRestTemplate(facebookTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(),
                facebook().getClientId());
        tokenServices.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(tokenServices);
        return facebookFilter;
    }


    @Bean
    @ConfigurationProperties("facebook.client")
    public AuthorizationCodeResourceDetails facebook() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("facebook.resource")
    public ResourceServerProperties facebookResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("google.client")
    public AuthorizationCodeResourceDetails google() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("google.resource")
    public ResourceServerProperties googleResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("linkedin.client")
    public AuthorizationCodeResourceDetails linkedIn() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("linkedin.resource")
    public ResourceServerProperties linkedInResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("twitter.client")
    public AuthorizationCodeResourceDetails twitter() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("twitter.resource")
    public ResourceServerProperties twitterResource() {
        return new ResourceServerProperties();
    }

}
