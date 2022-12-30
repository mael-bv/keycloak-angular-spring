package org.sid.ebankservice.security;

import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
@KeycloakConfiguration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	
	
	//partie de mael afin de voir si tout fonctionne !
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		super.configure(http);
		http.csrf().disable().authorizeRequests().antMatchers("/h2-console/**").permitAll();
		http.headers().frameOptions().disable();
		http.authorizeRequests().anyRequest().authenticated();	//http.authorizeHttpRequests().antMatchers("/h2-console/**").permitAll();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth){
		// TODO Auto-generated method stub
		auth.authenticationProvider(keycloakAuthenticationProvider());
	}
	
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		// TODO Auto-generated method stub
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}
	
}
