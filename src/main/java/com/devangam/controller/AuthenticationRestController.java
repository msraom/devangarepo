package com.devangam.controller;
import static com.devangam.constants.DevangamConstants.FAIL;
import static com.devangam.constants.DevangamConstants.SUCCESS;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.devangam.security.JwtAuthenticationRequest;
import com.devangam.security.JwtTokenUtil;
import com.devangam.security.JwtUser;
import com.devangam.security.service.JwtAuthenticationResponse;


@RestController
public class AuthenticationRestController {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService userDetailsService;

	@RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
	public @ResponseBody JwtAuthenticationResponse createAuthenticationToken(
			@RequestBody JwtAuthenticationRequest authenticationRequest, Device device) {
		JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
		try {
			// Perform the security
			final Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
							authenticationRequest.getPassword()));
			SecurityContextHolder.getContext().setAuthentication(authentication);
			// Reload password post-security so we can generate token
			final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
			jwtAuthenticationResponse.setToken(jwtTokenUtil.generateToken(userDetails, device));
			jwtAuthenticationResponse.setStatus(SUCCESS);
			jwtAuthenticationResponse.setMessage("Authentication Token Created Successfully");
		} catch (AuthenticationException authenticationException) {
			jwtAuthenticationResponse.setStatus(FAIL);
			jwtAuthenticationResponse.setMessage("Username doesn't exist.EmailID=" + authenticationRequest.getUsername());
		} catch (Exception exception) {
			jwtAuthenticationResponse.setStatus(FAIL);
			jwtAuthenticationResponse.setMessage("Create Authentication Token failed.EmailID=" + authenticationRequest.getUsername());
		}
		return jwtAuthenticationResponse;
	}

    @RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.GET)
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
        String token = request.getHeader(tokenHeader);
        String username = jwtTokenUtil.getUsernameFromToken(token);
        JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);

       // if (jwtTokenUtil.canTokenBeRefreshed(token) {
          //  String refreshedToken = jwtTokenUtil.refreshToken(token);
          //  return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken));
        //} else {
       //     return ResponseEntity.badRequest().body(null);
       // }
    }

}
