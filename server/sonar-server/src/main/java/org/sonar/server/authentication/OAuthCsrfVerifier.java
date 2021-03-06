/*
 * SonarQube
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.server.authentication;

import static org.apache.commons.codec.digest.DigestUtils.sha256Hex;
import static org.apache.commons.lang.StringUtils.isBlank;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Optional;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.sonar.api.platform.Server;
import org.sonar.server.exceptions.UnauthorizedException;

public class OAuthCsrfVerifier {

  private static final String CSRF_STATE_COOKIE = "OAUTHSTATE";

  private final Server server;

  public OAuthCsrfVerifier(Server server) {
    this.server = server;
  }

  public String generateState(HttpServletResponse response) {
    // Create a state token to prevent request forgery.
    // Store it in the session for later validation.
    String state = new BigInteger(130, new SecureRandom()).toString(32);
    Cookie cookie = new Cookie(CSRF_STATE_COOKIE, sha256Hex(state));
    cookie.setPath(server.getContextPath() + "/");
    cookie.setHttpOnly(true);
    cookie.setMaxAge(-1);
    cookie.setSecure(server.isSecured());
    response.addCookie(cookie);
    return state;
  }

  public void verifyState(HttpServletRequest request, HttpServletResponse response) {
    Optional<Cookie> stateCookie = CookieUtils.findCookie(CSRF_STATE_COOKIE, request);
    if (!stateCookie.isPresent()) {
      throw new UnauthorizedException();
    }
    Cookie cookie = stateCookie.get();

    String hashInCookie = cookie.getValue();

    // remove cookie
    cookie.setValue(null);
    cookie.setMaxAge(0);
    cookie.setPath(server.getContextPath() + "/");
    response.addCookie(cookie);

    String stateInRequest = request.getParameter("state");
    if (isBlank(stateInRequest) || !sha256Hex(stateInRequest).equals(hashInCookie)) {
      throw new UnauthorizedException();
    }
  }

}
