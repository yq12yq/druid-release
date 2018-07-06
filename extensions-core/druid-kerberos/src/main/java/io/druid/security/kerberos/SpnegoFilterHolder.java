/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.druid.security.kerberos;

import com.google.common.base.Throwables;
import com.google.inject.Inject;
import io.druid.guice.annotations.Self;
import io.druid.java.util.common.StringUtils;
import io.druid.java.util.common.logger.Logger;
import io.druid.server.AsyncQueryForwardingServlet;
import io.druid.server.DruidNode;
import io.druid.server.initialization.jetty.ServletFilterHolder;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.authentication.util.Signer;
import org.apache.hadoop.security.authentication.util.SignerException;
import org.apache.hadoop.security.authentication.util.SignerSecretProvider;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.TimeZone;


public class SpnegoFilterHolder implements ServletFilterHolder
{
  private static final Logger LOG = new Logger(KerberosAuthenticator.class);

  private final SpnegoFilterConfig config;
  private final DruidNode node;

  @Inject
  public SpnegoFilterHolder(SpnegoFilterConfig config, @Self DruidNode node)
  {
    this.config = config;
    this.node = node;
  }

  @Override
  public Filter getFilter()
  {
    return new AuthenticationFilter()
    {
      private Signer mySigner;

      @Override
      public void init(FilterConfig filterConfig) throws ServletException
      {
        ClassLoader prevLoader = Thread.currentThread().getContextClassLoader();
        try {
          // AuthenticationHandler is created during Authenticationfilter.init using reflection with thread context class loader.
          // In case of druid since the class is actually loaded as an extension and filter init is done in main thread.
          // We need to set the classloader explicitly to extension class loader.
          Thread.currentThread().setContextClassLoader(AuthenticationFilter.class.getClassLoader());
          super.init(filterConfig);
          String configPrefix = filterConfig.getInitParameter(CONFIG_PREFIX);
          configPrefix = (configPrefix != null) ? configPrefix + "." : "";
          Properties config = getConfiguration(configPrefix, filterConfig);
          String signatureSecret = config.getProperty(configPrefix + SIGNATURE_SECRET);
          if (signatureSecret == null) {
            signatureSecret = Long.toString(new Random().nextLong());
            LOG.warn("'signature.secret' configuration not set, using a random value as secret");
          }
          final byte[] secretBytes = StringUtils.toUtf8(signatureSecret);
          SignerSecretProvider signerSecretProvider = new SignerSecretProvider()
          {
            @Override
            public void init(Properties config, ServletContext servletContext, long tokenValidity) throws Exception
            {

            }

            @Override
            public byte[] getCurrentSecret()
            {
              return secretBytes;
            }

            @Override
            public byte[][] getAllSecrets()
            {
              return new byte[][]{secretBytes};
            }
          };
          mySigner = new Signer(signerSecretProvider);
        }
        finally {
          Thread.currentThread().setContextClassLoader(prevLoader);
        }
      }

      @Override
      public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
          throws IOException, ServletException {
        String path = ((HttpServletRequest) request).getRequestURI();
        if (isExcluded(path)) {
          filterChain.doFilter(request, response);
          return;
        }
        boolean unauthorizedResponse = true;
        int errCode = HttpServletResponse.SC_UNAUTHORIZED;
        AuthenticationException authenticationEx = null;
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        boolean isHttps = "https".equals(httpRequest.getScheme());
        try {
          boolean newToken = false;
          AuthenticationToken token;
          try {
            token = getToken(httpRequest);
          }
          catch (AuthenticationException ex) {
            LOG.warn("AuthenticationToken ignored: " + ex.getMessage());
            // will be sent back in a 401 unless filter authenticates
            authenticationEx = ex;
            token = null;
          }
          if (getAuthenticationHandler().managementOperation(token, httpRequest, httpResponse)) {
            if (token == null) {
              if (LOG.isDebugEnabled()) {
                LOG.debug("Request [{}] triggering authentication", getRequestURL(httpRequest));
              }
              token = getAuthenticationHandler().authenticate(httpRequest, httpResponse);
              if (token != null && token.getExpires() != 0 &&
                  token != AuthenticationToken.ANONYMOUS) {
                token.setExpires(System.currentTimeMillis() + getValidity() * 1000);
              }
              newToken = true;
            }
            if (token != null) {
              unauthorizedResponse = false;
              if (LOG.isDebugEnabled()) {
                LOG.debug("Request [{}] user [{}] authenticated", getRequestURL(httpRequest), token.getUserName());
              }
              final AuthenticationToken authToken = token;
              httpRequest = new HttpServletRequestWrapper(httpRequest) {

                @Override
                public String getAuthType() {
                  return authToken.getType();
                }

                @Override
                public String getRemoteUser() {
                  return authToken.getUserName();
                }

                @Override
                public Principal getUserPrincipal() {
                  return (authToken != AuthenticationToken.ANONYMOUS) ? authToken : null;
                }
              };
              if (newToken && !token.isExpired() && token != AuthenticationToken.ANONYMOUS) {
                String signedToken = mySigner.sign(token.toString());
                createAuthCookie(httpResponse, signedToken, getCookieDomain(),
                                 getCookiePath(), token.getExpires(),
                                 isCookiePersistent(), isHttps);
                request.setAttribute(AsyncQueryForwardingServlet.SIGNED_TOKEN_ATTRIBUTE, tokenToCookieString(
                    signedToken,
                    getCookieDomain(),
                    getCookiePath(),
                    token.getExpires(),
                    !token.isExpired() && token.getExpires() > 0,
                    isHttps
                ));
              }
              doFilter(filterChain, httpRequest, httpResponse);
            }
          } else {
            unauthorizedResponse = false;
          }
        } catch (AuthenticationException ex) {
          // exception from the filter itself is fatal
          errCode = HttpServletResponse.SC_FORBIDDEN;
          authenticationEx = ex;
          if (LOG.isDebugEnabled()) {
            LOG.debug("Authentication exception: " + ex.getMessage(), ex);
          } else {
            LOG.warn("Authentication exception: " + ex.getMessage());
          }
        }
        if (unauthorizedResponse) {
          if (!httpResponse.isCommitted()) {
            createAuthCookie(httpResponse, "", getCookieDomain(),
                             getCookiePath(), 0, isCookiePersistent(), isHttps);
            // If response code is 401. Then WWW-Authenticate Header should be
            // present.. reset to 403 if not found..
            if ((errCode == HttpServletResponse.SC_UNAUTHORIZED)
                && (!httpResponse.containsHeader(
                KerberosAuthenticator.WWW_AUTHENTICATE))) {
              errCode = HttpServletResponse.SC_FORBIDDEN;
            }
            if (authenticationEx == null) {
              httpResponse.sendError(errCode, "Authentication required");
            } else {
              httpResponse.sendError(errCode, authenticationEx.getMessage());
            }
          }
        }
      }

      @Override
      protected AuthenticationToken getToken(HttpServletRequest request) throws IOException, AuthenticationException
      {
        AuthenticationToken token = null;
        String tokenStr = null;


        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
          for (Cookie cookie : cookies) {
            if (cookie.getName().equals(AuthenticatedURL.AUTH_COOKIE)) {
              tokenStr = cookie.getValue();
              try {
                tokenStr = mySigner.verifyAndExtract(tokenStr);
              }
              catch (SignerException ex) {
                throw new AuthenticationException(ex);
              }
              break;
            }
          }
        }
        if (tokenStr != null) {
          token = AuthenticationToken.parse(tokenStr);
          if (!token.getType().equals(getAuthenticationHandler().getType())) {
            throw new AuthenticationException("Invalid AuthenticationToken type");
          }
          if (token.isExpired()) {
            throw new AuthenticationException("AuthenticationToken expired");
          }
        }
        return token;
      }
    };
  }

  private boolean isExcluded(String path)
  {
    for (String excluded : config.getExcludedPaths()) {
      if (path.startsWith(excluded)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return null;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    Map<String, String> params = new HashMap<>();
    try {
      params.put(
        "kerberos.principal",
        SecurityUtil.getServerPrincipal(config.getPrincipal(), node.getHost())
      );
      params.put("kerberos.keytab", config.getKeytab());
      params.put(AuthenticationFilter.AUTH_TYPE, "kerberos");
      params.put("kerberos.name.rules", config.getAuthToLocal());
      if (config.getCookieSignatureSecret() != null) {
        params.put("signature.secret", config.getCookieSignatureSecret());
      }
    }
    catch (IOException e) {
      Throwables.propagate(e);
    }
    return params;
  }

  @Override
  public String getPath()
  {
    return "/*";
  }

  @Override
  public EnumSet<DispatcherType> getDispatcherType()
  {
    return null;
  }


  /**
   * Creates the Hadoop authentication HTTP cookie.
   *
   * @param resp the response object.
   * @param token authentication token for the cookie.
   * @param domain the cookie domain.
   * @param path the cookie path.
   * @param expires UNIX timestamp that indicates the expire date of the
   *                cookie. It has no effect if its value &lt; 0.
   * @param isSecure is the cookie secure?
   * @param isCookiePersistent whether the cookie is persistent or not.
   *the following code copy/past from Hadoop 3.0.0 copied to avoid compilation issue due to new signature,
   *                           org.apache.hadoop.security.authentication.server.AuthenticationFilter#createAuthCookie
   *                           (
   *                           javax.servlet.http.HttpServletResponse,
   *                           java.lang.String,
   *                           java.lang.String,
   *                           java.lang.String,
   *                           long, boolean, boolean)
   */
  private static void tokenToAuthCookie(
      HttpServletResponse resp, String token,
      String domain, String path, long expires,
      boolean isCookiePersistent,
      boolean isSecure
  )
  {
    resp.addHeader("Set-Cookie", tokenToCookieString(token, domain, path, expires, isCookiePersistent, isSecure));
  }

  private static String tokenToCookieString(
      String token,
      String domain, String path, long expires,
      boolean isCookiePersistent,
      boolean isSecure
  )
  {
    StringBuilder sb = new StringBuilder(AuthenticatedURL.AUTH_COOKIE)
        .append("=");
    if (token != null && token.length() > 0) {
      sb.append("\"").append(token).append("\"");
    }

    if (path != null) {
      sb.append("; Path=").append(path);
    }

    if (domain != null) {
      sb.append("; Domain=").append(domain);
    }

    if (expires >= 0 && isCookiePersistent) {
      Date date = new Date(expires);
      SimpleDateFormat df = new SimpleDateFormat("EEE, dd-MMM-yyyy HH:mm:ss zzz", Locale.ENGLISH);
      df.setTimeZone(TimeZone.getTimeZone("GMT"));
      sb.append("; Expires=").append(df.format(date));
    }

    if (isSecure) {
      sb.append("; Secure");
    }

    sb.append("; HttpOnly");
    return sb.toString();
  }
}
