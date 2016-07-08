/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.iwa.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSException;
import org.wso2.carbon.identity.application.authenticator.iwa.IWAAuthenticationUtil;
import org.wso2.carbon.identity.application.authenticator.iwa.IWAConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.PrivilegedActionException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * This class handles the IWA login requests. The implementation is based on the Spnego Authentication.
 */
public class IWAServlet extends HttpServlet {

    private static Log log = LogFactory.getLog(IWAServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String commonAuthURL = IdentityUtil.getServerURL(IWAConstants.COMMON_AUTH_EP, false, true);
        String param = request.getParameter(IWAConstants.IWA_PARAM_STATE);
        if (param == null) {
            throw new IllegalArgumentException(IWAConstants.IWA_PARAM_STATE + " parameter is null.");
        }
        commonAuthURL += "?" + IWAConstants.IWA_PARAM_STATE + "=" + URLEncoder.encode(param, IWAConstants.UTF_8) +
                "&" + IWAConstants.IWA_PROCESSED + "=1";

        // extract authorization header
        String header = request.getHeader(IWAConstants.AUTHORIZATION_HEADER);

        //check if authentication request from the same host as the Identity Server
        if (isLocalhost(request)) {
            // we cannot handle this since the Identity Server and Kerberos Server are running on the same host
            // A kerberos server cannot issue a token to authenticate itself
            throw new ServletException("Cannot handle IWA authentication request from the same host as the KDC");
        } else if (header != null) {
            HttpSession session = request.getSession(true);
            if (session == null) {
                throw new ServletException("Expected HttpSession");
            }

            if (!header.startsWith(IWAConstants.NEGOTIATE_HEADER)) {
                log.error(IWAConstants.NEGOTIATE_HEADER + " header not found");
            } else {
                // extract the token from the header
                String token = header.substring(IWAConstants.NEGOTIATE_HEADER.length()).trim();
                if (token.startsWith(IWAConstants.NTLM_PROLOG)) {
                    log.warn("NTLM token found.");
                    // TODO handle NTLM token
                    response.sendRedirect(commonAuthURL);
                    return;
                }
                // pass the kerberos token to the authenticator
                session.setAttribute(IWAConstants.KERBEROS_TOKEN, token);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No Authorization Header found in the request for IWA Authentication. " +
                        "Sending Unauthorized response.");
            }
            //Send unauthorized response to get gss/NTLM token
            sendUnauthorized(response, false);
            return;
        }

        response.sendRedirect(commonAuthURL);
    }

    /**
     * Send response as unauthorized
     *
     * @param response
     * @param close    whether to close the connection or to keep it alive
     */
    private void sendUnauthorized(HttpServletResponse response, boolean close) {
        try {
            response.setHeader(IWAConstants.AUTHENTICATE_HEADER, IWAConstants.NEGOTIATE_HEADER);
            if (close) {
                response.addHeader(IWAConstants.HTTP_CONNECTION_HEADER, IWAConstants.CONNECTION_CLOSE);
            } else {
                response.addHeader(IWAConstants.HTTP_CONNECTION_HEADER, IWAConstants.CONNECTION_KEEP_ALIVE);
            }
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
        } catch (IOException e) {
            log.error("Error when sending Unauthorized Response for IWA Authentication request without " +
                    "an Authorization Header.", e);
        }
    }

    /**
     * Returns true if HTTP request is from the same host (localhost).
     *
     * @param req servlet request
     * @return true if HTTP request is from the same host (localhost)
     */
    private boolean isLocalhost(final HttpServletRequest req) {
        return StringUtils.equals(req.getLocalAddr(), (req.getRemoteAddr()));
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        try {
            // set the kerberos config path
            IWAAuthenticationUtil.setConfigFilePaths();
            IWAAuthenticationUtil.initializeIWALocalAuthenticator();
        } catch (GSSException | LoginException | PrivilegedActionException e) {
            throw new ServletException("Error when creating gss credentials.", e);
        }
    }
}
