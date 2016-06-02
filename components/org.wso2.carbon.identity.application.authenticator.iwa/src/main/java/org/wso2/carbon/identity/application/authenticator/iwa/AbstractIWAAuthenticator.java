/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.iwa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;


public abstract class AbstractIWAAuthenticator extends AbstractApplicationAuthenticator {

    //the following param of the request will be set once the request is processed by the IWAServlet
    public static final String IWA_PROCESSED = "iwaauth";
    private static final long serialVersionUID = -713445365980141169L;

    private static Log log = LogFactory.getLog(AbstractIWAAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        HttpSession session = request.getSession(false);

        // first check username in the session
        if (session.getAttribute(IWAConstants.USER_NAME) == null) {
            if (session.getAttribute(IWAConstants.GSS_TOKEN) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("GSS Token not present.");
                }
                throw new AuthenticationFailedException("Authentication Failed");
            }
        }

    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return request.getParameter(IWA_PROCESSED) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        sendToLoginPage(request, response, context.getContextIdentifier());
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(IWAConstants.IWA_PARAM_STATE);
    }


    public void sendToLoginPage(HttpServletRequest request, HttpServletResponse response, String ctx)
            throws AuthenticationFailedException {
        String iwaURL = null;
        try {
            iwaURL = IdentityUtil.getServerURL(IWAConstants.IWA_AUTH_EP, false, true) +
                    "?" + IWAConstants.IWA_PARAM_STATE + "=" + URLEncoder.encode(ctx, IWAConstants.UTF_8);
            response.sendRedirect(response.encodeRedirectURL(iwaURL));
        } catch (IOException e) {
            log.error("Error when sending to the login page :" + iwaURL, e);
            throw new AuthenticationFailedException("Authentication failed");
        }
    }
}
