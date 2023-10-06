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
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.io.IOException;
import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Abstract Class to handle common functionality of IWALocalAuthenticator and IWAFederatedAuthenticator
 */
public abstract class AbstractIWAAuthenticator extends AbstractApplicationAuthenticator {

    private static final long serialVersionUID = -713445365980141169L;
    private static final Log log = LogFactory.getLog(AbstractIWAAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        HttpSession session = request.getSession(false);
        if (session.getAttribute(IWAConstants.KERBEROS_TOKEN) == null) {
            throw new AuthenticationFailedException("GSS token not present in the http session");
        }
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return request.getParameter(IWAConstants.IWA_PROCESSED) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        sendToLoginPage(request, response, context.getContextIdentifier());
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(IWAConstants.IWA_PARAM_STATE);
    }

    /**
     * Redirect to the IWA servlet with the authentication context information
     *
     * @param request
     * @param response
     * @param ctx      Authentication context identifier
     * @throws AuthenticationFailedException
     */
    private void sendToLoginPage(HttpServletRequest request, HttpServletResponse response, String ctx)
            throws AuthenticationFailedException {

        String iwaURL = null;
        try {
            iwaURL = ServiceURLBuilder.create().addPath(IWAConstants.IWA_AUTH_EP).build().getAbsolutePublicURL() +
                    "?" + IWAConstants.IWA_PARAM_STATE + "=" + URLEncoder.encode(ctx, IWAConstants.UTF_8);
            response.sendRedirect(iwaURL);
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
        } catch (IOException e) {
            String msg = "Error when redirecting to the login page : " + iwaURL;
            throw new AuthenticationFailedException(msg, e);
        }
    }
}
