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


import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IWAFederatedAuthenticator authenticates a user from a Kerberos Token (GSS Token) sent by a pre-registered KDC.
 */
public class IWAFederatedAuthenticator extends AbstractIWAAuthenticator implements FederatedApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWAFederatedAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "IWA federated";

    private static final long serialVersionUID = -713445365110141169L;

    private static final Log log = LogFactory.getLog(IWAFederatedAuthenticator.class);
    private static ConcurrentHashMap<String, GSSCredential> gssCredentialMap = new ConcurrentHashMap<>();

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);
        HttpSession session = request.getSession(false);

        Map authenticatorProperties = context.getAuthenticatorProperties();

        GSSCredential gssCredential;
        try {
            String kerberosServer = (String) authenticatorProperties.get(IWAConstants.KERBEROS_SERVER);
            String servicePrincipalName = (String) authenticatorProperties.get(IWAConstants.SPN_NAME);
            String servicePrincipalPassword = (String) authenticatorProperties.get(IWAConstants.SPN_PASSWORD);

            if (StringUtils.isBlank(kerberosServer) || StringUtils.isBlank(servicePrincipalName) ||
                    StringUtils.isBlank(servicePrincipalPassword)) {
                throw new AuthenticationFailedException
                        ("Kerberos Server/Service Principal Name/Service Principal Password cannot " +
                                "be empty to create credentials for KDC : " + kerberosServer);
            }

            // get credentials for the kerberos server
            gssCredential = IWAAuthenticationUtil.getCredentials(kerberosServer);
            // create new server credentials for KDC since they don't exist
            if (gssCredential == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Server credentials not available for KDC : " + kerberosServer);
                }

                gssCredential = IWAAuthenticationUtil.createCredentials(kerberosServer, servicePrincipalName,
                        servicePrincipalPassword);

                if (log.isDebugEnabled()) {
                    log.debug("Created new server credentials for " + kerberosServer);
                }
            }

        } catch (PrivilegedActionException | LoginException | GSSException ex) {
            throw new AuthenticationFailedException("Cannot create kerberos credentials for server.", ex);
        }

        final String gssToken = (String) session.getAttribute(IWAConstants.GSS_TOKEN);

        // get the authenticated username from the GSS Token
        String authenticatedUserName = getAuthenticatedUserFromToken(gssCredential, Base64.decode(gssToken));
        if (StringUtils.isEmpty(authenticatedUserName)) {
            throw new AuthenticationFailedException("Authenticated user not found in GSS Token");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user extracted from kerberos ticket : " + authenticatedUserName);
            }
        }

        // remove the AD domain from the username
        int index = authenticatedUserName.lastIndexOf("@");
        authenticatedUserName = authenticatedUserName.substring(0, index);

        if (log.isDebugEnabled()) {
            log.debug("Authenticated Federated User : " + authenticatedUserName);
        }

        context.setSubject(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserName));
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List configProperties = new ArrayList();

        Property kerberosServerURL = new Property();
        kerberosServerURL.setName(IWAConstants.KERBEROS_SERVER);
        kerberosServerURL.setDisplayName("Kerberos Server URL");
        kerberosServerURL.setRequired(true);
        kerberosServerURL.setDescription("Kerberos Server");
        configProperties.add(kerberosServerURL);

        Property SPNName = new Property();
        SPNName.setName(IWAConstants.SPN_NAME);
        SPNName.setDisplayName("Service Principal Name");
        SPNName.setRequired(true);
        SPNName.setDescription("Kerberos Service Principal Name");
        configProperties.add(SPNName);

        Property SPNPassword = new Property();
        SPNPassword.setName(IWAConstants.SPN_PASSWORD);
        SPNPassword.setDisplayName("Service Principal Password");
        SPNPassword.setRequired(true);
        SPNPassword.setDescription("Kerberos Service Principal Password");
        SPNPassword.setConfidential(true);
        configProperties.add(SPNPassword);

        return configProperties;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }


    private String getAuthenticatedUserFromToken(GSSCredential gssCredentials, byte[] gssToken) throws AuthenticationFailedException {
        try {
            return IWAAuthenticationUtil.processToken(gssCredentials, gssToken);
        } catch (GSSException e) {
            throw new AuthenticationFailedException("Error processing the GSS Token", e);
        }
    }
}
