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

public class IWAFederatedAuthenticator extends AbstractIWAAuthenticator implements FederatedApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWAFederatedAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "iwa federated";

    private static final long serialVersionUID = -713445365110141169L;

    private static final Log log = LogFactory.getLog(IWAFederatedAuthenticator.class);
    private static ConcurrentHashMap<String, GSSCredential> gssCredentialMap = new ConcurrentHashMap<>();

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);

        Map authenticatorProperties = context.getAuthenticatorProperties();
        String kerberosServer = (String) authenticatorProperties.get(IWAConstants.KERBEROS_SERVER);

        // get credentials for the kerberos server
        GSSCredential gssCredential = IWAAuthenticationUtil.getCredentials(kerberosServer);

        try {
            // create server credentials for KDC
            if (gssCredential == null) {
                String servicePrincipalName = (String) authenticatorProperties.get(IWAConstants.SPN_NAME);
                String servicePrincipalPassword = (String) authenticatorProperties.get(IWAConstants.SPN_PASSWORD);

                gssCredential = IWAAuthenticationUtil.createCredentials(kerberosServer, servicePrincipalName,
                        servicePrincipalPassword);
            }

        } catch (PrivilegedActionException | LoginException | GSSException ex) {
            throw new AuthenticationFailedException("Cannot create kerberos credentials for server.", ex);
        }

        HttpSession session = request.getSession(false);
        final String gssToken = (String) session.getAttribute(IWAConstants.GSS_TOKEN);

        // get the authenticated username from the GSS Token
        String AuthenticatedUserName = getAuthenticatedUserFromToken(gssCredential, Base64.decode(gssToken));

        if (StringUtils.isEmpty(AuthenticatedUserName)) {
            throw new AuthenticationFailedException("Authenticated user not found in GSS Token");
        }

        // remove the AD domain from the username
        int index = AuthenticatedUserName.lastIndexOf("@");
        AuthenticatedUserName = AuthenticatedUserName.substring(0, index);

        if (log.isDebugEnabled()) {
            log.debug("Authenticate request received : AuthType - " + request.getAuthType() + ", User - " + AuthenticatedUserName);
        }

        context.setSubject(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(AuthenticatedUserName));
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
            log.error("Error processing the GSS token.", e);
            throw new AuthenticationFailedException("Error processing the GSS Token");
        }
    }
}
