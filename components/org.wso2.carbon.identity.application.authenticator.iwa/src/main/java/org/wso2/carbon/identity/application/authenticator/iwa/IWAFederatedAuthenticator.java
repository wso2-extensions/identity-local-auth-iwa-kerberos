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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

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
        final String gssToken = (String) session.getAttribute(IWAConstants.KERBEROS_TOKEN);
        IWAAuthenticationUtil.invalidateSession(request);

        Map authenticatorProperties = context.getAuthenticatorProperties();
        GSSCredential gssCredential;
        String userStoreDomain;
        try {
            // URL of the Kerberos Server that issues the token the user will authenticate with.
            String kdcServerUrl = (String) authenticatorProperties.get(IWAConstants.KERBEROS_SERVER);

            // Service Principal Name : an identifier representing IS registered at the Kerberos Server, this can
            // sometimes be the service account of the IS at the Kerberos Server
            String spnName = (String) authenticatorProperties.get(IWAConstants.SPN_NAME);

            userStoreDomain = (String) authenticatorProperties.get(IWAConstants.USER_STORE_DOMAIN);

            // Password of the service account of IS at the Kerberos Server
            char[] spnPassword = authenticatorProperties.get(IWAConstants.SPN_PASSWORD).toString().toCharArray();

            String errorMsg = null;
            if (StringUtils.isBlank(kdcServerUrl)) {
                errorMsg = "Kerberos Server URL cannot be empty.";
            } else if (StringUtils.isBlank(spnName)) {
                errorMsg = "Service Principal Name (SPN) cannot be empty.";
            } else if (ArrayUtils.isEmpty(spnPassword)) {
                errorMsg = "Service Principal password cannot be empty.";
            }

            if (errorMsg != null) {
                throw new AuthenticationFailedException(errorMsg);
            }

            // create credentials to decrypt the Kerberos Token used to authenticate the user
            gssCredential = IWAAuthenticationUtil.createCredentials(spnName, spnPassword);

        } catch (PrivilegedActionException | LoginException | GSSException ex) {
            throw new AuthenticationFailedException("Cannot create kerberos credentials for server.", ex);
        }

        // get the authenticated username from the GSS Token
        String fullyQualifiedName = getAuthenticatedUserFromToken(gssCredential, Base64.decode(gssToken));
        String realm = IWAAuthenticationUtil.extractRealmFromUserName(fullyQualifiedName);
        String authenticatedUserName = IWAAuthenticationUtil.getDomainAwareUserName(fullyQualifiedName);

        if (log.isDebugEnabled()) {
            log.debug("Authenticated Federated User : " + authenticatedUserName);
        }

        boolean isExistInPrimaryUserStore = isExistsInUserStore(authenticatedUserName,
                                                                context.getTenantDomain(), userStoreDomain);
        if (!isExistInPrimaryUserStore) {
            String msg = "User " + authenticatedUserName + "not found in the user store of tenant " + userStoreDomain;
            throw new AuthenticationFailedException("Authentication Failed, " + msg);
        }
        AuthenticatedUser authenticatedUserObj =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserName);
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(authenticatedUserName);
        authenticatedUserObj.setUserAttributes(
                IWAAuthenticationUtil.buildClaimMappingMap(getUserClaims(authenticatedUserName,
                                                                         context.getTenantDomain(), userStoreDomain)));
        context.setSubject(authenticatedUserObj);
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property kerberosServerURL = new Property();
        kerberosServerURL.setName(IWAConstants.KERBEROS_SERVER);
        kerberosServerURL.setDisplayName("Kerberos Server URL");
        kerberosServerURL.setRequired(true);
        kerberosServerURL.setDescription("Kerberos Server");
        configProperties.add(kerberosServerURL);

        Property spnName = new Property();
        spnName.setName(IWAConstants.SPN_NAME);
        spnName.setDisplayName("Service Principal Name");
        spnName.setRequired(true);
        spnName.setDescription("Kerberos Service Principal Name");
        configProperties.add(spnName);

        Property spnPassword = new Property();
        spnPassword.setName(IWAConstants.SPN_PASSWORD);
        spnPassword.setDisplayName("Service Principal Password");
        spnPassword.setRequired(true);
        spnPassword.setDescription("Kerberos Service Principal Password");
        spnPassword.setConfidential(true);
        configProperties.add(spnPassword);

        Property spnUserStoreDomain = new Property();
        spnUserStoreDomain.setName(IWAConstants.USER_STORE_DOMAIN);
        spnUserStoreDomain.setDisplayName("User store domains");
        spnUserStoreDomain.setRequired(false);
        spnUserStoreDomain.setDescription("User store domains comma (,) separated to check user");
        spnUserStoreDomain.setConfidential(false);
        configProperties.add(spnUserStoreDomain);

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


    private String getAuthenticatedUserFromToken(GSSCredential gssCredentials, byte[] gssToken)
            throws AuthenticationFailedException {
        try {
            return IWAAuthenticationUtil.processToken(gssToken, gssCredentials);
        } catch (GSSException e) {
            throw new AuthenticationFailedException("Error processing the GSS Token", e);
        }
    }

    private boolean IsUserExistsInListedUserStores(String authenticatedUserName, String tenantDomain, String
            userStoreDomains) throws AuthenticationFailedException {
        boolean isUserExists = false;
        try {
            for (String userStoreDomain : userStoreDomains.split(",")
                    ) {
                if (isExistsInUserStore(authenticatedUserName, tenantDomain, userStoreDomain)) {
                    isUserExists = true;
                }
            }
            return isUserExists;
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("IWAFederatedAuthenticator " +
                                                    "failed to find the user in the userstore", e);
        }
    }


    /**
     * Check whether the authenticated user exists in any user store that belongs to the realm the user belongs to.
     *
     * @param authenticatedUserName
     * @param tenantDomain
     * @param userStoreDomain
     * @return
     */
    private boolean isExistsInUserStore(String authenticatedUserName, String tenantDomain, String userStoreDomain)
            throws
            AuthenticationFailedException {
        UserStoreManager userStoreManager;
        try {
            userStoreManager = getPrimaryUserStoreManager(tenantDomain).getSecondaryUserStoreManager(userStoreDomain);
            // String userStoreDomain = IdentityUtil.getPrimaryDomainName();
            authenticatedUserName = IdentityUtil.addDomainToName(authenticatedUserName, userStoreDomain);

            // Check whether the authenticated user is in primary user store. This is a limitation and will be improved
            // to support ADs mounted as secondary user stores
            return userStoreManager.isExistingUser(MultitenantUtils.getTenantAwareUsername(authenticatedUserName));

        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("IWAFederatedAuthenticator " +
                                                    "failed to find the user in the userstore", e);
        }

    }

    /**
     * Gets Array of user claims which are associated with the given user.
     *
     * @param authenticatedUserName
     * @param tenantDomain
     * @param userStoreDomains
     * @return
     * @throws AuthenticationFailedException
     */
    private Claim[] getUserClaims(String authenticatedUserName, String tenantDomain,
                                  String userStoreDomains) throws
                                                           AuthenticationFailedException {
        String searchUserStore = IWAConstants.PRIMARY_USERSTORE;
        try {
            for (String userStoreDomain : userStoreDomains.split(",")
                    ) {
                if (isExistsInUserStore(authenticatedUserName, tenantDomain, userStoreDomain)) {
                    searchUserStore = userStoreDomain;
                    break;
                } else {
                    continue;
                }
            }
            return getPrimaryUserStoreManager(tenantDomain)
                    .getSecondaryUserStoreManager(searchUserStore).getUserClaimValues
                            (authenticatedUserName, "");
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("IWAFederatedAuthenticator failed to get user claims " +
                                                    "from userstore", e);
        }
    }

    private UserStoreManager getPrimaryUserStoreManager(String tenantDomain) throws UserStoreException {
        RealmService realmService = IWAServiceDataHolder.getInstance().getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

        return (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
    }


}
