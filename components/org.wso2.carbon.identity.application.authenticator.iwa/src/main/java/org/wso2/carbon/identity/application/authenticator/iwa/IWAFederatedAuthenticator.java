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
import org.wso2.carbon.identity.application.authenticator.iwa.bean.IWAAuthenticatedUserBean;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * IWAFederatedAuthenticator authenticates a user from a Kerberos Token (GSS Token) sent by a pre-registered KDC.
 */
public class IWAFederatedAuthenticator extends AbstractIWAAuthenticator implements FederatedApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWAKerberosAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "IWA Kerberos";

    private static final long serialVersionUID = -713445365110141169L;
    private static final Log log = LogFactory.getLog(IWAFederatedAuthenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);
        IWAAuthenticatedUserBean iwaAuthenticatedUserBean;
        HttpSession session = request.getSession(false);
        final String gssToken = (String) session.getAttribute(IWAConstants.KERBEROS_TOKEN);
        IWAAuthenticationUtil.invalidateSession(request);

        Map authenticatorProperties = context.getAuthenticatorProperties();
        GSSCredential gssCredential;
        String userStoreDomains;
        try {
            // Service Principal Name : an identifier representing IS registered at the Kerberos Server, this can
            // sometimes be the service account of the IS at the Kerberos Server
            String spnName = (String) authenticatorProperties.get(IWAConstants.SPN_NAME);

            // User store domains in which we need to check whether the authenicated user in Kerberos ticket exists in
            userStoreDomains = (String) authenticatorProperties.get(IWAConstants.USER_STORE_DOMAINS);

            // Password of the service account of IS at the Kerberos Server
            char[] spnPassword = authenticatorProperties.get(IWAConstants.SPN_PASSWORD).toString().toCharArray();

            String errorMsg = null;
           if (StringUtils.isBlank(spnName)) {
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
        String authenticatedUserName = IWAAuthenticationUtil.getDomainAwareUserName(fullyQualifiedName);

        if (log.isDebugEnabled()) {
            log.debug("Authenticated Federated User : " + authenticatedUserName);
        }

        if (StringUtils.isEmpty(userStoreDomains)) {
            // No UserStoreDomain values were set in the UI, so we don't have to check for existence of user in
            // user stores. ie. we will consider this user as a federated one.
            context.setSubject(
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserName));
        } else {
            // We need to check the user's existence in specified user store domains
            iwaAuthenticatedUserBean = userInformationInListedUserStores(authenticatedUserName,
                    context.getTenantDomain(), userStoreDomains);

            if (!iwaAuthenticatedUserBean.isUserExists()) {
                String msg = "User: %s not found in any of specified userstores: %s of tenant: %s.";
                throw new AuthenticationFailedException("Authentication Failed, " +
                        String.format(msg, authenticatedUserName, userStoreDomains, context.getTenantDomain()));
            }

            //Creates local authenticated user since this refer available user stores for user.
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(iwaAuthenticatedUserBean.getUser());
            authenticatedUser.setUserStoreDomain(iwaAuthenticatedUserBean.getUserStoreDomain());
            authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(iwaAuthenticatedUserBean.getTenantDomain()));
            authenticatedUser.setAuthenticatedSubjectIdentifier(iwaAuthenticatedUserBean.getUser());
            authenticatedUser.setUserAttributes(
                    IWAAuthenticationUtil.buildClaimMappingMap(getUserClaims(iwaAuthenticatedUserBean)));
            context.setSubject(authenticatedUser);
        }
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();

        Property spnName = new Property();
        spnName.setName(IWAConstants.SPN_NAME);
        spnName.setDisplayName("Service Principal Name");
        spnName.setRequired(true);
        spnName.setDescription("Kerberos Service Principal Name");
        spnName.setDisplayOrder(1);
        configProperties.add(spnName);

        Property spnPassword = new Property();
        spnPassword.setName(IWAConstants.SPN_PASSWORD);
        spnPassword.setDisplayName("Service Principal Password");
        spnPassword.setRequired(true);
        spnPassword.setDescription("Kerberos Service Principal Password");
        spnPassword.setDisplayOrder(2);
        spnPassword.setConfidential(true);
        configProperties.add(spnPassword);

        Property userStoreDomains = new Property();
        userStoreDomains.setName(IWAConstants.USER_STORE_DOMAINS);
        userStoreDomains.setDisplayName("User Store Domains");
        userStoreDomains.setRequired(false);
        userStoreDomains.setDisplayOrder(3);
        userStoreDomains.setDescription("Comma (,) separated UserStore Domains (Leave this blank if you don't want " +
                "to check user's presence in mounted user stores.)");
        configProperties.add(userStoreDomains);

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
            String extractedUserFromTicket = IWAAuthenticationUtil.processToken(gssToken, gssCredentials);
            if (StringUtils.isNotBlank(extractedUserFromTicket)) {
                return extractedUserFromTicket;
            } else {
                // This means the authenticated user information was not found from decrypting the Kerberos Token.
                throw new AuthenticationFailedException("Unable to extract authenticated user from Kerberos Token.");
            }
        } catch (GSSException e) {
            throw new AuthenticationFailedException("Error while processing the GSS Token.", e);
        }
    }

    /**
     * Gets IWAAuthenticatedUserBean based on the availability of the user in given user stores.
     *
     * @param authenticatedUserName
     * @param tenantDomain
     * @param userStoreDomains
     * @return
     * @throws AuthenticationFailedException
     */
    private IWAAuthenticatedUserBean userInformationInListedUserStores(String authenticatedUserName,
                                                                       String tenantDomain,
                                                                       String userStoreDomains)
            throws AuthenticationFailedException {

        boolean isUserExists = false;
        String userStoreDomainForUser = null;
        IWAAuthenticatedUserBean authenticatedUserBean = new IWAAuthenticatedUserBean();
        try {
            for (String userStoreDomain : userStoreDomains.split(",")) {
                if (isUserExistsInUserStore(authenticatedUserName, tenantDomain, userStoreDomain.trim())) {
                    isUserExists = true;
                    userStoreDomainForUser = userStoreDomain.trim();
                    break;
                }
            }
            authenticatedUserBean.setTenantDomain(tenantDomain);
            authenticatedUserBean.setUser(authenticatedUserName);
            authenticatedUserBean.setUserExists(isUserExists);
            authenticatedUserBean.setUserStoreDomain(userStoreDomainForUser);
            return authenticatedUserBean;

        } catch (AuthenticationFailedException e) {
            String msg = "IWAApplicationAuthenticator failed to find the user:%s of tenantDomain=%s in neither one of" +
                    " userstore domains:%s";
            throw new AuthenticationFailedException(
                    String.format(msg, authenticatedUserName, tenantDomain, userStoreDomains), e);
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
    private boolean isUserExistsInUserStore(String authenticatedUserName, String tenantDomain, String userStoreDomain)
            throws
            AuthenticationFailedException {
        UserStoreManager userStoreManager;
        try {
            String userNameWithUserStoreDomain = IdentityUtil.addDomainToName(authenticatedUserName, userStoreDomain);
            userStoreManager = getPrimaryUserStoreManager(tenantDomain);
            // check whether the user exists in the given user store domain
            return userStoreManager.isExistingUser(userNameWithUserStoreDomain);

        } catch (UserStoreException e) {
            String errorMsg = "Error when searching for user: %s in '%s' userStoreDomain in '%s' tenant.";
            throw new AuthenticationFailedException(
                    String.format(errorMsg, authenticatedUserName, userStoreDomain, tenantDomain), e);
        }
    }

    /**
     * Gets Array of user claims which are associated with the given user.
     *
     * @param userBean
     * @return
     * @throws AuthenticationFailedException
     */
    private Claim[] getUserClaims(IWAAuthenticatedUserBean userBean) throws
            AuthenticationFailedException {
        try {
            return getPrimaryUserStoreManager(userBean.getTenantDomain())
                    .getSecondaryUserStoreManager(userBean.getUserStoreDomain()).getUserClaimValues
                            (userBean.getUser(), "");
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("IWAApplicationAuthenticator failed to get user claims " +
                    "from userstore", e);
        }
    }

    private UserStoreManager getPrimaryUserStoreManager(String tenantDomain) throws UserStoreException {
        RealmService realmService = IWAServiceDataHolder.getInstance().getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        return (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
    }
}
