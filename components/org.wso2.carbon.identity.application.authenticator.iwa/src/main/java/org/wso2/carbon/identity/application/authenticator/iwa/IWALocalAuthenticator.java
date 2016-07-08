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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSException;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * IWALocalAuthenticator authenticates a user from a Kerberos Token (GSS Token) sent by a pre-registered KDC
 * (ie. the active directory). Currently we only authenticate users from the Primary user store of the super tenant
 * with this authenticator
 */
public class IWALocalAuthenticator extends AbstractIWAAuthenticator implements
        LocalApplicationAuthenticator {

    public static final String AUTHENTICATOR_NAME = "IWALocalAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "iwa-local";

    //the following param of the request will be set once the request is processed by the IWAServlet
    private static final long serialVersionUID = -713445365110141399L;
    private static Log log = LogFactory.getLog(IWALocalAuthenticator.class);


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        super.processAuthenticationResponse(request, response, context);

        HttpSession session = request.getSession(false);
        String gssToken = (String) session.getAttribute(IWAConstants.KERBEROS_TOKEN);
        invalidateSession(request);

        // get the authenticated username by processing the GSS Token
        String fullyQualifiedName;
        try {
            fullyQualifiedName = getAuthenticatedUserFromToken(Base64.decode(gssToken));
        } catch (GSSException e) {
            throw new AuthenticationFailedException("Error extracting username from the GSS Token.", e);
        }

        if (IdentityUtil.isBlank(fullyQualifiedName)) {
            throw new AuthenticationFailedException("Authenticated user not found in GSS Token : "
                    + fullyQualifiedName);
        }

        String authenticatedUserName = getDomainAwareUserName(fullyQualifiedName);

        boolean isExistInPrimaryUserStore;
        UserStoreManager userStoreManager;
        String spTenantDomain = context.getTenantDomain();
        try {
            userStoreManager = getPrimaryUserStoreManager(spTenantDomain);
            String userStoreDomain = IdentityUtil.getPrimaryDomainName();
            authenticatedUserName = IdentityUtil.addDomainToName(authenticatedUserName, userStoreDomain);

            // Check whether the authenticated user is in primary user store. This is a limitation and will be improved
            // to support ADs mounted as secondary user stores
            isExistInPrimaryUserStore =
                    userStoreManager.isExistingUser(MultitenantUtils.getTenantAwareUsername(authenticatedUserName));

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AuthenticationFailedException("IWALocalAuthenticator failed to find the user in the userstore", e);
        }

        if (!isExistInPrimaryUserStore) {
            String msg = "User " + authenticatedUserName + "not found in the user store of tenant " + spTenantDomain;
            throw new AuthenticationFailedException("Authentication Failed, " + msg);
        }

        String userNameWithTenantDomain = UserCoreUtil.addTenantDomainToEntry(authenticatedUserName, spTenantDomain);
        if (log.isDebugEnabled()) {
            log.debug("Authenticated Local User : " + userNameWithTenantDomain);
        }
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userNameWithTenantDomain));
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }


    /**
     * Method to extract the authenticated user name from the gss token
     *
     * @param gssToken base64 decoded gss token
     * @return true if token can be successfully processed using credentials
     * @throws GSSException
     */
    private String getAuthenticatedUserFromToken(byte[] gssToken) throws GSSException {
        return IWAAuthenticationUtil.processToken(gssToken);
    }


    private UserStoreManager getPrimaryUserStoreManager(String tenantDomain) throws UserStoreException {
        RealmService realmService = IWAServiceDataHolder.getInstance().getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

        return (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
    }
}
