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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.utils.CarbonUtils;
import sun.security.jgss.GSSUtil;

import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

/**
 * Util class for IWA Authenticator
 */
public class IWAAuthenticationUtil {

    private static GSSManager gssManager = GSSManager.getInstance();
    private static IWAServiceDataHolder dataHolder = IWAServiceDataHolder.getInstance();

    // holds the local IWA Authenticator credentials
    private static transient GSSCredential localIWACredentials;
    private static transient KerberosPrincipal serverPrincipal;

    private static Log log = LogFactory.getLog(IWAAuthenticationUtil.class);


    /**
     * Process Kerberos token and get user name.
     *
     * @param gssToken GSS token
     * @return username Username of the logged in user if GSSToken can be decrypted correctly else return null
     * @throws GSSException
     */
    public static String processToken(byte[] gssToken, GSSCredential gssCredentials) throws GSSException {
        GSSContext context = gssManager.createContext(gssCredentials);
        // Decrypt the kerberos ticket (GSS token)
        context.acceptSecContext(gssToken, 0, gssToken.length);

        // If we cannot decrypt the GSS Token properly we return the username as null.
        if (!context.isEstablished()) {
            log.error("Unable to decrypt the kerberos ticket as context was not established.");
            return null;
        }

        String loggedInUserName = context.getSrcName().toString();
        String target = context.getTargName().toString();

        if (log.isDebugEnabled()) {
            String msg = "Extracted details from GSS Token, LoggedIn User : " + loggedInUserName
                    + " , Intended target : " + target;
            log.debug(msg);
        }

        return loggedInUserName;
    }


    /**
     * Process gss token with local IWA credentials
     *
     * @param gssToken kerberos token
     * @return username of the logged in user
     * @throws GSSException
     */
    public static String processToken(byte[] gssToken) throws GSSException {
        return processToken(gssToken, localIWACredentials);
    }


    /**
     * Set jaas.conf and krb5 paths
     */
    public static void setConfigFilePaths() {
        String jaasConfigPath = System.getProperty(IWAConstants.JAAS_CONFIG_PROPERTY);
        String krb5ConfigPath = System.getProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY);
        String identityConfPath = Paths.get(CarbonUtils.getCarbonConfigDirPath(), "identity").toString();

        // Set jaas.conf file path if not set by the system property already.
        if (IdentityUtil.isBlank(jaasConfigPath)) {
            jaasConfigPath = Paths.get(identityConfPath, IWAConstants.JAAS_CONF_FILE_NAME).toString();
            System.setProperty(IWAConstants.JAAS_CONFIG_PROPERTY, jaasConfigPath);
        }

        // Set the krb5.conf file if not set by the system property already.
        if (IdentityUtil.isBlank(krb5ConfigPath)) {
            krb5ConfigPath = Paths.get(identityConfPath, IWAConstants.KERBEROS_CONF_FILE_NAME).toString();
            System.setProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY, krb5ConfigPath);
        }

        if (log.isDebugEnabled()) {
            log.debug("Kerberos jaas.conf file path set to : " + jaasConfigPath);
            log.debug("Kerberos krb5.conf file path set to : " + krb5ConfigPath);
        }

    }

    /**
     * Create server credential using SPNName and SPNPassword. This credential is used to decrypt the Kerberos Token
     * presented by the user. Although an actual authentication does not happen with the KDC, an invalid password
     * will result in checksum failure when decrypting the token.
     *
     * @param callbackHandler username password callback handler
     * @throws PrivilegedActionException
     * @throws LoginException
     */
    private static GSSCredential createServerCredentials(CallbackHandler callbackHandler)
            throws PrivilegedActionException, LoginException {
        LoginContext loginContext = new LoginContext(IWAConstants.SERVER, callbackHandler);
        loginContext.login();

        if (log.isDebugEnabled()) {
            log.debug("Pre-authentication successful for with Kerberos Server.");
        }
        // create server credentials from pre authentication with the AD
        return createCredentialsForSubject(loginContext.getSubject());
    }


    /**
     * Create GSSCredential as Subject
     *
     * @param subject login context subject
     * @return GSSCredential
     * @throws PrivilegedActionException
     */
    private static GSSCredential createCredentialsForSubject(final Subject subject) throws PrivilegedActionException {
        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {
                return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                        GSSUtil.GSS_SPNEGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
            }
        };

        if (log.isDebugEnabled()) {
            Set<Principal> principals = subject.getPrincipals();
            String principalName = null;
            if (principals != null) {
                principalName = principals.toString();
            }
            log.debug("Creating gss credentials as principal : " + principalName);
        }
        return Subject.doAs(subject, action);
    }


    /**
     * Create call back handler using given username and password
     *
     * @param username
     * @param password
     * @return CallbackHandler
     */
    private static CallbackHandler getUserNamePasswordCallbackHandler(final String username, final char[] password) {

        return new CallbackHandler() {
            public void handle(final Callback[] callback) {
                for (Callback currentCallBack : callback) {
                    if (currentCallBack instanceof NameCallback) {
                        final NameCallback nameCallback = (NameCallback) currentCallBack;
                        nameCallback.setName(username);
                    } else if (currentCallBack instanceof PasswordCallback) {
                        final PasswordCallback passCallback = (PasswordCallback) currentCallBack;
                        passCallback.setPassword(password);
                    } else {
                        log.error("Unsupported Callback class = " + currentCallBack.getClass().getName());
                    }
                }
            }
        };
    }

    /**
     * Create GSSCredentials required to decrypt the Kerberos Token from the Kerberos Server in which Identity Server
     * is a Service Principal.
     *
     * @param spnName     Service Principal Name for the Identity Server
     * @param spnPassword Service Principal password
     * @return created GSSCredentials
     * @throws PrivilegedActionException
     * @throws LoginException
     * @throws GSSException
     */
    public static GSSCredential createCredentials(String spnName, char[] spnPassword)
            throws PrivilegedActionException, LoginException, GSSException {

        CallbackHandler callbackHandler = getUserNamePasswordCallbackHandler(spnName, spnPassword);
        return createServerCredentials(callbackHandler);
    }

    /**
     * Util Method to extract the Realm (Domain) name from a fullyQualified user name
     * eg: admin@IS.LOCAL --> IS.LOCAL
     *
     * @param fullyQualifiedUserName
     * @return
     */
    public static String extractRealmFromUserName(String fullyQualifiedUserName) {
        if (StringUtils.isEmpty(fullyQualifiedUserName)) {
            throw new IllegalArgumentException("Authenticated user's fully qualified name cannot be empty.");
        }

        // remove the AD domain from the username
        int index = fullyQualifiedUserName.lastIndexOf("@");
        return fullyQualifiedUserName.substring(index + 1);
    }

    /**
     * Util method to get the domain/realm aware username from the fullyQualified username
     * eg: admin@IS.LOCAL --> admin
     *
     * @param fullyQualifiedUserName
     * @return
     */
    public static String getDomainAwareUserName(String fullyQualifiedUserName) {
        if (StringUtils.isEmpty(fullyQualifiedUserName)) {
            throw new IllegalArgumentException("Authenticated user's fully qualified name cannot be empty.");
        }

        // remove the AD domain from the username
        int index = fullyQualifiedUserName.lastIndexOf("@");
        return fullyQualifiedUserName.substring(0, index);
    }

    /**
     * Invalide a session. This is to prevent session fixation attacks
     *
     * @param request
     */
    public static void invalidateSession(HttpServletRequest request) {
        if (request.isRequestedSessionIdValid()) {
            // invalidate the session. ie. clear all attributes
            request.getSession().invalidate();
            // create a new session thereby creating a new jSessionID
            request.getSession(true);
        }
    }

    /**
     * Build a claim mapping map with the Claim array for set claims.
     *
     * @param userClaims
     * @return
     */
    public static Map<ClaimMapping, String> buildClaimMappingMap(Claim[] userClaims) {
        Map<ClaimMapping, String> claims = new HashMap<>();
        for (Claim iwaClaim : userClaims) {
            if (iwaClaim.getValue() != null) {
                claims.put(ClaimMapping.build(iwaClaim.getClaimUri(), iwaClaim.getClaimUri(), iwaClaim.getValue(),
                        false), iwaClaim.getValue());
            }
        }
        return claims;
    }
}
