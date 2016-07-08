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
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.service.RealmService;

import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;


/**
 * Util class for IWA Authenticator
 */
public class IWAAuthenticationUtil {

    private static GSSManager gssManager = GSSManager.getInstance();
    private static IWAServiceDataHolder dataHolder = IWAServiceDataHolder.getInstance();

    // holds the local IWA Authenticator credentials
    private static transient GSSCredential localIWACredentials;
    private static transient KerberosPrincipal serverPrincipal;

    // Shared Map to hold IWA GSS credentials for respective Kerberos servers
    private static transient Map<String, GSSCredential> gssCredentialMap = new ConcurrentHashMap<>();
    private static Log log = LogFactory.getLog(IWAAuthenticationUtil.class);


    public static void initializeIWALocalAuthenticator() throws GSSException, PrivilegedActionException, LoginException {
        RealmService realmService = dataHolder.getRealmService();

        String servicePrincipalName =
                realmService.getBootstrapRealmConfiguration().getUserStoreProperty(IWAConstants.SPN_NAME);
        String servicePrincipalPassword =
                realmService.getBootstrapRealmConfiguration().getUserStoreProperty(IWAConstants.SPN_PASSWORD);

        if (StringUtils.isNotEmpty(servicePrincipalName) && StringUtils.isNotEmpty(servicePrincipalPassword)) {
            CallbackHandler callbackHandler = getUsernamePasswordHandler(servicePrincipalName, servicePrincipalPassword);
            // create kerberos server credentials for IS
            localIWACredentials = createServerCredentials(callbackHandler);
            serverPrincipal = new KerberosPrincipal(localIWACredentials.getName().toString());
        }
    }

    /**
     * Process kerberos token and get user name
     *
     * @param gssToken kerberos token
     * @return username Username of the logged in user
     * @throws GSSException
     */
    public static String processToken(byte[] gssToken, GSSCredential gssCredentials) throws GSSException {
        GSSContext context = gssManager.createContext(gssCredentials);
        // decrypt the kerberos ticket (GSS token)
        context.acceptSecContext(gssToken, 0, gssToken.length);

        String loggedInUserName;
        String target;

        // if we cannot decrypt the GSS Token we return the username as null
        if (!context.isEstablished()) {
            log.error("Unable to decrypt the kerberos ticket as context was not established.");
            return null;
        }

        loggedInUserName = context.getSrcName().toString();
        target = context.getTargName().toString();

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
        String kerberosFilePath = System.getProperty(IWAConstants.KERBEROS_CONFIG_FILE);
        String jaasConfigPath = System.getProperty(IWAConstants.JAAS_CONFIG_FILE);

        String carbonHome = System.getProperty(CarbonBaseConstants.CARBON_HOME);

        // set the krb5.conf file path if not set by the system property already
        if (IdentityUtil.isBlank(kerberosFilePath)) {
            kerberosFilePath =
                    Paths.get(carbonHome, "repository", "conf", "identity", IWAConstants.KERBEROS_CONF_FILE_NAME)
                            .toString();
            System.setProperty(IWAConstants.KERBEROS_CONFIG_FILE, kerberosFilePath);
        }

        // set jaas.conf file path if not set by the system property already
        if (IdentityUtil.isBlank(jaasConfigPath)) {
            jaasConfigPath = Paths.get(carbonHome, "repository", "conf", "identity", IWAConstants.JAAS_CONF_FILE_NAME)
                    .toString();
            System.setProperty(IWAConstants.JAAS_CONFIG_FILE, jaasConfigPath);
        }

        if (log.isDebugEnabled()) {
            log.debug("Kerberos config file path set : " + kerberosFilePath + " ,JAAS config file path set : "
                    + jaasConfigPath);
        }

    }

    /**
     * Create server credential using SPN
     *
     * @param callbackHandler username password callback handler
     * @throws PrivilegedActionException
     * @throws LoginException
     */
    private static GSSCredential createServerCredentials(CallbackHandler callbackHandler)
            throws PrivilegedActionException, LoginException {
        // authenticate to the AD (Kerberos Server)
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
        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                                dataHolder.getSpnegoOid(), GSSCredential.ACCEPT_ONLY);
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
    private static CallbackHandler getUsernamePasswordHandler(final String username, final String password) {
        final CallbackHandler handler = new CallbackHandler() {
            public void handle(final Callback[] callback) {
                for (int i = 0; i < callback.length; i++) {
                    Callback currentCallBack = callback[i];
                    if (currentCallBack instanceof NameCallback) {
                        final NameCallback nameCallback = (NameCallback) currentCallBack;
                        nameCallback.setName(username);
                    } else if (currentCallBack instanceof PasswordCallback) {
                        final PasswordCallback passCallback = (PasswordCallback) currentCallBack;
                        passCallback.setPassword(password.toCharArray());
                    } else {
                        log.error("Unsupported Callback i = " + i + "; class = " + currentCallBack.getClass().getName());
                    }
                }
            }
        };

        return handler;
    }


    /**
     * get GSSCredentials for a particular KDC server
     *
     * @param kdcServerURL URL of the Kerberos Server
     * @return
     */
    public static GSSCredential getCredentials(String kdcServerURL) {
        return gssCredentialMap.get(kdcServerURL);
    }


    /**
     * Create GSSCredentials to communicate with a Kerberos Server
     *
     * @param kdcServer   URL of the Kerberos Server
     * @param SPNName     Service Principal Name for the Identity Server
     * @param SPNPassword Service Principal password
     * @return created GSSCredentials
     * @throws PrivilegedActionException
     * @throws LoginException
     * @throws GSSException
     */
    public static GSSCredential createCredentials(String kdcServer, String SPNName, String SPNPassword)
            throws PrivilegedActionException, LoginException, GSSException {

        CallbackHandler callbackHandler = getUsernamePasswordHandler(SPNName, SPNPassword);
        GSSCredential gssCredential = createServerCredentials(callbackHandler);

        // add the created credentials to the map
        gssCredentialMap.put(kdcServer.toLowerCase(), gssCredential);
        return gssCredential;
    }

}
