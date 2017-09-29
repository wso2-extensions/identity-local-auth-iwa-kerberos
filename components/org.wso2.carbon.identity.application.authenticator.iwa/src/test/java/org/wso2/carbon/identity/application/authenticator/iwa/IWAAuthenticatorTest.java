/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({IdentityUtil.class, IWAAuthenticationUtil.class, UserCoreUtil.class})
@PowerMockIgnore("org.ietf.jgss.*")
public class IWAAuthenticatorTest extends PowerMockTestCase{

    private static final String IWA_LOCAL_AUTHENTICATOR_NAME = "IWALocalAuthenticator";
    private static final String IWA_LOCAL_AUTHENTICATOR_FRIENDLY_NAME = "iwa-local";
    private static final String IWA_FEDERATED_AUTHENTICATOR_NAME = "IWAKerberosAuthenticator";
    private static final String IWA_FEDERATED_AUTHENTICATOR_FRIENDLY_NAME = "IWA Kerberos";
    private static final String IWA_AUTHENTICATOR_STATE = "iwaAuthenticatorState";
    private static final String IWA_REDIRECT_URL_WITH_PARAM =
            "https://localhost:9443/iwa-kerberos?state=iwaAuthenticatorState";
    private static final String IWA_REDIRECT_URL = "https://localhost:9443/iwa-kerberos";
    private static final String TOKEN_PATH = "src/test/resources/home/repository/conf/identity/token";

    private static final String SPN_NAME = "SPNName";
    private static final String USER_STORE_DOMAINS = "UserStoreDomains";
    private static final String SPN_PASSWORD = "SPNPassword";

    private static final String SPN_NAME_VALUE = "HTTP/idp.wso2.com@IS.LOCAL";
    private static final String USER_STORE_DOMAINS_VALUE = "PRIMARY";
    private static final String SPN_PASSWORD_VALUE = "password";

    @Mock
    HttpServletRequest mockHttpRequest;

    @Mock
    HttpServletResponse mockHttpResponse;

    @Mock
    HttpSession mockSession;

    @Mock
    RealmService mockRealmService;

    @Mock
    TenantManager mockTenantManager;

    @Mock
    AuthenticationContext mockAuthenticationContext;

    @Mock
    UserRealm mockUserRealm;

    @Mock
    UserStoreManager mockUserStoreManager;

    @Mock
    GSSCredential mockGSSCredential;

    @Mock
    Log mockedLog;

    private AbstractIWAAuthenticator iwaLocalAuthenticator;
    private AbstractIWAAuthenticator iwaFederatedAuthenticator;
    private List<Property> federatedAuthenticatorConfigs;
    private AuthenticatedUser authenticatedUser;
    private IWAServiceDataHolder dataHolder;
    private byte[] token;

    @BeforeTest
    public void setUp() throws Exception{

        iwaLocalAuthenticator = new IWALocalAuthenticator();
        iwaFederatedAuthenticator = new IWAFederatedAuthenticator();
        federatedAuthenticatorConfigs = new ArrayList<>();
        token = Files.readAllBytes(Paths.get(TOKEN_PATH));
        dataHolder = IWAServiceDataHolder.getInstance();
    }

    private void setMockHttpSession() {

        final Map<String,Object> attributes = new HashMap<>();

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                return attributes.get(key);
            }
        }).when(mockSession).getAttribute(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                Object value = invocation.getArguments()[1];
                attributes.put(key, value);
                return null;
            }
        }).when(mockSession).setAttribute(anyString(), any());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                attributes.clear();
                return null;
            }
        }).when(mockSession).invalidate();
    }

    private void setMockAuthenticationContext() {

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                authenticatedUser = (AuthenticatedUser) invocation.getArguments()[0];
                return null;
            }
        }).when(mockAuthenticationContext).setSubject(any(AuthenticatedUser.class));

    }

    private void setMockIWAAuthenticationUtil() throws Exception {

        mockStatic(IWAAuthenticationUtil.class);

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                HttpServletRequest key = (HttpServletRequest) invocation.getArguments()[0];
                key.getSession().invalidate();
                return null;
            }
        }).when(IWAAuthenticationUtil.class, "invalidateSession", any(HttpServletRequest.class));

        when(IWAAuthenticationUtil.getDomainAwareUserName(anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                if (args[0] != null && args.length > 0) {
                    int index = ((String) args[0]).lastIndexOf("@");
                    if (index > 0) {
                        return ((String) args[0]).substring(0, index);
                    }
                    return (String) args[0];
                }
                return null;
            }
        });
    }

    private void setMockUserCoreUtil() {

        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return (String) args[0] + "@" + args[1];
            }
        });
    }

    private void initCommonMocks() throws Exception{

        dataHolder.setRealmService(mockRealmService);
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockTenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getSecondaryUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn("carbon.super");

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("PRIMARY");

        when(IdentityUtil.addDomainToName(anyString(), anyString())).thenAnswer(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                if (args.length > 1 && (StringUtils.isNotEmpty((String)args[0]) &&
                        StringUtils.isNotEmpty((String)args[1]))) {
                    return (String) args[1] + "/" + (String) args[0];
                }
                return null;
            }
        });

        when(IdentityUtil.isBlank(anyString())).thenReturn(false);
        when(IdentityUtil.isBlank(null)).thenReturn(true);

        Class<?> clazz1 = IWALocalAuthenticator.class;
        Object localAuthObject = clazz1.newInstance();
        Field localAuthenticatorLogField = localAuthObject.getClass().getDeclaredField("log");
        localAuthenticatorLogField.setAccessible(true);
        localAuthenticatorLogField.set(localAuthObject, mockedLog);

        Class<?> clazz2 = IWAFederatedAuthenticator.class;
        Object federatedAuthObject = clazz2.newInstance();
        Field federatedAuthenticatorLogField = federatedAuthObject.getClass().getDeclaredField("log");

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(federatedAuthenticatorLogField, federatedAuthenticatorLogField.getModifiers() & ~Modifier.FINAL);

        federatedAuthenticatorLogField.setAccessible(true);
        federatedAuthenticatorLogField.set(federatedAuthObject, mockedLog);
        when(mockedLog.isDebugEnabled()).thenReturn(true);
    }



    @Test
    public void testCanHandle() {

        when(mockHttpRequest.getParameter(IWAConstants.IWA_PROCESSED)).thenReturn("1");
        Assert.assertTrue(iwaLocalAuthenticator.canHandle(mockHttpRequest), "CanHandle true expected");
    }

    @Test
    public void testCanHandleFail() {

        when(mockHttpRequest.getParameter(IWAConstants.IWA_PROCESSED)).thenReturn(null);
        Assert.assertFalse(iwaLocalAuthenticator.canHandle(mockHttpRequest), "CanHandle true in invalid conditions");
    }

    @Test
    public void testGetAuthenticatorName() {

        Assert.assertEquals(iwaLocalAuthenticator.getName(),
                IWA_LOCAL_AUTHENTICATOR_NAME, "Invalid authenticator name returned");
        Assert.assertEquals(iwaFederatedAuthenticator.getName(),
                IWA_FEDERATED_AUTHENTICATOR_NAME, "Invalid authenticator name returned");
    }

    @Test
    public void testGetAuthenticatorFriendlyName() {

        Assert.assertEquals(iwaLocalAuthenticator.getFriendlyName(),
                IWA_LOCAL_AUTHENTICATOR_FRIENDLY_NAME, "Invalid friendly name returned");
        Assert.assertEquals(iwaFederatedAuthenticator.getFriendlyName(),
                IWA_FEDERATED_AUTHENTICATOR_FRIENDLY_NAME, "Invalid friendly name returned");
    }

    @Test
    public void testInitiateAuthenticationRequest() throws Exception{

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(IWA_REDIRECT_URL);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(IWA_AUTHENTICATOR_STATE);

        final String[] redirectUrl = new String[1];
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArguments()[0];
            }
        }).when(mockHttpResponse).encodeRedirectURL(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                redirectUrl[0] = key;
                return null;
            }
        }).when(mockHttpResponse).sendRedirect(anyString());

        iwaLocalAuthenticator.initiateAuthenticationRequest(mockHttpRequest, mockHttpResponse,
                mockAuthenticationContext);
        Assert.assertEquals(redirectUrl[0], IWA_REDIRECT_URL_WITH_PARAM, "Invalid redirect url in sendRedirect");
    }

    @Test (expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateInvalidAuthenticationRequest() throws Exception{

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(IWA_REDIRECT_URL);
        when(mockAuthenticationContext.getContextIdentifier()).thenReturn(IWA_AUTHENTICATOR_STATE);

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                return invocation.getArguments()[0];
            }
        }).when(mockHttpResponse).encodeRedirectURL(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                throw new IOException();
            }
        }).when(mockHttpResponse).sendRedirect(anyString());

        iwaLocalAuthenticator.initiateAuthenticationRequest(mockHttpRequest, mockHttpResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testGetContextIdentifier() {

        when(mockHttpRequest.getParameter(IWAConstants.IWA_PARAM_STATE)).thenReturn(IWA_AUTHENTICATOR_STATE);
        String contextIdentifier = iwaLocalAuthenticator.getContextIdentifier(mockHttpRequest);
        Assert.assertEquals(contextIdentifier, IWA_AUTHENTICATOR_STATE, "Invalid context identifier");
    }

    @Test
    public void testAbstractProcessAuthenticationResponseException() throws Exception{

        initCommonMocks();

        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed without kerberos token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("GSS token not present in the http session"));
        }
    }

    @Test
    public void testProcessLocalInvalidTokenException() throws Exception{

        initCommonMocks();
        setMockHttpSession();
        setMockAuthenticationContext();
        setMockIWAAuthenticationUtil();
        setMockUserCoreUtil();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode("invalidKerberosTokenString".getBytes()));
        when(IWAAuthenticationUtil.processToken(any(byte[].class))).thenThrow(new GSSException(0));
        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with invalid kerberos token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Error extracting username from the GSS Token"));
        }
    }

    @Test
    public void testLocalUserNotFoundInTokenException() throws Exception {

        initCommonMocks();
        setMockHttpSession();
        setMockAuthenticationContext();
        setMockIWAAuthenticationUtil();
        setMockUserCoreUtil();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(IWAAuthenticationUtil.processToken(any(byte[].class))).thenReturn(null);

        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed when authenticated user is not found in the gss token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Authenticated user not found in GSS Token"));
        }
    }

    @Test
    public void testLocalUserNotFoundInUserStoreException() throws Exception {

        initCommonMocks();
        setMockHttpSession();
        setMockAuthenticationContext();
        setMockIWAAuthenticationUtil();
        setMockUserCoreUtil();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(IWAAuthenticationUtil.processToken(any(byte[].class))).thenReturn("wso2@IS.LOCAL");
        when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(false);

        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed when authenticated user is not found in the gss token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("not found in the user store of tenant"));
        }
    }

    @Test
    public void testProcessLocalAuthenticationResponse() throws Exception{

        initCommonMocks();
        setMockHttpSession();
        setMockAuthenticationContext();
        setMockIWAAuthenticationUtil();
        setMockUserCoreUtil();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(true);

        when(IWAAuthenticationUtil.processToken(token)).thenReturn("wso2@IS.LOCAL");

        iwaLocalAuthenticator.processAuthenticationResponse(
                mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
        Assert.assertEquals(authenticatedUser.getUserName(), "wso2");
    }

    @Test
    public void testFederatedConfigProperties() {

        federatedAuthenticatorConfigs = iwaFederatedAuthenticator.getConfigurationProperties();
        Property spnName = null;
        Property spnPassword = null;
        Property userStoreDomains = null;
        for (Property prop : federatedAuthenticatorConfigs) {
            if (SPN_NAME.equals(prop.getName())) {
                spnName = prop;
            } else if (SPN_PASSWORD.equals(prop.getName())) {
                spnPassword = prop;
            } else if (USER_STORE_DOMAINS.equals(prop.getName())) {
                userStoreDomains = prop;
            }
        }

        Assert.assertNotNull(spnName, "Configuration property not found for: " + SPN_NAME);
        Assert.assertNotNull(spnPassword, "Configuration property not found for: " + SPN_PASSWORD);
        Assert.assertNotNull(userStoreDomains, "Configuration property not found for: " + USER_STORE_DOMAINS);
    }

    @DataProvider(name = "provideInvalidAuthenticatorProperties")
    public Object[][] provideInvalidData() {

        Map<String, String> map1 = new HashMap<>();
        map1.put(SPN_NAME, "");
        map1.put(SPN_PASSWORD, SPN_PASSWORD_VALUE);

        Map<String, String> map2 = new HashMap<>();
        map2.put(SPN_NAME, SPN_NAME_VALUE);
        map2.put(SPN_PASSWORD, "");

        return new Object[][] {
                { map1, "Service Principal Name (SPN) cannot be empty" },
                { map2, "Service Principal password cannot be empty" }
        };
    }

    @Test (dataProvider = "provideInvalidAuthenticatorProperties")
    public void testInvalidFederatedAuthConfigs(Map<String, String> propertyMap, String errorMsg) throws Exception {

        setMockHttpSession();
        setMockIWAAuthenticationUtil();

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(propertyMap);
        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Authentication response processed with incorrect configs");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains(errorMsg), "Wrong exception thrown for given configs");
        }
    }

    @DataProvider(name = "provideAuthenticatorProperties")
    public Object[][] provideData() {

        Map<String, String> map1 = new HashMap<>();
        map1.put(SPN_NAME, SPN_NAME_VALUE);
        map1.put(SPN_PASSWORD, SPN_PASSWORD_VALUE);

        Map<String, String> map2 = new HashMap<>();
        map2.put(SPN_NAME, SPN_NAME_VALUE);
        map2.put(SPN_PASSWORD, SPN_PASSWORD_VALUE);
        map2.put(USER_STORE_DOMAINS, USER_STORE_DOMAINS_VALUE);

        return new Object[][] {
                { map1, "wso2" },
                { map2, "wso2"}
        };
    }

    @Test (dataProvider = "provideAuthenticatorProperties")
    public void testProcessFederatedAuthenticationRequest(Map<String, String> propertyMap, String username)
            throws Exception {

        setMockHttpSession();
        setMockIWAAuthenticationUtil();
        setMockAuthenticationContext();

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(propertyMap);
        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        when(IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class))).thenReturn(mockGSSCredential);
        when(IWAAuthenticationUtil.processToken(
                any(byte[].class), any(GSSCredential.class))).thenReturn("wso2@IS.LOCAL");

        if (StringUtils.isNotEmpty(propertyMap.get(USER_STORE_DOMAINS))) {

            initCommonMocks();
            when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(true);
            when(mockUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockUserStoreManager);
        }


        iwaFederatedAuthenticator.processAuthenticationResponse(
                mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
        Assert.assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), username);


    }

    @Test
    public void testCreateCredentialExceptions() throws Exception {

        setMockHttpSession();
        setMockIWAAuthenticationUtil();

        Map<String, String> map = new HashMap<>();
        map.put(SPN_NAME, SPN_NAME_VALUE);
        map.put(SPN_PASSWORD, SPN_PASSWORD_VALUE);
        map.put(USER_STORE_DOMAINS, USER_STORE_DOMAINS_VALUE);

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(map);
        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        when(IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class))).thenThrow(new GSSException(0));

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Authentication response processed without creating GSSCredentials");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Cannot create kerberos credentials for server"));
        }
    }

    @Test
    public void testUserDoesNotExistException() throws Exception {

        initCommonMocks();
        setMockHttpSession();
        setMockIWAAuthenticationUtil();
        setMockAuthenticationContext();

        Map<String, String> map = new HashMap<>();
        map.put(SPN_NAME, SPN_NAME_VALUE);
        map.put(SPN_PASSWORD, SPN_PASSWORD_VALUE);
        map.put(USER_STORE_DOMAINS, USER_STORE_DOMAINS_VALUE);

        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(map);
        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        when(IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class))).thenReturn(mockGSSCredential);
        when(IWAAuthenticationUtil.processToken(
                any(byte[].class), any(GSSCredential.class))).thenReturn("wso2@IS.LOCAL");

        when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(false);
        when(mockUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockUserStoreManager);

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("not found in the user store of tenant "));
        }
    }
}
