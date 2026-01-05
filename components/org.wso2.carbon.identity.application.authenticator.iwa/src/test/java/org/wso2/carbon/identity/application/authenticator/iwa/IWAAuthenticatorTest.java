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
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class IWAAuthenticatorTest {

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
    MultiAttributeLoginService mockMultiAttributeLoginService;

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
    ServiceURL serviceURL;

    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<IWAAuthenticationUtil> mockedIWAAuthenticationUtil;
    private MockedStatic<UserCoreUtil> mockedUserCoreUtil;
    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder;

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

    @BeforeMethod
    public void setUpMethod() {
        
        // Initialize static mocks before each test method
        // First ensure any existing mocks are cleaned up
        if (mockedIdentityUtil != null) {
            closeStaticMock(mockedIdentityUtil);
        }
        if (mockedIWAAuthenticationUtil != null) {
            closeStaticMock(mockedIWAAuthenticationUtil);
        }
        if (mockedUserCoreUtil != null) {
            closeStaticMock(mockedUserCoreUtil);
        }
        if (mockedIdentityTenantUtil != null) {
            closeStaticMock(mockedIdentityTenantUtil);
        }
        if (mockedServiceURLBuilder != null) {
            closeStaticMock(mockedServiceURLBuilder);
        }
        
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        mockedIWAAuthenticationUtil = mockStatic(IWAAuthenticationUtil.class);
        mockedUserCoreUtil = mockStatic(UserCoreUtil.class);
        mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);

        MockitoAnnotations.initMocks(this);
    }

    @AfterMethod
    public void tearDownMethod() {
        // Close static mocks gracefully
        closeStaticMock(mockedIdentityUtil);
        closeStaticMock(mockedIWAAuthenticationUtil);
        closeStaticMock(mockedUserCoreUtil);
        closeStaticMock(mockedIdentityTenantUtil);
        closeStaticMock(mockedServiceURLBuilder);
        
        mockedIdentityUtil = null;
        mockedIWAAuthenticationUtil = null;
        mockedUserCoreUtil = null;
        mockedIdentityTenantUtil = null;
        mockedServiceURLBuilder = null;
    }

    private void closeStaticMock(MockedStatic<?> mock) {
        if (mock != null) {
            try {
                mock.close();
            } catch (Exception ignored) {
                // Ignore exceptions when closing already closed mocks
            }
        }
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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.invalidateSession(any(HttpServletRequest.class)))
            .thenAnswer((Answer<Object>) invocation -> {
                HttpServletRequest key = (HttpServletRequest) invocation.getArguments()[0];
                key.getSession().invalidate();
                return null;
            });

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.getDomainAwareUserName(anyString()))
            .thenAnswer((Answer<String>) invocation -> {
                Object[] args = invocation.getArguments();
                if (args[0] != null && args.length > 0) {
                    int index = ((String) args[0]).lastIndexOf("@");
                    if (index > 0) {
                        return ((String) args[0]).substring(0, index);
                    }
                    return (String) args[0];
                }
                return null;
            });
    }

    private void setMockUserCoreUtil() {

        mockedUserCoreUtil.when(() -> UserCoreUtil.addTenantDomainToEntry(anyString(), anyString()))
            .thenAnswer((Answer<String>) invocation -> {
                Object[] args = invocation.getArguments();
                return (String) args[0] + "@" + args[1];
            });
    }

    private void initCommonMocks() throws Exception{

        dataHolder.setRealmService(mockRealmService);
        dataHolder.setMultiAttributeLoginService(mockMultiAttributeLoginService);
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);

        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockTenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getSecondaryUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn("carbon.super");

        mockedIdentityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn("PRIMARY");

        mockedIdentityUtil.when(() -> IdentityUtil.addDomainToName(anyString(), anyString()))
            .thenAnswer((Answer<String>) invocation -> {
                Object[] args = invocation.getArguments();
                if (args.length > 1 && (StringUtils.isNotEmpty((String)args[0]) &&
                        StringUtils.isNotEmpty((String)args[1]))) {
                    return (String) args[1] + "/" + (String) args[0];
                }
                return null;
            });

        mockedIdentityUtil.when(() -> IdentityUtil.isBlank(anyString())).thenReturn(false);
        mockedIdentityUtil.when(() -> IdentityUtil.isBlank(anyString())).thenAnswer((Answer<Boolean>) invocation -> {
            Object[] args = invocation.getArguments();
            return args[0] == null || ((String) args[0]).trim().isEmpty();
        });

        Class<?> clazz1 = IWALocalAuthenticator.class;
        Object localAuthObject = clazz1.newInstance();
        Field localAuthenticatorLogField = localAuthObject.getClass().getDeclaredField("log");
        localAuthenticatorLogField.setAccessible(true);

        Class<?> clazz2 = IWAFederatedAuthenticator.class;
        Object federatedAuthObject = clazz2.newInstance();
        Field federatedAuthenticatorLogField = federatedAuthObject.getClass().getDeclaredField("log");

        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(federatedAuthenticatorLogField, federatedAuthenticatorLogField.getModifiers() & ~Modifier.FINAL);

        federatedAuthenticatorLogField.setAccessible(true);
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

        mockServiceURLBuilder();
        mockedIdentityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
            .thenReturn(IWA_REDIRECT_URL);
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

        mockServiceURLBuilder();
        mockedIdentityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
            .thenReturn(IWA_REDIRECT_URL);
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
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(any(byte[].class)))
            .thenThrow(new GSSException(0));
        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with invalid kerberos token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Error while processing the GSS Token"),
                    "Exception message has changed or exception thrown from an unintended code segment.");
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
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(any(byte[].class)))
            .thenReturn(null);

        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed when authenticated user is not found in the gss token");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("Unable to extract authenticated user from Kerberos Token"),
                    "Exception message has changed or exception thrown from an unintended code segment.");
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
    public void testLocalIsExistingUserException() throws Exception {

        initCommonMocks();
        setMockHttpSession();
        setMockAuthenticationContext();
        setMockIWAAuthenticationUtil();
        setMockUserCoreUtil();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode(token));
        when(IWAAuthenticationUtil.processToken(any(byte[].class))).thenReturn("wso2@IS.LOCAL");
        when(mockUserStoreManager.isExistingUser(anyString())).thenThrow(new UserStoreException());

        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with user store exception");
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("IWALocalAuthenticator failed to find the user in the userstore"));
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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(token))
            .thenReturn("wso2@IS.LOCAL");
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString()))
            .thenReturn(-1234);

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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class)))
            .thenReturn(mockGSSCredential);
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(
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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class)))
            .thenThrow(new GSSException(0));

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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class)))
            .thenReturn(mockGSSCredential);
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(
                any(byte[].class), any(GSSCredential.class))).thenReturn("wso2@IS.LOCAL");

        when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(false);
        when(mockUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockUserStoreManager);

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
        } catch (AuthenticationFailedException e) {
            Assert.assertTrue(e.getMessage().contains("not found in any of specified userstores"),
                    "Exception message has changed or exception thrown from an unintended code segment.");
        }
    }



    @Test
    public void testIsExistingUserException() throws Exception {

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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class)))
            .thenReturn(mockGSSCredential);
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(
                any(byte[].class), any(GSSCredential.class))).thenReturn("wso2@IS.LOCAL");

        when(mockUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUser(anyString())).thenThrow(new UserStoreException());

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with User Store exception");
        } catch (AuthenticationFailedException e) {
            //expected exception
            Assert.assertTrue(e.getMessage().contains("failed to find the user"),
                    "Exception message has changed or exception thrown from an unintended code segment.");
        }
    }

    @Test
    public void testGetUserClaimsException() throws Exception {

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

        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.createCredentials(anyString(), any(char[].class)))
            .thenReturn(mockGSSCredential);
        mockedIWAAuthenticationUtil.when(() -> IWAAuthenticationUtil.processToken(
                any(byte[].class), any(GSSCredential.class))).thenReturn("wso2@IS.LOCAL");

        when(mockUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUser(anyString())).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValues(anyString(), anyString())).thenThrow(new UserStoreException());

        try {
            iwaFederatedAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with User Store exception");
        } catch (AuthenticationFailedException e) {
            //expected exception
            Assert.assertTrue(e.getMessage().contains("IWAApplicationAuthenticator failed to get user claims"));
        }
    }

    private void mockServiceURLBuilder() {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    if (x.startsWith("/")) {
                        path += x;
                    } else {
                        path += "/" + x;
                    }
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                return serviceURL;
            }
        };

        mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(builder);
    }
}
