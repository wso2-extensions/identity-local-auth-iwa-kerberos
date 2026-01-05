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

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.user.core.claim.Claim;
import sun.security.jgss.GSSManagerImpl;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

public class IWAAuthenticationUtilTest {

    private static final String USERNAME_ATTRIBUTE_NAME = "username";
    private static final String JAAS_CONFIG_PATH = "src/test/resources/home/repository/conf/identity/jaas.conf";
    private static final String KERBEROS_CONFIG_PATH = "src/test/resources/home/repository/conf/identity/krb5.conf";
    private static final String TOKEN_PATH = "src/test/resources/home/repository/conf/identity/token";

    private String fullQualifiedUsername;
    private String password;
    private char[] passwordArray;

    @Mock
    HttpServletRequest mockRequest;

    @Mock
    HttpSession mockSession;

    @Mock
    GSSManagerImpl mockedGSSManager;

    @Mock
    GSSContext mockedGSSContext;

    @Mock
    GSSName mockedGSSName;

    private GSSCredential gssCredentials;

    private byte[] token;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        fullQualifiedUsername = "wso2@IS.LOCAL";
        password = "Boow123#";
        passwordArray = password.toCharArray();
        token = Files.readAllBytes(Paths.get(TOKEN_PATH));

        System.setProperty("carbon.home", new File("src/test/resources/home").getAbsolutePath());
        setMockHttpSession();
    }

    @AfterTest
    public void cleanUp() throws Exception {
        unSetMockedGSSManager();
    }

    public void setMockHttpSession() {

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

    public void setMockedGSSManager() throws Exception {

        Field gssManagerField = IWAAuthenticationUtil.class.getDeclaredField("gssManager");
        gssManagerField.setAccessible(true);
        gssManagerField.set(null, mockedGSSManager);

        when(mockedGSSManager.createContext(nullable(GSSCredential.class))).thenReturn(mockedGSSContext);
    }

    public void unSetMockedGSSManager() throws Exception {
        Field gssManagerField = IWAAuthenticationUtil.class.getDeclaredField("gssManager");
        gssManagerField.setAccessible(true);
        gssManagerField.set(null, GSSManager.getInstance());
    }

    @Test
    public void testGetDomainAwareUserName() {

        String username = IWAAuthenticationUtil.getDomainAwareUserName(fullQualifiedUsername);
        Assert.assertEquals(username, "wso2");
    }

    @Test (expectedExceptions = {IllegalArgumentException.class})
    public void testGetDomainAwareUserNameException() {

        IWAAuthenticationUtil.getDomainAwareUserName("");
    }

    @Test
    public void testGetRealmFromUserName() {

        String domain = IWAAuthenticationUtil.extractRealmFromUserName(fullQualifiedUsername);
        Assert.assertEquals(domain, "IS.LOCAL");
    }

    @Test (expectedExceptions = {IllegalArgumentException.class})
    public void testGetRealmFromUserNameException() {

        IWAAuthenticationUtil.extractRealmFromUserName("");
    }

    @DataProvider(name = "provideClaims")
    public Object[][] provideData() {

        Claim[] claimsArray1;
        Claim[] claimsArray2;
        String claimUri;
        String claimValue;

        Claim claim1 = new Claim();
        claimUri = "testLocalClaimURI1";
        claimValue = "value1";
        claim1.setClaimUri(claimUri);
        claim1.setValue(claimValue);

        Claim claim2 = new Claim();
        claimUri = "testLocalClaimURI2";
        claimValue = "value2";
        claim2.setClaimUri(claimUri);
        claim2.setValue(claimValue);

        Claim claim3 = new Claim();
        claimUri = "testLocalClaimURI3";
        claimValue = null;
        claim3.setClaimUri(claimUri);
        claim3.setValue(claimValue);

        claimsArray1 = new Claim[]{claim1, claim2};
        claimsArray2 = new Claim[]{claim1, claim2, claim3};

        return new Object[][] {
                { claimsArray1, 2 },
                { claimsArray2, 2 }
        };
    }

    @Test(dataProvider = "provideClaims")
    public void testBuildClaimMappingMap(Claim[] claims, int mapSize) {
        Assert.assertEquals(IWAAuthenticationUtil.buildClaimMappingMap(claims).size(), mapSize);
    }

    @Test
    public void testConfiguration() {

        IWAAuthenticationUtil.setConfigFilePaths();
        String jaasPath = System.getProperty(IWAConstants.JAAS_CONFIG_PROPERTY);
        String krb5Path = System.getProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY);

        Assert.assertNotNull(jaasPath, "JAAS config property not set");
        Assert.assertNotNull(krb5Path, "Kerberos config property not set");
    }

    @Test
    public void testConfigurationWithSystemProperties() {

        System.setProperty(IWAConstants.JAAS_CONFIG_PROPERTY, JAAS_CONFIG_PATH);
        System.setProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY, KERBEROS_CONFIG_PATH);

        IWAAuthenticationUtil.setConfigFilePaths();
        Assert.assertNotNull(System.getProperty(IWAConstants.JAAS_CONFIG_PROPERTY), "JAAS config property not set");
        Assert.assertNotNull(System.getProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY), "Kerberos config property not set");
    }

    @Test
    public void testInvalidateSession() {

        when(mockRequest.isRequestedSessionIdValid()).thenReturn(true);
        when(mockRequest.getSession()).thenReturn(mockSession);
        mockSession.setAttribute(USERNAME_ATTRIBUTE_NAME, fullQualifiedUsername);

        IWAAuthenticationUtil.invalidateSession(mockRequest);
        Assert.assertNull(mockSession.getAttribute(USERNAME_ATTRIBUTE_NAME));
    }

    @Test
    public void testInvalidateInvalidatedSession() {

        when(mockRequest.isRequestedSessionIdValid()).thenReturn(false);
        when(mockRequest.getSession()).thenReturn(mockSession);
        mockSession.setAttribute(USERNAME_ATTRIBUTE_NAME, fullQualifiedUsername);

        IWAAuthenticationUtil.invalidateSession(mockRequest);
        Assert.assertNotNull(mockSession.getAttribute(USERNAME_ATTRIBUTE_NAME));
    }

    @Test
    public void testCreateCredentials() throws Exception{

        gssCredentials = IWAAuthenticationUtil.createCredentials(fullQualifiedUsername, passwordArray);
        Assert.assertEquals(gssCredentials.getRemainingLifetime(), GSSCredential.INDEFINITE_LIFETIME);
        Assert.assertEquals(gssCredentials.getUsage(), 2);

    }

    @DataProvider (name = "provideContextEstablishedData")
    public Object[][] provideContextEstablishedData() {

        return new Object[][] {
                { true, "wso2@IS.LOCAL" },
                { false, "Unable to decrypt the kerberos ticket as context was not established" }
        };
    }

    @Test (dataProvider = "provideContextEstablishedData")
    public void testProcessTokenError(boolean isEstablished, String log) throws Exception {

        setMockedGSSManager();
        when(mockedGSSContext.isEstablished()).thenReturn(isEstablished);
        when(mockedGSSContext.getSrcName()).thenReturn(mockedGSSName);
        when(mockedGSSContext.getTargName()).thenReturn(mockedGSSName);
        when(mockedGSSName.toString()).thenReturn("wso2@IS.LOCAL");
        String loginUsername = IWAAuthenticationUtil.processToken(token);
        if (isEstablished) {
            Assert.assertEquals(loginUsername, "wso2@IS.LOCAL");
        }
    }

}
