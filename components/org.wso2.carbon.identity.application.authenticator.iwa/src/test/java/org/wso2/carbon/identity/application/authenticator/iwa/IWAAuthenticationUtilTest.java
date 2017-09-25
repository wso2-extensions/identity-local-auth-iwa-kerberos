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

import org.ietf.jgss.GSSCredential;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.user.core.claim.Claim;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.when;

public class IWAAuthenticationUtilTest {

    private static final String USERNAME_ATTRIBUTE_NAME = "username";
    private String fullQualifiedUsername;
    private String password;
    private char[] passwordArray;

    @Mock
    HttpServletRequest mockRequest;

    @Mock
    HttpSession mockSession;

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        fullQualifiedUsername = "testUser@KERBEROS.DOMAIN";
        password = "password";
        passwordArray = password.toCharArray();

        System.setProperty("carbon.home", new File("src/test/resources/home").getAbsolutePath());
        mockHttpSession();
    }

    public void mockHttpSession() {
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

    @Test
    public void testGetDomainAwareUserName() {

        String username = IWAAuthenticationUtil.getDomainAwareUserName(fullQualifiedUsername);
        Assert.assertEquals(username, "testUser");
    }

    @Test (expectedExceptions = {IllegalArgumentException.class})
    public void testGetDomainAwareUserNameException() {

        IWAAuthenticationUtil.getDomainAwareUserName("");
    }

    @Test
    public void testGetRealmFromUserName() {

        String domain = IWAAuthenticationUtil.extractRealmFromUserName(fullQualifiedUsername);
        Assert.assertEquals(domain, "KERBEROS.DOMAIN");
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
        Assert.assertNotNull(System.getProperty(IWAConstants.JAAS_CONFIG_PROPERTY), "JAAS config property not set");
        Assert.assertNotNull(System.getProperty(IWAConstants.KERBEROS_CONFIG_PROPERTY), "Kerberos config property not set");
    }

    @Test
    public void testInvalidateSession() {

        mockSession.setAttribute(USERNAME_ATTRIBUTE_NAME, fullQualifiedUsername);
        when(mockRequest.isRequestedSessionIdValid()).thenReturn(true);
        when(mockRequest.getSession()).thenReturn(mockSession);

        IWAAuthenticationUtil.invalidateSession(mockRequest);
        Assert.assertNull(mockSession.getAttribute(USERNAME_ATTRIBUTE_NAME));
    }

    @Test
    public void testCreateCredentials() throws Exception{

        GSSCredential gssCredential = IWAAuthenticationUtil.createCredentials(fullQualifiedUsername, passwordArray);
        Assert.assertEquals(gssCredential.getRemainingLifetime(), GSSCredential.INDEFINITE_LIFETIME);
        Assert.assertEquals(gssCredential.ACCEPT_ONLY, 2);

    }

}
