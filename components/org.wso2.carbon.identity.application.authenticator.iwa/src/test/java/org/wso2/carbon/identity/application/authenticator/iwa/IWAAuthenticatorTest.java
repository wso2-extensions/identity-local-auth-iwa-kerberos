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
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({IdentityUtil.class, IWAAuthenticationUtil.class})
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

    private static final String SPN_NAME = "SPNName";
    private static final String USER_STORE_DOMAINS = "UserStoreDomains";
    private static final String SPN_PASSWORD = "SPNPassword";

    @Mock
    HttpServletRequest mockHttpRequest;

    @Mock
    HttpServletResponse mockHttpResponse;

    @Mock
    HttpSession mockSession;

    @Mock
    AuthenticationContext mockAuthenticationContext;

    private AbstractIWAAuthenticator iwaLocalAuthenticator;
    private AbstractIWAAuthenticator iwaFederatedAuthenticator;
    private List<Property> federatedAuthenticatorConfigs;

    @BeforeTest
    public void setUp() {

        iwaLocalAuthenticator = new IWALocalAuthenticator();
        iwaFederatedAuthenticator = new IWAFederatedAuthenticator();
        federatedAuthenticatorConfigs = new ArrayList<>();

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
    public void testProcessAuthenticationResponse() throws Exception{

        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockSession);
        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed without kerberos token");
        } catch (AuthenticationFailedException e) {
            //expected exception
        }

        setMockHttpSession();

        mockSession.setAttribute(IWAConstants.KERBEROS_TOKEN, Base64.encode("invalidKerberosTokenString".getBytes()));
        when(mockHttpRequest.isRequestedSessionIdValid()).thenReturn(true);
        when(mockHttpRequest.getSession()).thenReturn(mockSession);
        try {
            iwaLocalAuthenticator.processAuthenticationResponse(
                    mockHttpRequest, mockHttpResponse, mockAuthenticationContext);
            Assert.fail("Response processed with invalid kerberos token");
        } catch (AuthenticationFailedException e) {
            //expected exception
        }

        //todo testing for valid token
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
}
