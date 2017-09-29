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

import org.apache.commons.logging.Log;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.iwa.servlet.IWAServlet;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
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

@PrepareForTest ( {IdentityUtil.class})
public class IWAServletTest extends PowerMockTestCase {

    private static final String NTLM_PROLOG = "TlRMTVNT";
    private static final String COMMON_AUTH_URL = "https://localhost:9443/commonauth";
    private static final String REDIRECT_URL = "https://localhost:9443/commonauth?state=iwaAuthenticatorState&iwaauth=1";

    @Mock
    HttpServletRequest mockedHttpRequest;

    @Mock
    HttpServletResponse mockedHttpResponse;

    @Mock
    HttpSession mockedHttpSession;

    @Mock
    Log mockedLog;

    private ExtendedIWAServlet iwaServlet;
    private String loggedMessage;

    class ExtendedIWAServlet extends IWAServlet {

        public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
            super.doGet(request, response);
        }
    }

    @BeforeTest
    public void setUp() {

        iwaServlet = new ExtendedIWAServlet();
    }

    @DataProvider(name = "provideHttpRequestData")
    public Object[][] provideHttpRequestData() {

        MockitoAnnotations.initMocks(this);
        return new Object[][] {
                { null, "Negotiate myAuthorozationToken", mockedHttpSession, "idp.local.com", "idp.remote.com",
                        IWAConstants.IWA_PARAM_STATE + " parameter is null."},
                { "iwaAuthenticatorState", "Negotiate myAuthorozationToken", mockedHttpSession, "idp.local.com",
                        "idp.local.com", "Cannot handle IWA authentication request from the same host as the KDC"},
                { "iwaAuthenticatorState", "Negotiate myAuthorozationToken", null, "idp.local.com", "idp.remote.com",
                        "Expected HttpSession"},
                { "iwaAuthenticatorState", "myAuthorozationToken", mockedHttpSession, "idp.local.com", "idp.remote.com",
                        IWAConstants.NEGOTIATE_HEADER + " header not found"},
                { "iwaAuthenticatorState", null, mockedHttpSession, "idp.local.com", "idp.remote.com",
                        "Sending Unauthorized response."},
                { "iwaAuthenticatorState", "Negotiate TlRMTVNTToken", mockedHttpSession, "idp.local.com",
                        "idp.remote.com", "NTLM token found."},
                { "iwaAuthenticatorState", "Negotiate myAuthorozationToken", mockedHttpSession, "idp.local.com",
                        "idp.remote.com", ""},
        };
    }

    @Test( dataProvider = "provideHttpRequestData")
    public void testDoPost(String state, String authorizationHeader, Object session, String localAddress,
                           String remoteAddress, String message) throws Exception{

        setMockedLog();
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(COMMON_AUTH_URL);

        HttpSession httpSession = (HttpSession) session;

        when(mockedHttpRequest.getParameter(anyString())).thenReturn(state);
        when(mockedHttpRequest.getHeader(anyString())).thenReturn(authorizationHeader);
        when(mockedHttpRequest.getSession(anyBoolean())).thenReturn(httpSession);
        when(mockedHttpRequest.getLocalAddr()).thenReturn(localAddress);
        when(mockedHttpRequest.getRemoteAddr()).thenReturn(remoteAddress);

        final String[] redirectUrl = new String[1];
        final int[] statusCode = new int[1];
        final Map<String,Object> attributes = new HashMap<>();

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                redirectUrl[0] = key;
                return null;
            }
        }).when(mockedHttpResponse).sendRedirect(anyString());
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                int key = (int) invocation.getArguments()[0];
                statusCode[0] = key;
                return null;
            }
        }).when(mockedHttpResponse).setStatus(anyInt());

        Mockito.doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                String key = (String) invocation.getArguments()[0];
                Object value = invocation.getArguments()[1];
                attributes.put(key, value);
                return null;
            }
        }).when(mockedHttpSession).setAttribute(anyString(), any());

        try {
            iwaServlet.get(mockedHttpRequest, mockedHttpResponse);

            if (authorizationHeader == null) {
                Assert.assertEquals(statusCode[0], 401);
            } else {
                Assert.assertEquals(redirectUrl[0], REDIRECT_URL);
            }

            if (loggedMessage != null) {
                Assert.assertTrue(loggedMessage.contains(message));
            }

            loggedMessage = null;
        } catch (ServletException e) {
            Assert.assertTrue(e.getMessage().contains(message), "Expected error message not found");
        } catch (RuntimeException e) {
            Assert.assertTrue(e instanceof IllegalArgumentException, "Unexpected exception thrown");
            Assert.assertTrue(e.getMessage().contains(message),"Expected error message not found");
        }
    }

    private void setMockedLog() throws Exception {

        Class<?> clazz = IWAServlet.class;
        Object iwaServletObject = clazz.newInstance();

        Field logField = iwaServletObject.getClass().getDeclaredField("log");
        logField.setAccessible(true);
        logField.set(iwaServletObject, mockedLog);

        when(mockedLog.isDebugEnabled()).thenReturn(true);
        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                loggedMessage = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockedLog).error(anyString());

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                loggedMessage = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockedLog).debug(anyString());
    }
}

