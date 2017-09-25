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

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.when;

public class IWALocalAuthenticatorTest {

    public static final String IWA_AUTHENTICATOR_NAME = "IWALocalAuthenticator";
    public static final String IWA_AUTHENTICATOR_FRIENDLY_NAME = "iwa-local";

    @Mock
    HttpServletRequest mockHttpRequest;

    @Mock
    HttpSession mockSession;

    AbstractIWAAuthenticator iwaLocalAuthenticator;

    @BeforeTest
    public void setUp() {

        MockitoAnnotations.initMocks(this);
        iwaLocalAuthenticator = new IWALocalAuthenticator();
    }

    @Test
    public void testCanHandle() {

        when(mockHttpRequest.getParameter(IWAConstants.IWA_PROCESSED)).thenReturn("1");
        Assert.assertTrue(iwaLocalAuthenticator.canHandle(mockHttpRequest), "CanHandle test failed");
    }

    @Test
    public void testCanHandleFail() {

        when(mockHttpRequest.getParameter(IWAConstants.IWA_PROCESSED)).thenReturn(null);
        Assert.assertFalse(iwaLocalAuthenticator.canHandle(mockHttpRequest));
    }

    @Test
    public void testGetAuthenticatorName() {

        String authenticatorName = iwaLocalAuthenticator.getName();
        Assert.assertEquals(authenticatorName, IWA_AUTHENTICATOR_NAME);
    }

    @Test
    public void testGetAuthenticatorFriendlyName() {

        String authenticatorFriendlyName = iwaLocalAuthenticator.getFriendlyName();
        Assert.assertEquals(authenticatorFriendlyName, IWA_AUTHENTICATOR_FRIENDLY_NAME);
    }
}
