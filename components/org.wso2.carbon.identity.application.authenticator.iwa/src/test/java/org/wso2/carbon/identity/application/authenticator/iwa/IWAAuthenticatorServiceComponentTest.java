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
import org.eclipse.equinox.http.servlet.internal.HttpServiceImpl;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpContext;
import org.osgi.service.http.HttpService;
import org.osgi.service.http.NamespaceException;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.Dictionary;
import javax.servlet.Servlet;
import javax.servlet.ServletException;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.when;

public class IWAAuthenticatorServiceComponentTest extends PowerMockTestCase {

    @Mock
    Log mockedLog;

    @Mock
    HttpServiceImpl mockedHttpService;

    @Mock
    HttpContext mockedHttContext;

    @Mock
    ComponentContext mockedComponentContext;

    @Mock
    BundleContext mockedBundleContext;

    @Mock
    RealmService mockedRealmService;

    public static final String IWA_URL = "/iwa-kerberos";

    private ExtendedServiceComponent serviceComponent;
    private String loggedMessage;
    private IWAServiceDataHolder dataHolder;
    private final String[] url = new String[1];

    class ExtendedServiceComponent extends IWAAuthenticatorServiceComponent {

        public void activate(ComponentContext ctxt) {
            super.activate(ctxt);
        }

        public void deactivate(ComponentContext ctxt) {
            super.deactivate(ctxt);
        }

        public void setHttpService(HttpService httpService) {
            super.setHttpService(httpService);
        }

        public void unsetHttpService(HttpService httpService) {
            super.unsetHttpService(httpService);
        }

        public void setRealmService(RealmService realmService) {
            super.setRealmService(realmService);
        }

        public void unsetRealmService(RealmService realmService) {
            super.unsetRealmService(realmService);
        }
    }

    @BeforeTest
    public void setUp() throws Exception{

        MockitoAnnotations.initMocks(this);
        dataHolder = IWAServiceDataHolder.getInstance();
        serviceComponent = new ExtendedServiceComponent();

        setMockPrivateFields();
    }

    private void setMockPrivateFields() throws Exception {

        Class<?> clazz = IWAAuthenticatorServiceComponent.class;
        Object serviceComponentObject = clazz.newInstance();

        Field logField = serviceComponentObject.getClass().getDeclaredField("log");
        logField.setAccessible(true);
        logField.set(serviceComponentObject, mockedLog);

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

    @DataProvider(name = "provideActivateData")
    public Object[][] provideActivateData() {

        return new Object[][] {
                { new NamespaceException(null), "Error when registering the IWA servlet" },
                { new ServletException(), "Error when registering the IWA servlet" },
                { new Exception(), "IWAFederatedAuthenticator bundle activation failed" },
                { null, "IWAFederatedAuthenticator bundle is activated"}
        };
    }

    @Test (dataProvider = "provideActivateData")
    public void testActivate(final Exception thrownException, String log) throws Exception {

        when(mockedComponentContext.getBundleContext()).thenReturn(mockedBundleContext);
        dataHolder.setHttpService(mockedHttpService);

        final ApplicationAuthenticator[] authenticator = new ApplicationAuthenticator[1];

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                if (thrownException instanceof NamespaceException || thrownException instanceof ServletException) {
                    throw thrownException;
                } else {
                    url[0] = (String) invocation.getArguments()[0];
                    return null;
                }
            }
        }).when(mockedHttpService).registerServlet(anyString(), any(Servlet.class), isNull(Dictionary.class), isNull(HttpContext.class));

        doAnswer(new Answer<Object>(){
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                if (thrownException != null && (
                        !(thrownException instanceof NamespaceException) ||
                                !(thrownException instanceof ServletException))) {
                    throw thrownException;
                } else {
                    authenticator[0] = (ApplicationAuthenticator) invocation.getArguments()[1];
                    return null;
                }
            }
        }).when(mockedBundleContext).registerService(anyString(), any(ApplicationAuthenticator.class), isNull(Dictionary.class));

        serviceComponent.activate(mockedComponentContext);
        Assert.assertTrue(loggedMessage.contains(log));
        if (thrownException == null) {
            Assert.assertEquals(url[0], IWA_URL, "Servlet is not registered for iwa url");
            Assert.assertTrue(authenticator[0] instanceof IWAFederatedAuthenticator,
                    "IWAFederatedAuthenticator in not registered as a service");
        }
    }

    @Test
    public void testDeactivate() {

        serviceComponent.deactivate(mockedComponentContext);
        Assert.assertTrue(loggedMessage.contains("IWAFederatedAuthenticator bundle is deactivated"),
                "Debug message not correct");
    }

    @Test
    public void testSetHttpService() {

        serviceComponent.setHttpService(mockedHttpService);
        Assert.assertTrue(loggedMessage.contains("HTTP Service is set in the IWA SSO bundle"),
                "Debug message not correct");
    }

    @Test
    public void testUnsetHttpService() {

        serviceComponent.unsetHttpService(mockedHttpService);
        Assert.assertTrue(loggedMessage.contains("HTTP Service is unset in the IWA SSO bundle"),
                "Debug message not correct");
    }

    @Test
    public void testSetRealmService() {

        serviceComponent.setRealmService(mockedRealmService);
        Assert.assertTrue(loggedMessage.contains("Setting the Realm Service"), "Debug message not correct");
    }

    @Test
    public void testUnsetRealmService() {

        serviceComponent.unsetRealmService(mockedRealmService);
        Assert.assertTrue(loggedMessage.contains("Unsetting the Realm Service"), "Debug message not correct");
    }
}
