/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.iwa.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.osgi.service.http.NamespaceException;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iwa.IWAConstants;
import org.wso2.carbon.identity.application.authenticator.iwa.IWAFederatedAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iwa.servlet.IWAServlet;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.Servlet;
import javax.servlet.ServletException;


/**
 * @scr.component name="identity.application.authenticator.iwa.component" immediate="true"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="MultiAttributeLoginService"
 * interface="org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService"
 * cardinality="1..1" policy="dynamic" bind="setMultiAttributeLoginService"
 * unbind="unsetMultiAttributeLoginService"
 */
public class IWAAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(IWAAuthenticatorServiceComponent.class);
    private IWAServiceDataHolder dataHolder = IWAServiceDataHolder.getInstance();

    protected void activate(ComponentContext ctxt) {
        try {
            IWAFederatedAuthenticator iwaFederatedAuthenticator = new IWAFederatedAuthenticator();

            // Register iwa servlet
            Servlet iwaServlet = new ContextPathServletAdaptor(new IWAServlet(), IWAConstants.IWA_URL);

            HttpService httpService = dataHolder.getHttpService();
            httpService.registerServlet(IWAConstants.IWA_URL, iwaServlet, null, null);

            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                                                    iwaFederatedAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("IWAFederatedAuthenticator bundle is activated");
            }
        } catch (NamespaceException | ServletException e) {
            log.error("Error when registering the IWA servlet, '"
                      + IWAConstants.IWA_URL + "' may be already in use." + e);
        } catch (Throwable e) {
            log.error("IWAFederatedAuthenticator bundle activation failed");
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("IWAFederatedAuthenticator bundle is deactivated");
        }
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the IWA SSO bundle");
        }
        dataHolder.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the IWA SSO bundle");
        }
        dataHolder.setHttpService(null);
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        dataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }
        dataHolder.setRealmService(null);
    }

    protected void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Multi Attribute Login Service");
        }
        dataHolder.setMultiAttributeLoginService(multiAttributeLoginService);
    }

    protected void unsetMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Multi Attribute Login Service");
        }
        dataHolder.setMultiAttributeLoginService(null);
    }
}
