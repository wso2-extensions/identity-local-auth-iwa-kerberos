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
package org.wso2.carbon.identity.application.authenticator.iwa.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * IWAService DataHolder
 */
public class IWAServiceDataHolder {

    private HttpService httpService;
    private RealmService realmService;
    private MultiAttributeLoginService multiAttributeLoginService;
    private static final Log log = LogFactory.getLog(IWAServiceDataHolder.class);

    private static IWAServiceDataHolder instance = new IWAServiceDataHolder();

    private IWAServiceDataHolder() {
    }

    public static IWAServiceDataHolder getInstance() {
        return instance;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RealmService getRealmService() {
        if (realmService == null) {
            throw new RuntimeException("Realm Service cannot be null. Component has not initialized properly.");
        }
        return realmService;
    }

    public HttpService getHttpService() {
        if (httpService == null) {
            throw new RuntimeException("HTTP Service cannot be null. Component has not initialized properly.");
        }
        return httpService;
    }

    public void setHttpService(HttpService httpService) {
        this.httpService = httpService;
    }

    public MultiAttributeLoginService getMultiAttributeLoginService() {

        return multiAttributeLoginService;
    }

    public void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        this.multiAttributeLoginService = multiAttributeLoginService;
    }
}
