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

import org.apache.commons.lang3.reflect.FieldUtils;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.osgi.service.http.HttpService;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.iwa.internal.IWAServiceDataHolder;
import org.wso2.carbon.user.core.service.RealmService;

public class IWAServiceDataHolderTest {

    @Mock
    HttpService mockedHttpService;

    @Mock
    RealmService mockedRealmService;

    private  IWAServiceDataHolder dataHolder;

    @BeforeTest
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        dataHolder = IWAServiceDataHolder.getInstance();
    }

    @Test
    public void testSetHttpService() throws Exception {

        dataHolder.setHttpService(mockedHttpService);
        Assert.assertEquals(FieldUtils.readField(dataHolder, "httpService", true), mockedHttpService);
    }

    @Test
    public void testGetHttpService() {

        dataHolder.setHttpService(mockedHttpService);
        Assert.assertEquals(dataHolder.getHttpService(), mockedHttpService);
    }

    @Test (expectedExceptions = RuntimeException.class)
    public void testGetHttpServiceException() {

        dataHolder.setHttpService(null);
        dataHolder.getHttpService();
    }

    @Test
    public void testSetRealmService() throws Exception {

        dataHolder.setRealmService(mockedRealmService);
        Assert.assertEquals(FieldUtils.readField(dataHolder, "realmService", true), mockedRealmService);
    }

    @Test
    public void testGetRealmService() {

        dataHolder.setRealmService(mockedRealmService);
        Assert.assertEquals(dataHolder.getRealmService(), mockedRealmService);
    }

    @Test (expectedExceptions = RuntimeException.class)
    public void testGetRealmServiceException() {

        dataHolder.setRealmService(null);
        dataHolder.getRealmService();
    }


}
