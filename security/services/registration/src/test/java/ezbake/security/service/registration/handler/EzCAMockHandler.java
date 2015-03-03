/*   Copyright (C) 2013-2015 Computer Sciences Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

package ezbake.security.service.registration.handler;

import ezbake.base.thrift.EzBakeBaseThriftService;
import ezbake.base.thrift.EzSecurityToken;
import ezbake.ezca.EzCA;
import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;

/**
 * User: jhastings
 * Date: 1/9/15
 * Time: 12:41 PM
 */
public class EzCAMockHandler extends EzBakeBaseThriftService implements EzCA.Iface{

    private static final String cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIICvDCCAaSgAwIBAgIBAjANBgkqhkiG9w0BAQUFADAqMRUwEwYDVQQLEwxUaGVT\n" +
            "b3VyY2VEZXYxETAPBgNVBAMTCEV6QmFrZUNBMCAXDTE0MTEyNTE4MTk1MFoYDzIw\n" +
            "NDQxMTI1MTgxOTUwWjAXMRUwEwYDVQQDFAxfRXpfU2VjdXJpdHkwggEiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8cDrwjzIA5duFy4GSxdNEGH8p19oVy6ER\n" +
            "f3v95jCjNeoDZxJsDTi5Za5NRqBurIlg33vYNWc3mVviO1p1uPaZtr+Jz7gD8+76\n" +
            "aNWHhnqIL7LluvEs3lfAcZtFuFfazmOEjAZ3vL4G4iH5zNeloX1oFNwhu1zfUdh1\n" +
            "KqozOUYRhYuXr7VW0nrUAaUcWwjJdVRIfeoB9S+e386F8fMwbS/Oh5NfatVDz96d\n" +
            "TBgI/UGehbDtRyirCy9hFOjTu6c+vMqVMoKPIaVG1n1GWFqap9JMDBjiKRrzSOZv\n" +
            "bxtkJDxM4dkb//ATkp6cV4g7VLo9c6DpOLj8AzKxL8AbOtTodIlZAgMBAAEwDQYJ\n" +
            "KoZIhvcNAQEFBQADggEBAIrpIDo8Ob+svzyF7xCVwLH7C5afK8A+8n8tI78UheTe\n" +
            "bR7SBrwP/0wK7Xq+uKHkAKKmyMlree95gCYJyHf1sJOFDGt1TEvxuG7oykkgHWfY\n" +
            "TimHoDvvp7QwJTlSkEDZpiTAn94S6Y9LYAygvvK9guDNFqO1DoU0aTeNElS6rq+w\n" +
            "3esV+iGBPyzjmATPhMuZhm6wOiu8QEjyKRBuOqaE54GpRY4GvSIdr1lzamKUoUl/\n" +
            "EixLzFBu11hkqIaM81/wvtWszmntTHt3uVhc39azZqWIknRUaocrRw2/1sUOOE5t\n" +
            "6eGyUd1V2s6w+yCezGhRmKzjTVmuu575yB3Gse7/nGg=\n" +
            "-----END CERTIFICATE-----\n";

    @Override
    public TProcessor getThriftProcessor() {
        return new EzCA.Processor<>(this);
    }

    @Override
    public String csr(EzSecurityToken token, String csr) throws TException {
        return cert;
    }
}
