/*   Copyright (C) 2013-2014 Computer Sciences Corporation
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

package ezbake.security.test.suite.app;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provides;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.thrift.TBase;
import org.apache.thrift.TException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TSimpleJSONProtocol;
import org.kohsuke.args4j.Option;

import ezbake.security.impl.ua.FileUAService;
import ezbake.security.impl.ua.LDAPUAService;
import ezbake.security.api.ua.UserAttributeService;
import ezbake.security.test.suite.common.Command;
import ezbake.security.ua.UAModule;
import java.util.Properties;

public class UATestCommand extends Command {

    @Option(name="-a", usage="UA search impl")
    private String uaSearchImpl;

    @Option(name="-r", usage="UA service impl")
    private String uaServiceImpl;

    @Option(name="-ldaphost", usage="ldap host")
    private String ldapHost;

    @Option(name="-ldapport", usage="ldap port")
    private int ldapPort = -1;

    @Option(name="-f", usage="user to search for", required=true)
    private String principal;

    public UATestCommand() {}

    public UATestCommand(Properties properties) {
        super(properties);
    }

    @Override
    public void runCommand() {
        try {
            updateConfig();
            UATest.getInstance(configuration).setPrincipal(principal).run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void updateConfig() {
        if (uaServiceImpl != null) {
            configuration.setProperty(UAModule.UA_SERVICE_IMPL, uaServiceImpl);
        }
        if (uaSearchImpl != null) {
            configuration.setProperty(UAModule.UA_SEARCH_IMPL, uaSearchImpl);
        }
        if (ldapHost != null) {
            configuration.setProperty(LDAPUAService.LDAP_HOST, ldapHost);
        }
        if (ldapPort != -1) {
            configuration.setProperty(LDAPUAService.LDAP_PORT, String.valueOf(ldapPort));
        }
    }

    public static class UATest {
        private UserAttributeService uaservice;
        private String principal;

        @Inject
        public UATest(Properties configs, UserAttributeService uaservice) {
            this.uaservice = uaservice;
        }
         
        public static UATest getInstance(Properties ezConfig) {
            Injector injector = Guice.createInjector(
                new UAModule(ezConfig),
                new ConfigModule(ezConfig),
                new LDAPUAService.LdapModule(ezConfig)
            );
            return injector.getInstance(UATest.class);
        }

        private UATest setPrincipal(String principal) {
            this.principal = principal;
            return this;
        }
             
        public void run() throws Exception {
            System.out.println(uaservice.getUser(principal));
        }
    }

    public static class ConfigModule extends AbstractModule {
        private Properties properties;

        public ConfigModule(Properties properties) {
            this.properties = properties;
        }

	@Override
	public void configure() {}
        @Provides
        Properties provideEzConfiguration() {
            return properties;
        }
     }
}
