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

package ezbake.security.impl.ua;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provides;

import ezbake.security.api.ua.Community;
import ezbake.security.api.ua.User;
import ezbake.security.api.ua.UserAttributeService;
import ezbake.security.api.ua.UserNotFoundException;
import ezbake.security.service.sync.NoopRedisCache;
import ezbake.security.service.sync.EzSecurityRedisCache;

public class LDAPUAService implements UserAttributeService {
    public static final String LDAP_HOST = "ezbake.uaservice.ldap.host";
    public static final String DEFAULT_LDAP_HOST = "localhost";

    public static final String LDAP_PORT = "ezbake.uaservice.ldap.port";
    public static final int DEFAULT_LDAP_PORT = 389;
	
    public static class LdapModule extends AbstractModule {
	private Properties ezConfiguration;

	public LdapModule(Properties ezConfiguration) {
	    this.ezConfiguration = ezConfiguration;
	}
		
	@Override
	protected void configure() {}
		
	@Provides
	LdapConnection provideLdapConnection() {
	    logger.info("connecting to ldap at {}:{}", getHost(), getPort());
	    LdapConnection connection = new LdapNetworkConnection(getHost(), getPort(), false);
	    return connection;
	}

	private int getPort() {
	    return Integer.valueOf(ezConfiguration.getProperty(LDAP_PORT, String.valueOf(DEFAULT_LDAP_PORT)));
	}

	private String getHost() {
	    return ezConfiguration.getProperty(LDAP_HOST, DEFAULT_LDAP_HOST);
	}
    }
	
    private static final Logger logger = LoggerFactory.getLogger(LDAPUAService.class);
    protected final LdapConnection connection;
    private final NoopRedisCache cache;

    @Inject
    public LDAPUAService(Properties ezConfiguration, LdapConnection connection) {
	cache = new NoopRedisCache();
	this.connection = connection;
    }
    
    @Override
    public boolean assertUserStrictFailure(String principal) {
        return assertUser(principal);
    }

    @Override
    public boolean assertUser(String principal) {
	try {
	    getUserOrThrow(principal);
	} catch (UserNotFoundException e) {
	    logger.debug("couldn't find user {}", principal, e);
	    return false;
	}
	return true;
    }

    @Override
    public User getUser(String principal) throws UserNotFoundException {
        return getUserOrThrow(principal);
    }

    @Override
    public User getUserProfile(String principal) throws UserNotFoundException {
        User u = getUserOrThrow(principal);
        u.setCommunities(null);
        u.setAuthorizations(null);
        u.setProjects(null);
        return u;
    }

    @Override
    public Map<String, List<String>> getUserGroups(String principal) throws UserNotFoundException {
        User u = getUserOrThrow(principal);
        return u.getProjects();
    }

    @Override
    public EzSecurityRedisCache getCache() {
        return this.cache;
    }

    //--------------------------------------------------------------------------------

    private User getUserOrThrow(String principal) throws UserNotFoundException {
	try {
	    maybeBind();
	    Dn userDnVal = userDn(principal);
	    logger.debug("looking up user with dn {}", userDnVal);
	    Entry userEntry = connection.lookup(userDnVal);
	    if (userEntry == null) {
		throw new UserNotFoundException("LDAP response for " + userDnVal + " empty");
	    }
	    User user = userFromEntry(userEntry);
	    user.setPrincipal(principal);
	    return user;
	} catch (LdapException e) {
	    throw new UserNotFoundException("Couldn't find " + principal, e);
	}
    }

    //--------------------------------------------------------------------------------

    public void addToList(Collection<String> lst, Attribute attr) throws LdapInvalidAttributeValueException {
	logger.trace("adding {} to {}", attr, lst);
	while(attr.size() > 0) {
	    String val = attr.getString();
	    lst.add(val);
	    logger.trace("{}: {}", val, lst);
	    attr.remove(val);
	}
    }
    
    private User userFromEntry(Entry userEntry) throws LdapException {
	User user = new User();
	int emailCount = 0;
	for (Attribute attr : userEntry.getAttributes()) {
	    logger.trace("considering attribute {}", attr);
	    switch (attr.getUpId()) {
	    case "givenName": user.setFirstName(attr.getString()); break;
	    case "sn": user.setSurName(attr.getString()); break;
	    case "uid": user.setUid(attr.getString()); break;
	    case "ou": user.setCompany(attr.getString()); user.setOrganization(attr.getString()); user.getAuthorizations().setOrganization(attr.getString()); break;
	    case "telephoneNumber": user.setPhoneNumber(attr.getString()); break;
	    case "mail": user.getEmails().put(String.valueOf(emailCount++), attr.getString()); break;
	    case "ezAuthLevel": user.getAuthorizations().setLevel(attr.getString()); break;
	    case "ezGovernmentAuth": addToList(user.getAuthorizations().getAuths(), attr.clone()); break;
	    case "ezCommunityAuth": addToList(user.getAuthorizations().getCommunityAuthorizations(), attr.clone()); break;
	    case "ezCountryOfCitizenship": user.getAuthorizations().setCitizenship(attr.getString()); break;
	    case "ezGroupAndProject": addToProjects(user.getProjects(), attr.clone()); break;
	    case "ezCommunityName": user.getCommunities().addAll(communitiesFromAttr(attr.clone())); break;
	    case "ezAffiliation": addToList(user.getAffiliations(), attr.clone()); break;
	    };
	}

	user.setName(user.getFirstName() + " " + user.getSurName());

	return user;
    }

    //--------------------------------------------------------------------------------

    private List<Community> communitiesFromAttr(Attribute attr) throws LdapException {
	List<Community> communities = new ArrayList<>();
	logger.trace("getting communities: {}", attr);
	while(attr.size() > 0) {
	    String val = attr.getString();
	    communities.add(communityFromName(val));
	    logger.trace("{}: {}", val, communities);
	    attr.remove(val);
	}
	return communities;
    }

    private Community communityFromName(String name) throws LdapException {
	Community result = new Community();
	Dn communityDnVal = communityDn(name);
	logger.trace("looking up community with dn {}", communityDnVal);
	Entry communityEntry = connection.lookup(communityDnVal);
	for (Attribute attr : communityEntry.getAttributes()) {
	    logger.trace("considering attribute {}", attr);
	    switch (attr.getUpId()) {
	    case "ezCommunityName": result.setCommunityName(attr.getString()); break;
	    case "ezCommunityType": result.setCommunityType(attr.getString()); break;
	    case "ou": result.setOrganization(attr.getString()); break;
	    case "ezTopic": addToList(result.getTopics(), attr.clone()); break;
	    case "ezRegion": addToList(result.getRegions(), attr.clone()); break;
	    case "ezGroupMemberOf": addToList(result.getGroups(), attr.clone()); break;
	    case "ezCommunityFlag": result.getFlags().put(flagFrom(attr.getString()),boolFrom(attr.getString())); break;
	    }
	}
	return result;
    }

    private List<String> groupsFromType(String type) throws LdapException {
	List<String> result = new ArrayList<>();
	Dn groupTypeDnVal = groupTypeDn(type);
	logger.trace("looking up group type with dn {}", groupTypeDnVal);
	Entry typeEntry = connection.lookup(groupTypeDnVal);
	for (Attribute attr : typeEntry.getAttributes()) {
	    logger.trace("considering attribute {}", attr);
	    switch (attr.getUpId()) {
	    case "ezGroupMemberOf": addToList(result, attr.clone()); break;
	    }
	}
	return result;
    }

    //--------------------------------------------------------------------------------
    
    private void addToProjects(Map<String,List<String>> groups, Attribute attr) throws LdapInvalidAttributeValueException {
	logger.trace("adding {} to {}", attr, groups);
	while(attr.size() > 0) {
	    String groupAndProject = attr.getString();
	    String groupName = groupFrom(groupAndProject);
	    String projectName = projectFrom(groupAndProject);
	    logger.trace("decomposed {} to {} -> {}. adding to {}",
			 groupAndProject, groupName, projectName, groups);
	    List<String> projects = groups.get(groupName);
	    if (projects == null) {
		projects = new ArrayList<>();
		groups.put(groupName, projects);
	    }
	    projects.add(projectName);
	    attr.remove(groupAndProject);
	}
    }

    //--------------------------------------------------------------------------------

    private Boolean boolFrom(String val) {
	return new Boolean(val.split("=")[1]);
    }

    private String flagFrom(String val) {
	return val.split("=")[0];
    }

    private String groupFrom(String groupAndProject) {
	return groupAndProject.split(":")[0];
    }

    private String projectFrom(String groupAndProject) {
	return groupAndProject.split(":")[1];
    }

    //--------------------------------------------------------------------------------

    private Dn communityDn(String name) throws LdapInvalidDnException {
	return baseDn().add(new Rdn("cn","ezbake")).add(new Rdn("cn","communities")).add(new Rdn("cn", name));
    }

    private Dn groupTypeDn(String type) throws LdapInvalidDnException {
	return baseDn().add(new Rdn("cn","ezbake")).add(new Rdn("cn","grouptypes")).add(new Rdn("cn", type));
    }

    private Dn userDn(String principal) throws LdapInvalidDnException {
	return new Dn(principal.split(","));
    }

    //--------------------------------------------------------------------------------

    protected Dn baseDn() throws LdapInvalidDnException {
	// This simply takes the domain components of the hostname and
	// infers the LDAP layout from it. It's presumptuous but
	// flexible enough to work with the SRP as it's
	// configured. I'm going to leave this protected to allow base
	// classes to do it more flexibly if needed.

	String hostname = null;
	try {
	    hostname = InetAddress.getLocalHost().getHostName();
	} catch (UnknownHostException ex) {
	    String msg = "localhost unknown. highly unexpected.";
	    logger.error(msg, ex);
	    throw new RuntimeException(msg, ex);
	}

	String[] hostElements = hostname.split("\\.");
	logger.trace("got {} components for hostname {}", hostElements.length, hostname);
	Dn result = new Dn();
	// domain elements (all except first) in reverse order
	for (int i = hostElements.length - 1; i >= 1; i--) {
	    String elem = hostElements[i];
	    logger.trace("adding element {}", elem);
	    result = result.add(new Rdn("dc", elem));
	}
	logger.trace("baseDn: {}", result);
	return result;
    }

    //--------------------------------------------------------------------------------

    private void maybeBind() throws LdapException {
	if (!connection.isAuthenticated()) {
	    logger.info("binding to ldap. This should only happen once.");
	    connection.bind();
	}
    }

}
