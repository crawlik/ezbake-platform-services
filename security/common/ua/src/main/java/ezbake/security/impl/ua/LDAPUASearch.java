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

import java.util.Properties;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;

import ezbake.security.api.ua.SearchResult;
import ezbake.security.api.ua.UserSearchService;

public class LDAPUASearch extends LDAPUAService implements UserSearchService {
    private static final Logger logger = LoggerFactory.getLogger(LDAPUASearch.class);

    @Inject
    public LDAPUASearch(Properties ezProperties, LdapConnection connection) {
    	super(ezProperties, connection);
    }

    @Override
    public SearchResult search(String first, String last) {
	try {
	    SearchRequest req = new SearchRequestImpl()
		.setBase(baseDn().add(new Rdn("cn","accounts")).add(new Rdn("cn","users")))
		.addAttributes("(&(givenName=" + first + ")(sn=" + last + "))");
	    return doSearch(req);
	} catch (LdapException e) {
	    logger.warn("failed search for {} {}", first, last, e);
	    return new SearchResult();
	}
    }

    @Override
    public SearchResult listGroupMembers(String groupName, String projectName) {
	try {
	    SearchRequest req = new SearchRequestImpl()
		.setBase(baseDn().add(new Rdn("cn","accounts")).add(new Rdn("cn","users")))
		.addAttributes("ezGroupAndProject=" + groupName + ":" + projectName);
	    return doSearch(req);
	} catch (LdapException e) {
	    logger.warn("failed search for {} {}", groupName, projectName, e);
	    return new SearchResult();
	}
    }

    private SearchResult doSearch(SearchRequest req) throws LdapException {
	try {
	    SearchResult result = new SearchResult();
	    SearchCursor cursor = connection.search(req);
	    logger.debug("search requst: {}", req);
	    while (cursor.next()) {
		Entry entry = cursor.getEntry();
		logger.trace("entry {} matched search {}", entry, req);
		for (Attribute attr : entry.getAttributes()) {
		    logger.trace("considering attribute {}", attr);
		    switch (attr.getUpId()) {
		    case "uid": result.getData().add(attr.get().toString()); break;
		    }
		}
	    }
	    return result;
	} catch (CursorException e) {
	    throw new LdapException(e);
	}
    }
}
