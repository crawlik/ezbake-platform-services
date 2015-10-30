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

package ezbake.groups.cli.commands.user;

import ezbake.groups.cli.commands.CLIException;

import ezbake.configuration.EzConfigurationLoaderException;
import ezbake.groups.graph.EzGroupsGraphImpl;
import ezbake.groups.graph.exception.InvalidVertexTypeException;
import ezbake.groups.graph.exception.UserNotFoundException;
import ezbake.groups.graph.frames.vertex.User;
import ezbake.groups.graph.frames.vertex.BaseVertex;
import ezbake.groups.graph.exception.IndexUnavailableException;
import ezbake.groups.graph.exception.InvalidGroupNameException;
import ezbake.groups.graph.exception.InvalidVertexTypeException;
import ezbake.groups.graph.exception.UserNotFoundException;
import ezbake.groups.graph.exception.VertexExistsException;
import ezbake.groups.graph.exception.VertexNotFoundException;
import ezbake.groups.graph.exception.AccessDeniedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Properties;
import java.lang.RuntimeException;

import org.kohsuke.args4j.Option;

/**
 * User: alex vinnik Date: 10/29/15
 */
public class CreateUserCommand extends UserCommand {

	@Option(name = "-n", aliases = "--user-name", required = true)
	private String userName;

	public CreateUserCommand() {
	}

	public CreateUserCommand(String userName, Properties configuration) {
		super(configuration);
		this.userName = userName;
	}

	@Override
	public void runCommand() throws EzConfigurationLoaderException, CLIException {
		EzGroupsGraphImpl graph = getGraph();
		try {
			final User graphUser = graph.addUser(BaseVertex.VertexType.USER,
					this.user, this.userName);
			long userId = graphUser.getIndex();
			graph.commitTransaction();
			System.out.println("User name: " + graphUser.getName());
			System.out.println("     principal: " + graphUser.getPrincipal());
			System.out.println("     index: " + graphUser.getIndex());
		} catch (final VertexExistsException e) {
			throw new CLIException("Cannot create user, the vertex already exists! user name: " + user);
		} catch (InvalidVertexTypeException | InvalidGroupNameException e) {
			throw new CLIException("Unexpected exception.");
		} catch (final UserNotFoundException e) {
			throw new CLIException("User not found: " + this.user);
		} catch (final AccessDeniedException e) {
			throw new CLIException("User does not have permission to create a user");
		} catch (final IndexUnavailableException e) {
			throw new CLIException("Cannot get an index for the user");
		}
	}
}
