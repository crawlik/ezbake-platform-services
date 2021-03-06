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

package ezbake.deployer.publishers.openShift.inject;

import ezbake.deployer.utilities.Utilities;

import java.io.File;
import java.util.List;

/**
 * Inject resources for django apps. Right now this is just a post_deploy action hook, but others can be added
 */
public class DjangoActionHookInjector extends ClasspathResourceInjector {

    public static final String DJANGO_ACTION_HOOKS = "ezdeploy.openshift.django.action_hooks";
    private static final List<String> djangoActionHooks = Utilities.getResourcesFromClassPath(
            DjangoActionHookInjector.class, DJANGO_ACTION_HOOKS);

    /**
     * This returns the list of resources that should be looked up and injected
     *
     * @return a list of classpath resources to inject
     */
    @Override
    public List<String> getResources() {
        return djangoActionHooks;
    }

    /**
     * The path at which the resources should be injected
     *
     * @return the base path for the resources
     */
    @Override
    public File getBasePath() {
        return OPENSHIFT_ACTION_HOOKS_PATH;
    }
}
