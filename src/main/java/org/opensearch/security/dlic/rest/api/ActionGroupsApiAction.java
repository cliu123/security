/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.checkerframework.checker.units.qual.C;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.dlic.rest.validation.ActionGroupValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.ConfigModelV7;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.securityconf.impl.CType;
import com.google.common.collect.ImmutableList;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ActionGroupsApiAction extends PatchableResourceApiAction {

	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			// legacy mapping for backwards compatibility
			// TODO: remove in next version
			new Route(Method.GET, "/actiongroup/{name}"),
			new Route(Method.GET, "/actiongroup/"),
			new Route(Method.DELETE, "/actiongroup/{name}"),
			new Route(Method.PUT, "/actiongroup/{name}"),

			// corrected mapping, introduced in OpenSearch Security
			new Route(Method.GET, "/actiongroups/{name}"),
			new Route(Method.GET, "/actiongroups/"),
			new Route(Method.DELETE, "/actiongroups/{name}"),
			new Route(Method.PUT, "/actiongroups/{name}"),
			new Route(Method.PATCH, "/actiongroups/"),
			new Route(Method.PATCH, "/actiongroups/{name}")

	));

	@Override
	protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		final String name = request.param("name");
		final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);
		existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

		new ConfigModelV7(null, null, (SecurityDynamicConfiguration<ActionGroupsV7>) existingConfiguration, null, null, null);
		try {
			log.info("!!!!!Create ConfigModelV7 object");
//			new ConfigModelV7(null, null, (SecurityDynamicConfiguration<ActionGroupsV7>) existingConfiguration, null, null, null);
		} catch (StackOverflowError e) {
			log.info("!!!!!Caught StackOverflowError");
			throw new OpenSearchSecurityException("Recursive action group");
		}
		super.handlePut(channel, request, client, content);
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ACTIONGROUPS;
	}

	@Inject
	public ActionGroupsApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                 final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                                 final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(final RestRequest request, BytesReference ref, Object... param) {
		return new ActionGroupValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected CType getConfigName() {
		return CType.ACTIONGROUPS;
	}

	@Override
    protected String getResourceName() {
        return "actiongroup";
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

}
