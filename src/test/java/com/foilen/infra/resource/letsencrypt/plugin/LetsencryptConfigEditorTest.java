/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.foilen.infra.plugin.core.system.fake.junits.AbstractIPPluginTest;
import com.foilen.infra.plugin.core.system.junits.JunitsHelper;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.smalltools.test.asserts.AssertTools;
import com.foilen.smalltools.tools.JsonTools;

public class LetsencryptConfigEditorTest extends AbstractIPPluginTest {

    @Test
    public void testCreate_OK() {

        // Create
        Map<String, String> formValues = new HashMap<>();
        formValues.put(LetsencryptConfig.PROPERTY_NAME, "The Name");
        formValues.put(LetsencryptConfig.PROPERTY_ACCOUNT_KEYPAIR_PEM, "");
        formValues.put(LetsencryptConfig.PROPERTY_CONTACT_EMAIL, "admin@example.com");
        formValues.put(LetsencryptConfig.PROPERTY_DNS_UPDATED_SUB_DOMAIN, "letsencrypt.example.com");
        formValues.put(LetsencryptConfig.PROPERTY_TAG_NAME, "");
        formValues.put(LetsencryptConfig.PROPERTY_IS_STAGING, "true");
        assertEditorNoErrors(null, new LetsencryptConfigEditor(), formValues);

        // Check resource
        IPResourceService resourceService = getCommonServicesContext().getResourceService();
        LetsencryptConfig letsencryptConfig = resourceService.resourceFind(resourceService.createResourceQuery(LetsencryptConfig.class)).get();
        LetsencryptConfig letsencryptConfigCleaned = JsonTools.clone(letsencryptConfig);
        letsencryptConfigCleaned.setAccountKeypairPem(notNullOrEmptyToIsSet(letsencryptConfigCleaned.getAccountKeypairPem()));
        letsencryptConfigCleaned.setTagName(notNullOrEmptyToIsSet(letsencryptConfigCleaned.getTagName()));
        AssertTools.assertJsonComparison("LetsencryptConfigEditorTest-testCreate_OK-resource-expected.json", getClass(), letsencryptConfigCleaned);

        // Load in editor
        assertEditorPageDefinition(LetsencryptConfigEditor.EDITOR_NAME, letsencryptConfigCleaned, "LetsencryptConfigEditorTest-testCreate_OK-pageDefinition-expected.json", getClass());

        // Check state
        JunitsHelper.assertState(getCommonServicesContext(), getInternalServicesContext(), "LetsencryptConfigEditorTest-testCreate_OK-state-expected.json", getClass());

    }
}
