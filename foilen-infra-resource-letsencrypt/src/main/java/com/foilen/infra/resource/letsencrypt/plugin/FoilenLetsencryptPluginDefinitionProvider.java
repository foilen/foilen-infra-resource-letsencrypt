/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;

import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.plugin.IPPluginDefinitionProvider;
import com.foilen.infra.plugin.v1.core.plugin.IPPluginDefinitionV1;

public class FoilenLetsencryptPluginDefinitionProvider implements IPPluginDefinitionProvider {

    @Override
    public IPPluginDefinitionV1 getIPPluginDefinition() {
        IPPluginDefinitionV1 pluginDefinition = new IPPluginDefinitionV1("Foilen", "Lets Encrypt", "Automatically retrieve letsencrypt certificates", "1.0.0");

        pluginDefinition.addCustomResource(LetsencryptConfig.class, "Letsencrypt Config", //
                Arrays.asList(LetsencryptConfig.PROPERTY_NAME), //
                Collections.emptyList());

        pluginDefinition.addTimer(new LetsEncryptRefreshOldCertsBeginTimer(), //
                LetsEncryptRefreshOldCertsBeginTimer.TIMER_NAME, //
                Calendar.DAY_OF_YEAR, //
                1, //
                false, //
                true);

        // Resource editors
        pluginDefinition.addTranslations("/com/foilen/infra/resource/letsencrypt/messages");
        pluginDefinition.addResourceEditor(new LetsencryptConfigEditor(), LetsencryptConfigEditor.EDITOR_NAME);
        pluginDefinition.addResourceEditor(new LetsEncryptWebsiteCertificateEditor(), LetsEncryptWebsiteCertificateEditor.EDITOR_NAME);

        // Updater
        pluginDefinition.addUpdateHandler(new LetsencryptConfigUpdateHandler());

        return pluginDefinition;
    }

    @Override
    public void initialize(CommonServicesContext commonServicesContext) {
    }

}
