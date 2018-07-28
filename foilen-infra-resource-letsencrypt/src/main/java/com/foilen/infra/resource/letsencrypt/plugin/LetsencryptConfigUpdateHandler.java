/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import com.foilen.infra.plugin.v1.core.common.DomainHelper;
import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.eventhandler.AbstractCommonMethodUpdateEventHandler;
import com.foilen.infra.plugin.v1.core.eventhandler.CommonMethodUpdateEventHandlerContext;
import com.foilen.infra.resource.domain.Domain;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.AsymmetricKeys;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.tools.SecureRandomTools;
import com.google.common.base.Strings;

public class LetsencryptConfigUpdateHandler extends AbstractCommonMethodUpdateEventHandler<LetsencryptConfig> {

    @Override
    protected void commonHandlerExecute(CommonServicesContext services, ChangesContext changes, CommonMethodUpdateEventHandlerContext<LetsencryptConfig> context) {

        LetsencryptConfig resource = context.getResource();

        // Domain
        context.addManagedResourceTypes(Domain.class);
        String dnsUpdatedSubDomain = resource.getDnsUpdatedSubDomain();
        context.addManagedResources(new Domain(dnsUpdatedSubDomain, DomainHelper.reverseDomainName(dnsUpdatedSubDomain)));

        boolean update = false;
        // accountKeypairPem
        if (Strings.isNullOrEmpty(resource.getAccountKeypairPem())) {
            logger.info("Generating an AccountKeypair");
            AsymmetricKeys keys = RSACrypt.RSA_CRYPT.generateKeyPair(4096);
            String accountPem = RSACrypt.RSA_CRYPT.savePrivateKeyPemAsString(keys) + RSACrypt.RSA_CRYPT.savePublicKeyPemAsString(keys);
            resource.setAccountKeypairPem(accountPem);
            update = true;
        }

        // tagName
        if (Strings.isNullOrEmpty(resource.getTagName())) {
            logger.info("Generating a Tag name");
            resource.setTagName("letsencrypt_" + SecureRandomTools.randomHexString(10).toLowerCase());
            update = true;
        }

        // Update if changed
        if (update) {
            changes.resourceUpdate(resource);
        }

    }

    @Override
    public Class<LetsencryptConfig> supportedClass() {
        return LetsencryptConfig.class;
    }

}
