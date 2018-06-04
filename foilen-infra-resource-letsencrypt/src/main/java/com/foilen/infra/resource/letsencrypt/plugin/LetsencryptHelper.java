/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.shredzone.acme4j.challenge.Dns01Challenge;

import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.context.TimerEventContext;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.infra.plugin.v1.model.resource.LinkTypeConstants;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.dns.model.DnsEntryType;
import com.foilen.infra.resource.letsencrypt.acme.AcmeService;
import com.foilen.infra.resource.letsencrypt.acme.AcmeServiceImpl;
import com.foilen.infra.resource.webcertificate.WebsiteCertificate;
import com.foilen.smalltools.tools.ResourceTools;
import com.foilen.smalltools.tools.SecureRandomTools;

public abstract class LetsencryptHelper {

    /**
     * Get the ACME configuration, create the challenges and start the timer to complete.
     *
     * @param services
     *            all services
     * @param changes
     *            the changes to make
     * @param certificatesToUpdate
     *            the certificates to generate challenges for
     */
    public static void createChallengesAndCreateTimer(CommonServicesContext services, ChangesContext changes, List<WebsiteCertificate> certificatesToUpdate) {

        IPResourceService resourceService = services.getResourceService();

        // Get the config
        Optional<LetsencryptConfig> configOptional = resourceService.resourceFind(resourceService.createResourceQuery(LetsencryptConfig.class));
        LetsencryptConfig config;
        if (configOptional.isPresent()) {
            config = configOptional.get();
        } else {
            // Create a config
            config = new LetsencryptConfig( //
                    "Foilen", //
                    "admin@foilen.com", //
                    ResourceTools.getResourceAsString("foilen-account-keypair.pem", LetsencryptHelper.class), //
                    ".letsencrypt.foilen.org", //
                    false, //
                    "letsencrypt_" + SecureRandomTools.randomBase64String(10));
            changes.resourceAdd(config);
        }

        String tagName = config.getTagName();
        if (tagName == null) {
            tagName = "letsencrypt_" + SecureRandomTools.randomBase64String(10);
            config.setTagName(tagName);
            changes.resourceUpdate(config);
        }

        AcmeService acmeService = new AcmeServiceImpl(config);

        // Get the challenges
        Map<String, Dns01Challenge> challengeByDomain = new HashMap<>();
        for (WebsiteCertificate certificate : certificatesToUpdate) {
            String domain = certificate.getDomainNames().stream().findFirst().get();
            Dns01Challenge dnsChallenge = acmeService.challengeInit(domain);
            challengeByDomain.put(domain, dnsChallenge);
            DnsEntry dnsEntry = new DnsEntry("_acme-challenge." + domain, DnsEntryType.TXT, dnsChallenge.getDigest());
            changes.resourceAdd(dnsEntry);
            changes.linkAdd(certificate, LinkTypeConstants.MANAGES, dnsEntry);
            changes.tagAdd(dnsEntry, tagName);
        }

        // Add the waiting domain
        String dnsWaitDomain = SecureRandomTools.randomHexString(5) + config.getDnsUpdatedSubDomain();

        DnsEntry dnsEntry = new DnsEntry(dnsWaitDomain, DnsEntryType.A, "127.0.0.1");
        changes.resourceAdd(dnsEntry);
        changes.linkAdd(config, LinkTypeConstants.MANAGES, dnsEntry);
        changes.tagAdd(dnsEntry, tagName);

        // Start a new timer for the rest
        services.getTimerService().timerAdd(new TimerEventContext(new LetsEncryptRefreshOldCertsWaitDnsTimer(acmeService, dnsWaitDomain, challengeByDomain), //
                "Let Encrypt - Complete - Wait DNS", //
                Calendar.MINUTE, //
                2, //
                true, //
                false));

    }

}
