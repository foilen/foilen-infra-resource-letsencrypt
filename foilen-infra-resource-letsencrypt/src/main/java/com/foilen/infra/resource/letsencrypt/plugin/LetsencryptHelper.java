/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.context.TimerEventContext;
import com.foilen.infra.plugin.v1.core.exception.IllegalUpdateException;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.infra.plugin.v1.model.resource.LinkTypeConstants;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.dns.model.DnsEntryType;
import com.foilen.infra.resource.letsencrypt.acme.AcmeService;
import com.foilen.infra.resource.letsencrypt.acme.AcmeServiceImpl;
import com.foilen.infra.resource.letsencrypt.acme.LetsencryptException;
import com.foilen.infra.resource.webcertificate.WebsiteCertificate;
import com.foilen.smalltools.tools.SecureRandomTools;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Joiner;

public abstract class LetsencryptHelper {

    private static final Logger logger = LoggerFactory.getLogger(LetsencryptHelper.class);

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
        logger.info("Getting the config");
        Optional<LetsencryptConfig> configOptional = resourceService.resourceFind(resourceService.createResourceQuery(LetsencryptConfig.class));
        LetsencryptConfig config;
        logger.info("Config is present? {}", configOptional.isPresent());
        if (configOptional.isPresent()) {
            config = configOptional.get();
        } else {
            throw new IllegalUpdateException("Could not find a LetsencryptConfig. Create one first");
        }

        String tagName = config.getTagName();
        if (tagName == null) {
            throw new IllegalUpdateException("The LetsencryptConfig does not have a tag name");
        }

        logger.info("Will update certificates: {}", certificatesToUpdate.stream().flatMap(it -> it.getDomainNames().stream()).sorted().collect(Collectors.toList()));
        AcmeService acmeService = new AcmeServiceImpl(config);

        // Get the challenges
        logger.info("Getting the challenges");
        List<String> domainsWithoutChallenge = new ArrayList<>();
        Map<String, Tuple2<Order, Dns01Challenge>> challengeByDomain = new HashMap<>();
        for (WebsiteCertificate certificate : certificatesToUpdate) {
            String domain = certificate.getDomainNames().stream().findFirst().get();
            Tuple2<Order, Dns01Challenge> orderAndDnsChallenge;
            try {
                orderAndDnsChallenge = acmeService.challengeInit(domain);
                Dns01Challenge dnsChallenge = orderAndDnsChallenge.getB();
                challengeByDomain.put(domain, orderAndDnsChallenge);
                String digest = dnsChallenge.getDigest();
                DnsEntry dnsEntry = new DnsEntry("_acme-challenge." + domain, DnsEntryType.TXT, digest);
                changes.resourceAdd(dnsEntry);
                changes.linkAdd(certificate, LinkTypeConstants.MANAGES, dnsEntry);
                changes.tagAdd(dnsEntry, tagName);
            } catch (LetsencryptException e) {
                logger.error("Cannot get the challenge for domain {}", domain, e);
                domainsWithoutChallenge.add(domain + " : " + e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected failure while getting the challenge for domain {}", domain, e);
                domainsWithoutChallenge.add(domain + " : " + e.getMessage());
            }
        }

        if (!domainsWithoutChallenge.isEmpty()) {
            services.getMessagingService().alertingWarn("Let's Encrypt - Domains Without Challenge", Joiner.on('\n').join(domainsWithoutChallenge));
        }

        if (challengeByDomain.isEmpty()) {
            throw new LetsencryptException("Could not get any challenge");
        }

        // Add the waiting domain
        String dnsWaitDomain = SecureRandomTools.randomHexString(5) + config.getDnsUpdatedSubDomain();
        logger.info("Adding the DNS Wait domain {}", dnsWaitDomain);

        DnsEntry dnsEntry = new DnsEntry(dnsWaitDomain, DnsEntryType.A, "127.0.0.1");
        changes.resourceAdd(dnsEntry);
        changes.linkAdd(config, LinkTypeConstants.MANAGES, dnsEntry);
        changes.tagAdd(dnsEntry, tagName);

        // Start a new timer for the rest
        logger.info("Start the Waiting for the DNS");
        services.getTimerService().timerAdd(new TimerEventContext(new LetsEncryptRefreshOldCertsWaitDnsTimer(acmeService, dnsWaitDomain, challengeByDomain), //
                "Let Encrypt - Complete - Wait DNS", //
                Calendar.MINUTE, //
                2, //
                true, //
                false));

    }

}
