/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.context.TimerEventContext;
import com.foilen.infra.plugin.v1.core.eventhandler.TimerEventHandler;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.webcertificate.WebsiteCertificate;
import com.foilen.smalltools.tools.AbstractBasics;
import com.foilen.smalltools.tools.DateTools;
import com.google.common.base.Strings;

/**
 * Checks the certificates that will expire in 3 weeks and refresh them.
 */
public class LetsEncryptRefreshOldCertsBeginTimer extends AbstractBasics implements TimerEventHandler {

    public static final String TIMER_NAME = "Lets Encrypt";

    @Override
    public void timerHandler(CommonServicesContext services, ChangesContext changes, TimerEventContext event) {

        IPResourceService resourceService = services.getResourceService();

        // Remove any pending check (would have if the application is restarted while waiting)
        logger.info("Cleaning pending checks");
        Set<String> tagNames = resourceService.resourceFindAll(resourceService.createResourceQuery(LetsencryptConfig.class)).stream() //
                .map(LetsencryptConfig::getTagName) //
                .filter(it -> !Strings.isNullOrEmpty(it)) //
                .collect(Collectors.toSet());
        List<DnsEntry> oldDnsEntries = resourceService.resourceFindAll( //
                resourceService.createResourceQuery(DnsEntry.class) //
                        .tagAddOr(tagNames.toArray(new String[tagNames.size()])));
        long cleaned = 0;
        for (DnsEntry dnsEntry : oldDnsEntries) {
            changes.resourceDelete(dnsEntry);
            ++cleaned;
        }
        logger.info("Cleaned {} old DnsEntries", cleaned);

        // Check the certs that will expire in 3 weeks
        logger.info("Getting lets encrypt certificates that expire in 3 weeks");
        List<WebsiteCertificate> certificatesToUpdate = resourceService.resourceFindAll( //
                resourceService.createResourceQuery(WebsiteCertificate.class) //
                        .addEditorEquals(LetsEncryptWebsiteCertificateEditor.EDITOR_NAME) //
                        .propertyLesserAndEquals(WebsiteCertificate.PROPERTY_END, DateTools.addDate(new Date(), Calendar.WEEK_OF_YEAR, 3) //
                ));

        logger.info("Got {} certificates that will expire", certificatesToUpdate.size());
        // Remove those that failed in the last day
        long beforeTime = System.currentTimeMillis() - 23 * 60 * 60000;
        certificatesToUpdate.removeIf(websiteCertificate -> {
            String value = websiteCertificate.getMeta().get(LetsencryptHelper.LAST_FAILURE);
            if (value != null) {
                try {
                    long lastFailure = Long.valueOf(value);
                    return lastFailure > beforeTime;
                } catch (Exception e) {
                }
            }
            return false;
        });

        logger.info("Got {} certificates to update", certificatesToUpdate.size());
        if (certificatesToUpdate.isEmpty()) {
            return;
        }

        certificatesToUpdate.forEach(it -> {
            logger.info("Updating certificates: {}", it.getDomainNames());
        });

        LetsencryptHelper.createChallengesAndCreateTimer(services, changes, certificatesToUpdate);

    }

}
