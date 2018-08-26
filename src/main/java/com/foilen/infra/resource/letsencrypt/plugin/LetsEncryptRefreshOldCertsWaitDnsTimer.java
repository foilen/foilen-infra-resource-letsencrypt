/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;

import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.context.TimerEventContext;
import com.foilen.infra.plugin.v1.core.eventhandler.TimerEventHandler;
import com.foilen.infra.plugin.v1.core.service.IPResourceService;
import com.foilen.infra.plugin.v1.model.resource.LinkTypeConstants;
import com.foilen.infra.resource.dns.DnsEntry;
import com.foilen.infra.resource.dns.model.DnsEntryType;
import com.foilen.infra.resource.letsencrypt.acme.AcmeService;
import com.foilen.infra.resource.letsencrypt.acme.LetsencryptException;
import com.foilen.infra.resource.webcertificate.WebsiteCertificate;
import com.foilen.infra.resource.webcertificate.helper.CertificateHelper;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.AsymmetricKeys;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;
import com.foilen.smalltools.crypt.spongycastle.cert.RSATools;
import com.foilen.smalltools.tools.AbstractBasics;
import com.foilen.smalltools.tools.ResourceTools;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Joiner;

public class LetsEncryptRefreshOldCertsWaitDnsTimer extends AbstractBasics implements TimerEventHandler {

    private static final String CA_CERTIFICATE_TEXT = ResourceTools.getResourceAsString("/com/foilen/infra/resource/letsencrypt/lets-encrypt-x3-cross-signed.pem");

    private AcmeService acmeService;

    private String dnsWaitDomain;
    private Map<String, Tuple2<Order, Dns01Challenge>> challengeByDomain;

    private boolean foundOnLastCheck = false;

    public LetsEncryptRefreshOldCertsWaitDnsTimer(AcmeService acmeService, String dnsWaitDomain, Map<String, Tuple2<Order, Dns01Challenge>> challengeByDomain) {
        this.acmeService = acmeService;
        this.dnsWaitDomain = dnsWaitDomain;
        this.challengeByDomain = challengeByDomain;
    }

    @Override
    public void timerHandler(CommonServicesContext services, ChangesContext changes, TimerEventContext event) {

        try {

            // Wait for the domain + 30s
            try {
                logger.info("Checking for domain {}", dnsWaitDomain);
                InetAddress.getByName(dnsWaitDomain);
            } catch (UnknownHostException e) {
                // Wait 2 more minutes
                logger.info("Domain {} not present. Waiting 2 more minutes", dnsWaitDomain);
                services.getTimerService().timerAdd(new TimerEventContext(this, //
                        "Let Encrypt - Complete - Wait DNS", //
                        Calendar.MINUTE, //
                        2, //
                        true, //
                        false));
                return;
            }

            logger.info("Domain {} found", dnsWaitDomain);
            if (!foundOnLastCheck) {
                // Wait just 30 seconds more
                logger.info("Wait 30 more seconds");
                foundOnLastCheck = true;
                services.getTimerService().timerAdd(new TimerEventContext(this, //
                        "Let Encrypt - Complete - Wait last", //
                        Calendar.SECOND, //
                        30, //
                        true, //
                        false));
                return;
            }

            // Complete the challenges
            logger.info("Complete challenges");
            IPResourceService resourceService = services.getResourceService();
            Iterator<Entry<String, Tuple2<Order, Dns01Challenge>>> it = challengeByDomain.entrySet().iterator();
            while (it.hasNext()) {
                Entry<String, Tuple2<Order, Dns01Challenge>> entry = it.next();
                try {
                    logger.info("Complete the challenge for certificate: {}", entry.getKey());
                    acmeService.challengeComplete(entry.getValue().getB());
                } catch (LetsencryptException e) {
                    // Challenge failed
                    logger.info("Failed the challenge for certificate: {}", entry.getKey());

                    // Update meta as failure
                    resourceService.resourceFindAll( //
                            resourceService.createResourceQuery(WebsiteCertificate.class) //
                                    .addEditorEquals(LetsEncryptWebsiteCertificateEditor.EDITOR_NAME) //
                                    .propertyEquals(WebsiteCertificate.PROPERTY_DOMAIN_NAMES, Collections.singleton(entry.getKey()))) //
                            .forEach(websiteCertificate -> {
                                websiteCertificate.getMeta().put(LetsencryptHelper.LAST_FAILURE, String.valueOf(System.currentTimeMillis()));
                                changes.resourceUpdate(websiteCertificate);
                            });

                    it.remove();
                }
            }

            // Get all the certificates
            logger.info("Get all the certificates currently in the system");
            List<WebsiteCertificate> websiteCertificates = new ArrayList<>();
            for (String domain : challengeByDomain.keySet()) {
                websiteCertificates.addAll(resourceService.resourceFindAll( //
                        resourceService.createResourceQuery(WebsiteCertificate.class) //
                                .addEditorEquals(LetsEncryptWebsiteCertificateEditor.EDITOR_NAME) //
                                .propertyEquals(WebsiteCertificate.PROPERTY_DOMAIN_NAMES, Collections.singleton(domain)) //
                ));
            }
            Map<String, WebsiteCertificate> websiteCertificateByDomain = new HashMap<>();
            websiteCertificates.forEach(websiteCertificate -> {
                String domain = websiteCertificate.getDomainNames().stream().findFirst().get();
                websiteCertificateByDomain.put(domain, websiteCertificate);
            });

            // Get the certificates for the successful ones
            logger.info("Get all the certificates from Lets Encrypt");
            List<String> failures = new ArrayList<>();
            List<Tuple2<AsymmetricKeys, RSACertificate>> keysAndCerts = new ArrayList<>();
            for (String domain : challengeByDomain.keySet()) {
                AsymmetricKeys asymmetricKeys = RSACrypt.RSA_CRYPT.generateKeyPair(4096);

                CSRBuilder csrb = new CSRBuilder();
                csrb.addDomain(domain);

                try {
                    logger.info("Getting certificate for: {}", domain);
                    csrb.sign(RSATools.createKeyPair(asymmetricKeys));
                    byte[] csr = csrb.getEncoded();
                    RSACertificate certificate = acmeService.requestCertificate(challengeByDomain.get(domain).getA(), csr);
                    certificate.setKeysForSigning(asymmetricKeys);
                    keysAndCerts.add(new Tuple2<>(asymmetricKeys, certificate));

                    logger.info("Successfully updated certificate: {}", domain);
                } catch (Exception e) {
                    // Cert creation failed
                    logger.info("Failed to retrieve the certificate for: {}", domain);
                    failures.add(domain + " : " + e.getMessage());
                }
            }

            if (!failures.isEmpty()) {
                services.getMessagingService().alertingWarn("Let's Encrypt - Domains Couldn't get certificate", Joiner.on('\n').join(failures));
            }

            // Delete the DNS wait entry
            logger.info("Delete the DNS Wait entry: {}", dnsWaitDomain);
            changes.resourceDelete(new DnsEntry(dnsWaitDomain, DnsEntryType.A, "127.0.0.1"));

            // Update the certificates
            logger.info("Update the certificates in the system");
            for (Tuple2<AsymmetricKeys, RSACertificate> entry : keysAndCerts) {
                RSACertificate rsaCertificate = entry.getB();
                WebsiteCertificate newCert = CertificateHelper.toWebsiteCertificate(CA_CERTIFICATE_TEXT, rsaCertificate);
                newCert.setResourceEditorName(LetsEncryptWebsiteCertificateEditor.EDITOR_NAME);

                String commonName = newCert.getDomainNames().stream().findFirst().get();
                WebsiteCertificate previousCert = websiteCertificateByDomain.get(commonName);

                changes.resourceUpdate(previousCert, newCert);
            }

            // Delete the DNS entries for challenges
            logger.info("Delete the DNS entries for challenges");
            for (WebsiteCertificate websiteCertificate : websiteCertificates) {
                List<DnsEntry> dnsEntries = resourceService.linkFindAllByFromResourceAndLinkTypeAndToResourceClass(websiteCertificate, LinkTypeConstants.MANAGES, DnsEntry.class);
                for (DnsEntry dnsEntry : dnsEntries) {
                    changes.resourceDelete(dnsEntry);
                }
            }

        } catch (Exception e) {
            logger.error("Problem while managing Lets Encrypt", e);
            services.getMessagingService().alertingError("Problem while managing Lets Encrypt", e.getMessage());
        } finally {
            logger.info("Timer completed");
        }

    }

}
