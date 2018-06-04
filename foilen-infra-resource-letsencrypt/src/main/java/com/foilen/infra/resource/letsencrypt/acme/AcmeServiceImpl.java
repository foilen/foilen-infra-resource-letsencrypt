/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.acme;

import java.net.URI;
import java.security.cert.X509Certificate;

import org.shredzone.acme4j.AcmeClient;
import org.shredzone.acme4j.AcmeClientFactory;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.foilen.infra.resource.letsencrypt.plugin.LetsencryptConfig;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;
import com.foilen.smalltools.crypt.spongycastle.cert.RSATools;
import com.foilen.smalltools.tools.AssertTools;
import com.foilen.smalltools.tools.ThreadTools;

/**
 * To communicate with the ACME server.
 */
public class AcmeServiceImpl implements AcmeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AcmeServiceImpl.class);

    private LetsencryptConfig config;

    private AcmeClient client;

    // Cache
    private Registration registration;

    public AcmeServiceImpl(LetsencryptConfig config) {
        this.config = config;
        try {
            LOGGER.info("Logging to {}", config.getUrl());
            client = AcmeClientFactory.connect(config.getUrl());
            login();
        } catch (Exception e) {
            throw new LetsencryptException("Problem connecting to ACME", e);
        }
    }

    @Override
    public void challengeComplete(Dns01Challenge challenge) {

        AssertTools.assertNotNull(registration, "You need to log in first");

        // Trigger the challenge
        try {
            LOGGER.debug("Triggering the challenge");
            client.triggerChallenge(registration, challenge);
        } catch (AcmeException e) {
            LOGGER.error("Problem triggering the challenge", e);
            throw new LetsencryptException("Problem triggering the challenge", e);
        }

        // Wait until completed
        while (challenge.getStatus() != Status.VALID) {
            if (challenge.getStatus() == Status.INVALID) {
                throw new LetsencryptException("The challenge failed");
            }
            ThreadTools.sleep(5 * 1000); // 5 secs
            try {
                LOGGER.debug("Updating the status");
                client.updateChallenge(challenge);
            } catch (AcmeException e) {
                LOGGER.error("Problem updating the challenge status", e);
                throw new LetsencryptException("Problem updating the challenge status", e);
            }
            LOGGER.debug("Current status: {}", challenge.getStatus());
        }

    }

    @Override
    public Dns01Challenge challengeInit(String domainName) {

        AssertTools.assertNotNull(registration, "You need to log in first");

        Authorization authorization = new Authorization();
        authorization.setDomain(domainName);

        try {
            LOGGER.debug("Getting authorization for domain {}", domainName);
            client.newAuthorization(registration, authorization);
        } catch (AcmeException e) {
            LOGGER.error("Problem authorizing domain {}", domainName, e);
            throw new LetsencryptException("Problem authorizing domain " + domainName, e);
        }

        // Get the DNS challenge
        Dns01Challenge challenge = authorization.findChallenge(Dns01Challenge.TYPE);
        if (challenge == null) {
            LOGGER.error("The DNS challenge is unsupported");
            throw new LetsencryptException("The DNS challenge is unsupported");
        }

        // Start the challenge
        challenge.authorize(registration);
        return challenge;
    }

    @Override
    public void login() {
        registration = new Registration(RSATools.createKeyPair(RSACrypt.RSA_CRYPT.loadKeysPemFromString(config.getAccountKeypairPem())));
        registration.addContact("mailto:" + config.getContactEmail());

        // Create a new registration
        try {
            LOGGER.debug("Registering account");
            client.newRegistration(registration);
            // Accept TOS
            LOGGER.debug("Accepting TOS: {}", registration.getAgreement());// TODO Keep track of TOS
            client.modifyRegistration(registration);
        } catch (AcmeConflictException e) {
            // AcmeClient already exists
        } catch (AcmeException e) {
            LOGGER.error("Problem registering account", e);
            registration = null;
            throw new LetsencryptException("Problem registering account", e);
        }

        // Get the location
        LOGGER.debug("AcmeClient location: {}", registration.getLocation());

    }

    @Override
    public RSACertificate requestCertificate(byte[] certificateRequest) {

        AssertTools.assertNotNull(registration, "You need to log in first");

        // Get the cert URL
        URI certUri;
        try {
            LOGGER.debug("Get the certificate URL");
            certUri = client.requestCertificate(registration, certificateRequest);
        } catch (AcmeException e) {
            LOGGER.error("Problem getting the certificate", e);
            throw new LetsencryptException("Problem getting the certificate", e);
        }

        // Download the cert
        try {
            LOGGER.debug("Download the certificate");
            X509Certificate cert = client.downloadCertificate(certUri);
            return new RSACertificate(cert);
        } catch (AcmeException e) {
            LOGGER.error("Problem downloading the certificate", e);
            throw new LetsencryptException("Problem downloading the certificate", e);
        }

    }

}
