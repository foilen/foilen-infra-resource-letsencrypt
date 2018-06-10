/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.acme;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.foilen.infra.resource.letsencrypt.plugin.LetsencryptConfig;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;
import com.foilen.smalltools.crypt.spongycastle.cert.RSATools;
import com.foilen.smalltools.tools.AssertTools;
import com.foilen.smalltools.tools.ThreadTools;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Joiner;

/**
 * To communicate with the ACME server.
 */
public class AcmeServiceImpl implements AcmeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AcmeServiceImpl.class);

    private LetsencryptConfig config;

    // Cache
    private Session session;
    private Account account;

    public AcmeServiceImpl(LetsencryptConfig config) {
        this.config = config;
        try {
            LOGGER.info("Logging to {}", config.getUrl());
            session = new Session(new URI(config.getUrl()));
            login();
        } catch (Exception e) {
            throw new LetsencryptException("Problem connecting to ACME", e);
        }
    }

    @Override
    public void challengeComplete(Dns01Challenge challenge) {

        AssertTools.assertNotNull(account, "You need to log in first");

        // Trigger the challenge
        try {
            LOGGER.info("Triggering the challenge");
            challenge.trigger();
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
                LOGGER.info("Updating the status");
                challenge.update();
            } catch (AcmeException e) {
                LOGGER.error("Problem updating the challenge status", e);
                throw new LetsencryptException("Problem updating the challenge status", e);
            }
            LOGGER.info("Current status: {}", challenge.getStatus());
        }

    }

    @Override
    public Tuple2<Order, Dns01Challenge> challengeInit(String domainName) {

        AssertTools.assertNotNull(account, "You need to log in first");

        Order order;
        try {
            order = account.newOrder() //
                    .domains(domainName) //
                    .create();
        } catch (AcmeException e) {
            LOGGER.error("Could not ask for domain {}", domainName, e);
            throw new LetsencryptException("Could not ask for domain " + domainName, e);
        }

        // Get the DNS challenge
        Dns01Challenge challenge = null;
        List<String> availableChallenges = new ArrayList<>();
        for (Authorization auth : order.getAuthorizations()) {
            auth.getChallenges().stream().map(it -> it.getType()).forEach(it -> availableChallenges.add(it));
            challenge = auth.findChallenge(Dns01Challenge.TYPE);
        }
        if (challenge == null) {
            throw new LetsencryptException("DNS Challenge not found for " + domainName + " ; Available challenges are: [" + Joiner.on(", ").join(availableChallenges) + "]");
        }

        return new Tuple2<>(order, challenge);
    }

    private void login() {

        KeyPair accountKeyPair = RSATools.createKeyPair(RSACrypt.RSA_CRYPT.loadKeysPemFromString(config.getAccountKeypairPem()));

        LOGGER.info("Registering account");
        try {
            account = new AccountBuilder() //
                    .addContact("mailto:" + config.getContactEmail()) //
                    .agreeToTermsOfService() //
                    .useKeyPair(accountKeyPair) //
                    .create(session);
        } catch (AcmeException e) {
            LOGGER.error("Problem logging in", e);
            throw new LetsencryptException("Problem logging in", e);
        }

        URL accountLocationUrl = account.getLocation();
        session.login(accountLocationUrl, accountKeyPair);

        // Get the location
        LOGGER.info("AcmeClient location: {}", accountLocationUrl);

    }

    @Override
    public RSACertificate requestCertificate(Order order, byte[] certificateRequest) {

        AssertTools.assertNotNull(account, "You need to log in first");

        // Get the cert URL
        try {
            order.execute(certificateRequest);
        } catch (AcmeException e) {
            LOGGER.error("Problem executing the cert request", e);
            throw new LetsencryptException("Problem executing the cert request", e);
        }

        // Wait the order to be ready
        int count = 0;
        while (order.getStatus() != Status.VALID && count < 6) {
            if (order.getStatus() == Status.INVALID) {
                throw new LetsencryptException("The order failed");
            }
            ThreadTools.sleep(10 * 1000); // 10 secs
            try {
                LOGGER.info("Updating the status");
                order.update();
            } catch (AcmeException e) {
                LOGGER.error("Problem updating the order status", e);
                throw new LetsencryptException("Problem updating the order status", e);
            }
            LOGGER.info("[{}] Current order status: {}", count, order.getStatus());
            ++count;
        }

        if (order.getStatus() != Status.VALID) {
            LOGGER.error("Order status is still not valid after 1 minute. Status is {} ; problem is {} ; json: {}", order.getStatus(), order.getError(), order.getJSON().toString());
            throw new LetsencryptException("Order status is still not valid after 1 minute. Status is " + order.getStatus());
        }

        Certificate certificate = order.getCertificate();
        X509Certificate cert = certificate.getCertificate();
        return new RSACertificate(cert);

    }

}
