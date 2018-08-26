/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.acme.test;

import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;

import com.foilen.infra.resource.letsencrypt.acme.AcmeService;
import com.foilen.infra.resource.letsencrypt.acme.AcmeServiceImpl;
import com.foilen.infra.resource.letsencrypt.acme.LetsencryptException;
import com.foilen.infra.resource.letsencrypt.plugin.LetsencryptConfig;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.AsymmetricKeys;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;
import com.foilen.smalltools.crypt.spongycastle.cert.RSATools;
import com.foilen.smalltools.tools.FileTools;
import com.foilen.smalltools.tools.SecureRandomTools;
import com.foilen.smalltools.tools.ThreadTools;
import com.foilen.smalltools.tuple.Tuple2;

public class TestAcmeStaging {

    private static final String KEYPAIR_FILE = "_keypair.pem";

    public static void main(String[] args) {

        // Get or create registration
        String accountPem;
        if (FileTools.exists(KEYPAIR_FILE)) {
            System.out.println("Key Pair: Reusing");
            accountPem = FileTools.getFileAsString(KEYPAIR_FILE);
        } else {
            System.out.println("Key Pair: Creating");
            AsymmetricKeys keys = RSACrypt.RSA_CRYPT.generateKeyPair(4096);
            accountPem = RSACrypt.RSA_CRYPT.savePrivateKeyPemAsString(keys) + RSACrypt.RSA_CRYPT.savePublicKeyPemAsString(keys);
            FileTools.writeFile(accountPem, KEYPAIR_FILE);
        }

        // Create the config
        LetsencryptConfig config = new LetsencryptConfig( //
                "Foilen", //
                "admin@foilen.com", //
                accountPem, //
                ".letsencrypt.foilen.org", //
                true, //
                "letsencrypt_" + SecureRandomTools.randomBase64String(10));

        // Request the challenge
        AcmeService acmeService = new AcmeServiceImpl(config);
        String domainName = "testing.foilen.org";
        Tuple2<Order, Dns01Challenge> orderAndDnsChallenge = acmeService.challengeInit(domainName);
        Dns01Challenge dnsChallenge = orderAndDnsChallenge.getB();

        String acmeDomainName = "_acme-challenge." + domainName;
        System.out.println("Need " + acmeDomainName + " / TXT / " + dnsChallenge.getDigest());

        // Wait for the DNS to be updated
        System.out.println("Waiting for domain 5 minutes");
        ThreadTools.sleep(5 * 60000);

        // Confirm
        try {
            System.out.println("Challenge completed");
            acmeService.challengeComplete(dnsChallenge);
        } catch (LetsencryptException e) {
            // Challenge failed
            System.out.println("Failed the challenge");
            e.printStackTrace();
            System.exit(1);
        }

        // Get the certificate
        System.out.println("Getting the certificate");
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(domainName);

        try {
            AsymmetricKeys asymmetricKeys = RSACrypt.RSA_CRYPT.generateKeyPair(4096);
            csrb.sign(RSATools.createKeyPair(asymmetricKeys));
            byte[] csr = csrb.getEncoded();
            RSACertificate certificate = acmeService.requestCertificate(orderAndDnsChallenge.getA(), csr);
            certificate.setKeysForSigning(asymmetricKeys);

            System.out.println("Got the certificate: " + certificate.getThumbprint());
        } catch (Exception e) {
            System.out.println("Failed to retrieve the certificate");
            e.printStackTrace();
            System.exit(1);
        }

    }

}
