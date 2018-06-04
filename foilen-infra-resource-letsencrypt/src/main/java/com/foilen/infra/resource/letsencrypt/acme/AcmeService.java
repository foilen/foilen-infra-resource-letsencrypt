/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.acme;

import org.shredzone.acme4j.challenge.Dns01Challenge;

import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;

public interface AcmeService {

    void challengeComplete(Dns01Challenge dnsChallenge);

    Dns01Challenge challengeInit(String domainName);

    void login();

    RSACertificate requestCertificate(byte[] certificateRequest);

}