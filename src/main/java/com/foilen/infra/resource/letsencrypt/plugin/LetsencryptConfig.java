/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.foilen.infra.plugin.v1.model.resource.AbstractIPResource;
import com.foilen.infra.plugin.v1.model.resource.InfraPluginResourceCategory;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LetsencryptConfig extends AbstractIPResource {

    public static final String PROPERTY_NAME = "name";
    public static final String PROPERTY_CONTACT_EMAIL = "contactEmail";
    public static final String PROPERTY_ACCOUNT_KEYPAIR_PEM = "accountKeypairPem";
    public static final String PROPERTY_DNS_UPDATED_SUB_DOMAIN = "dnsUpdatedSubDomain";
    public static final String PROPERTY_TAG_NAME = "tagName";
    public static final String PROPERTY_IS_STAGING = "staging";

    private String name;
    private String contactEmail;
    private String accountKeypairPem;
    private String dnsUpdatedSubDomain;
    private String tagName;
    private boolean isStaging;

    public LetsencryptConfig() {
    }

    public LetsencryptConfig(String name, String contactEmail, String accountKeypairPem, String dnsUpdatedSubDomain, boolean isStaging, String tagName) {
        this.name = name;
        this.contactEmail = contactEmail;
        this.accountKeypairPem = accountKeypairPem;
        this.dnsUpdatedSubDomain = dnsUpdatedSubDomain;
        this.isStaging = isStaging;
        this.tagName = tagName;
    }

    public String getAccountKeypairPem() {
        return accountKeypairPem;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public String getDnsUpdatedSubDomain() {
        return dnsUpdatedSubDomain;
    }

    public String getName() {
        return name;
    }

    @Override
    public InfraPluginResourceCategory getResourceCategory() {
        return InfraPluginResourceCategory.NET;
    }

    @Override
    public String getResourceDescription() {
        return contactEmail //
                + " | " + //
                (isStaging ? "STAGGING" : "PROD");
    }

    @Override
    public String getResourceName() {
        return name;
    }

    public String getTagName() {
        return tagName;
    }

    public String getUrl() {
        if (isStaging) {
            return "acme://letsencrypt.org/staging";
        }
        return "acme://letsencrypt.org/";
    }

    public boolean isStaging() {
        return isStaging;
    }

    public void setAccountKeypairPem(String accountKeypairPem) {
        this.accountKeypairPem = accountKeypairPem;
    }

    public void setContactEmail(String contactEmail) {
        this.contactEmail = contactEmail;
    }

    public void setDnsUpdatedSubDomain(String dnsUpdatedSubDomain) {
        this.dnsUpdatedSubDomain = dnsUpdatedSubDomain;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setStaging(boolean isStaging) {
        this.isStaging = isStaging;
    }

    public void setTagName(String tagName) {
        this.tagName = tagName;
    }

}
