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

    private String name;
    private String contactEmail;
    private String accountKeypairPem;
    private String dnsUpdatedSubDomain;
    private String tagName;
    private boolean isStagging = false;

    public LetsencryptConfig() {
    }

    public LetsencryptConfig(String name, String contactEmail, String accountKeypairPem, String dnsUpdatedSubDomain, boolean isStagging, String tagName) {
        this.name = name;
        this.contactEmail = contactEmail;
        this.accountKeypairPem = accountKeypairPem;
        this.dnsUpdatedSubDomain = dnsUpdatedSubDomain;
        this.isStagging = isStagging;
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
                (isStagging ? "STAGGING" : "PROD");
    }

    @Override
    public String getResourceName() {
        return name;
    }

    public String getTagName() {
        return tagName;
    }

    public String getUrl() {
        if (isStagging) {
            return "acme://letsencrypt.org/staging";
        }
        return "acme://letsencrypt.org/";
    }

    public boolean isStagging() {
        return isStagging;
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

    public void setStagging(boolean isStagging) {
        this.isStagging = isStagging;
    }

    public void setTagName(String tagName) {
        this.tagName = tagName;
    }

}
