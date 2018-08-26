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
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.foilen.infra.plugin.v1.core.context.ChangesContext;
import com.foilen.infra.plugin.v1.core.context.CommonServicesContext;
import com.foilen.infra.plugin.v1.core.service.TranslationService;
import com.foilen.infra.plugin.v1.core.visual.PageDefinition;
import com.foilen.infra.plugin.v1.core.visual.editor.ResourceEditor;
import com.foilen.infra.plugin.v1.core.visual.helper.CommonFormatting;
import com.foilen.infra.plugin.v1.core.visual.helper.CommonPageItem;
import com.foilen.infra.plugin.v1.core.visual.helper.CommonValidation;
import com.foilen.infra.plugin.v1.core.visual.pageItem.LabelPageItem;
import com.foilen.infra.plugin.v1.core.visual.pageItem.field.InputTextFieldPageItem;
import com.foilen.infra.resource.webcertificate.WebsiteCertificate;
import com.foilen.infra.resource.webcertificate.helper.CertificateHelper;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.AsymmetricKeys;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.crypt.spongycastle.cert.CertificateDetails;
import com.foilen.smalltools.crypt.spongycastle.cert.RSACertificate;
import com.foilen.smalltools.tools.DateTools;
import com.foilen.smalltools.tuple.Tuple2;

public class LetsEncryptWebsiteCertificateEditor implements ResourceEditor<WebsiteCertificate> {

    public static final String EDITOR_NAME = "Let's Encrypt WebsiteCertificate";

    private static final String FIELD_NAME_DOMAIN = "domain";

    @Override
    public void fillResource(CommonServicesContext servicesCtx, ChangesContext changesContext, Map<String, String> validFormValues, WebsiteCertificate resource) {

        String domain = validFormValues.get(FIELD_NAME_DOMAIN);

        boolean gen = false;
        // Not gen
        gen |= resource.getCertificate() == null;
        // Expired
        if (resource.getEnd() == null) {
            gen = true;
        } else {
            gen |= resource.getEnd().getTime() < System.currentTimeMillis();
        }
        // Not the same domain
        Optional<String> currentDomainOptional = resource.getDomainNames().stream().findFirst();
        if (currentDomainOptional.isPresent()) {
            gen |= !currentDomainOptional.get().equals(domain);
        } else {
            gen = true;
        }

        if (gen) {

            AsymmetricKeys keys = RSACrypt.RSA_CRYPT.generateKeyPair(4096);
            RSACertificate rsaCertificate = new RSACertificate(keys).selfSign( //
                    new CertificateDetails().setCommonName(domain) //
                            .addSanDns(domain) //
                            .setEndDate(DateTools.addDate(Calendar.DAY_OF_YEAR, 1)));
            CertificateHelper.toWebsiteCertificate(null, rsaCertificate, resource);

            // Request an official cert
            servicesCtx.getTimerService().executeLater((services, changes, event) -> {
                List<WebsiteCertificate> certificatesToUpdate = new ArrayList<>();
                certificatesToUpdate.add(resource);
                LetsencryptHelper.createChallengesAndCreateTimer(servicesCtx, changes, certificatesToUpdate);
            });

        }

    }

    @Override
    public void formatForm(CommonServicesContext servicesCtx, Map<String, String> rawFormValues) {
        CommonFormatting.trimSpacesAround(rawFormValues);
    }

    @Override
    public Class<WebsiteCertificate> getForResourceType() {
        return WebsiteCertificate.class;
    }

    @Override
    public PageDefinition providePageDefinition(CommonServicesContext servicesCtx, WebsiteCertificate editedResource) {

        TranslationService translationService = servicesCtx.getTranslationService();

        PageDefinition pageDefinition = new PageDefinition(translationService.translate("LetsEncryptWebsiteCertificateEditor.title"));

        pageDefinition.addPageItem(new LabelPageItem().setText( //
                translationService.translate("LetsEncryptWebsiteCertificateEditor.information") //
        ));

        InputTextFieldPageItem domainPageItem = CommonPageItem.createInputTextField(servicesCtx, pageDefinition, "LetsEncryptWebsiteCertificateEditor.domain", FIELD_NAME_DOMAIN);

        if (editedResource != null) {

            pageDefinition.addPageItem(new LabelPageItem().setText( //
                    translationService.translate("LetsEncryptWebsiteCertificateEditor.thumbprint", editedResource.getThumbprint()) //
            ));

            pageDefinition.addPageItem(new LabelPageItem().setText( //
                    translationService.translate("LetsEncryptWebsiteCertificateEditor.start", DateTools.formatFull(editedResource.getStart())) //
            ));

            pageDefinition.addPageItem(new LabelPageItem().setText( //
                    translationService.translate("LetsEncryptWebsiteCertificateEditor.end", DateTools.formatFull(editedResource.getEnd())) //
            ));

            Optional<String> domain = editedResource.getDomainNames().stream().findFirst();
            domainPageItem.setFieldValue(domain.isPresent() ? domain.get() : null);

        }

        return pageDefinition;

    }

    @Override
    public List<Tuple2<String, String>> validateForm(CommonServicesContext servicesCtx, Map<String, String> rawFormValues) {
        List<Tuple2<String, String>> errors = CommonValidation.validateNotNullOrEmpty(rawFormValues, FIELD_NAME_DOMAIN);
        errors.addAll(CommonValidation.validateDomainName(rawFormValues, FIELD_NAME_DOMAIN));
        return errors;

    }

}
