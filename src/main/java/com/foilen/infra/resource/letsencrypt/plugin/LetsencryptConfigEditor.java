/*
    Foilen Infra Resource Lets Encrypt
    https://github.com/foilen/foilen-infra-resource-letsencrypt
    Copyright (c) 2018 Foilen (http://foilen.com)

    The MIT License
    http://opensource.org/licenses/MIT

 */
package com.foilen.infra.resource.letsencrypt.plugin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;

import com.foilen.infra.plugin.v1.core.visual.editor.simpleresourceditor.SimpleResourceEditor;
import com.foilen.infra.plugin.v1.core.visual.editor.simpleresourceditor.SimpleResourceEditorDefinition;
import com.foilen.infra.plugin.v1.core.visual.helper.CommonFormatting;
import com.foilen.infra.plugin.v1.core.visual.helper.CommonValidation;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.AsymmetricKeys;
import com.foilen.smalltools.crypt.spongycastle.asymmetric.RSACrypt;
import com.foilen.smalltools.tuple.Tuple2;
import com.google.common.base.Strings;

public class LetsencryptConfigEditor extends SimpleResourceEditor<LetsencryptConfig> {

    public static final String EDITOR_NAME = "Let's Encrypt Config";

    private BiFunction<String, String, List<Tuple2<String, String>>> validateKeyPair = (fieldName, fieldValue) -> {
        List<Tuple2<String, String>> errors = new ArrayList<>();
        if (!Strings.isNullOrEmpty(fieldValue)) {
            try {
                AsymmetricKeys a = RSACrypt.RSA_CRYPT.loadKeysPemFromString(fieldValue);
                if (a == null) {
                    errors.add(new Tuple2<String, String>(fieldName, "error.invalidKeyPairPem"));
                }
            } catch (Exception e) {
                errors.add(new Tuple2<String, String>(fieldName, "error.invalidKeyPairPem"));
            }
        }
        return errors;
    };
    private BiFunction<String, String, List<Tuple2<String, String>>> validateboolean = (fieldName, fieldValue) -> {
        List<Tuple2<String, String>> errors = new ArrayList<>();
        if (!Strings.isNullOrEmpty(fieldValue)) {
            if (!Arrays.asList("true", "false").contains(fieldValue)) {
                errors.add(new Tuple2<String, String>(fieldName, "error.invalidBoolean"));
            }
        }
        return errors;
    };

    @Override
    protected void getDefinition(SimpleResourceEditorDefinition simpleResourceEditorDefinition) {

        simpleResourceEditorDefinition.addInputText(LetsencryptConfig.PROPERTY_NAME, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addValidator(CommonValidation::validateNotNullOrEmpty);
        });

        simpleResourceEditorDefinition.addInputText(LetsencryptConfig.PROPERTY_CONTACT_EMAIL, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addValidator(CommonValidation::validateNotNullOrEmpty);
            fieldConfigConsumer.addValidator(CommonValidation::validateEmail);
        });

        simpleResourceEditorDefinition.addMultilineInputText(LetsencryptConfig.PROPERTY_ACCOUNT_KEYPAIR_PEM, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addValidator(validateKeyPair);
        });

        simpleResourceEditorDefinition.addInputText(LetsencryptConfig.PROPERTY_DNS_UPDATED_SUB_DOMAIN, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addFormator(CommonFormatting::toLowerCase);
            fieldConfigConsumer.addValidator(CommonValidation::validateNotNullOrEmpty);
            fieldConfigConsumer.addValidator(CommonValidation::validateDomainName);
        });

        simpleResourceEditorDefinition.addInputText(LetsencryptConfig.PROPERTY_TAG_NAME, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addFormator(CommonFormatting::toLowerCase);
            fieldConfigConsumer.addValidator(CommonValidation::validateAlphaNumLower);
        });

        simpleResourceEditorDefinition.addInputText(LetsencryptConfig.PROPERTY_IS_STAGING, fieldConfigConsumer -> {
            fieldConfigConsumer.addFormator(CommonFormatting::toLowerCase);
            fieldConfigConsumer.addFormator(CommonFormatting::trimSpacesAround);
            fieldConfigConsumer.addFormator(value -> Strings.isNullOrEmpty(value) ? "false" : value);
            fieldConfigConsumer.addValidator(CommonValidation::validateNotNullOrEmpty);
            fieldConfigConsumer.addValidator(validateboolean);
        });

    }

    @Override
    public Class<LetsencryptConfig> getForResourceType() {
        return LetsencryptConfig.class;
    }

}
