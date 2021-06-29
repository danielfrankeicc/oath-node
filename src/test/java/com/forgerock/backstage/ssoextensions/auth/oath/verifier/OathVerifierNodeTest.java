/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2019 ForgeRock AS.
 * Portions copyright 2019 Zoltan Tarcsay
 * Portions copyright 2019 Josh Cross
 * Portions copyright 2019 Chris Clifton
 */

package com.forgerock.backstage.ssoextensions.auth.oath.verifier;

import com.forgerock.backstage.ssoextensions.auth.oath.OathAlgorithm;
import com.forgerock.backstage.ssoextensions.auth.oath.OathHelper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import java.io.IOException;
import java.util.HashMap;

import static com.forgerock.backstage.ssoextensions.auth.oath.OathConstants.OATH_DEVICE_PROFILE_KEY;
import static com.forgerock.backstage.ssoextensions.auth.oath.verifier.OathVerifierNode.RECOVERY_PRESSED;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

public class OathVerifierNodeTest extends PowerMockTestCase {

    @Mock
    OathVerifierNodeConfig configMock;

    @Mock
    OathHelper helper;

    @Mock
    ConfirmationCallback confirmationCallback;

    @Mock
    NameCallback nameCallback;

    OathVerifierNode verifierNode;

    private final JsonValue emptySharedState = new JsonValue(new HashMap<>());
    private final ExternalRequestContext request = new ExternalRequestContext.Builder().parameters(emptyMap()).build();
    private final OathDeviceSettings deviceSettings = new OathDeviceSettings();

    @BeforeMethod
    public void beforeMethod() {
        when(configMock.minSharedSecretLength()).thenReturn(1);
        when(configMock.passwordLength()).thenReturn(6);
        when(configMock.algorithm()).thenReturn(OathAlgorithm.HOTP);
        when(configMock.hotpWindowSize()).thenReturn(100);
        when(configMock.checksum()).thenReturn(true);
        when(configMock.truncationOffset()).thenReturn(-1);
        when(configMock.totpTimeStepInWindow()).thenReturn(2);
        when(configMock.totpTimeStepInterval()).thenReturn(30);
        when(configMock.totpMaxClockDrift()).thenReturn(5);
        when(configMock.allowRecoveryCodeUsage()).thenReturn(true);

        verifierNode = new OathVerifierNode(configMock, helper);

        deviceSettings.setSharedSecret("abcd");
    }

    @Test
    public void process_whenNoDeviceSettings_thenNotRegistered() throws NodeProcessException {

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of());
        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("NOT_REGISTERED");
    }

    @Test
    public void process_whenRecoveryPressed_thenRecoveryCode()
            throws NodeProcessException, DevicePersistenceException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(RECOVERY_PRESSED);
        when(helper.getOathDeviceSettings(any())).thenReturn(new OathDeviceSettings());

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("RECOVERY_CODE");
    }

    @Test
    public void process_whenRecoveryPressedRecoveryCodeDisabled_thenReturnCallbacks()
            throws NodeProcessException, DevicePersistenceException {

        when(configMock.allowRecoveryCodeUsage()).thenReturn(false);

        when(confirmationCallback.getSelectedIndex()).thenReturn(RECOVERY_PRESSED);
        when(helper.getOathDeviceSettings(any())).thenReturn(new OathDeviceSettings());

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));

        Action action = verifierNode.process(context);
        assertThat(action.callbacks).hasSize(2);
        assertThat(action.callbacks.get(0)).isInstanceOf(NameCallback.class);
        assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
        assertThat(((ConfirmationCallback)action.callbacks.get(1)).getOptions().length).isEqualTo(1);
    }

    @Test
    public void process_whenInitialSetup_thenReturnCallbacks()
            throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(new OathDeviceSettings());

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback));

        Action action = verifierNode.process(context);
        assertThat(action.callbacks).hasSize(2);
        assertThat(action.callbacks.get(0)).isInstanceOf(NameCallback.class);
        assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
        assertThat(((ConfirmationCallback)action.callbacks.get(1)).getOptions().length).isEqualTo(2);
    }

    @Test
    public void process_whenValidOtpProvidedFromContext_thenSuccess()
            throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(deviceSettings);
        when(nameCallback.getName()).thenReturn("5644919");

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("SUCCESS");
    }

    @Test
    public void process_whenValidOtpProvidedFromSharedState_thenSuccess() throws NodeProcessException, IOException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(nameCallback.getName()).thenReturn("5644919");
        when(helper.decryptOathDeviceSettings(anyString())).thenReturn(deviceSettings);
        JsonValue sharedState = new JsonValue(ImmutableMap.of(OATH_DEVICE_PROFILE_KEY, ""));
        TreeContext context = new TreeContext(sharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("SUCCESS");
    }

    @Test
    public void process_whenInvalidOtpProvided_thenFail() throws DevicePersistenceException, NodeProcessException {

        when(confirmationCallback.getSelectedIndex()).thenReturn(0);
        when(helper.getOathDeviceSettings(any())).thenReturn(deviceSettings);
        when(nameCallback.getName()).thenReturn("invalid_otp");

        TreeContext context = new TreeContext(emptySharedState, request, ImmutableList.of(confirmationCallback, nameCallback));

        Action action = verifierNode.process(context);
        assertThat(action.outcome).isEqualTo("FAILURE");
    }

}
