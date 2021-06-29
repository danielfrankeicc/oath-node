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
import org.forgerock.openam.core.rest.devices.oath.OathDeviceSettings;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

public class HotpVerifierTest extends PowerMockTestCase {

    @Mock
    OathVerifierNodeConfig configMock;

    private final OathDeviceSettings settings = new OathDeviceSettings();
    private HotpVerifier hotpVerifier;

    @BeforeMethod
    public void init() {
        when(configMock.minSharedSecretLength()).thenReturn(1);
        when(configMock.passwordLength()).thenReturn(6);
        when(configMock.algorithm()).thenReturn(OathAlgorithm.HOTP);
        when(configMock.hotpWindowSize()).thenReturn(100);
        when(configMock.checksum()).thenReturn(false);
        when(configMock.truncationOffset()).thenReturn(-1);
        when(configMock.totpTimeStepInWindow()).thenReturn(2);
        when(configMock.totpTimeStepInterval()).thenReturn(30);
        when(configMock.totpMaxClockDrift()).thenReturn(5);
        when(configMock.allowRecoveryCodeUsage()).thenReturn(true);

        hotpVerifier = new HotpVerifier(configMock, settings);;

        settings.setSharedSecret("abcd");
    }

    @Test
    public void verify_whenFirst_thenValid() throws OathVerificationException {
        settings.setCounter(0);
        hotpVerifier.verify("564491");
    }

    @Test
    public void verify_whenSecond_thenValid() throws OathVerificationException {
        settings.setCounter(1);
        hotpVerifier.verify("853971");
    }

    @Test
    public void verify_whenInvalidToken_thenFail() {
        assertThatThrownBy(() -> hotpVerifier.verify("foo"))
                .isInstanceOf(OathVerificationException.class);
    }

    @Test
    public void verify_incrementCounter() throws OathVerificationException {
        int counter = settings.getCounter();
        hotpVerifier.verify("853971");
        assertThat(settings.getCounter()).isEqualTo(counter + 1);
    }
}
