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

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

public class TotpVerifierTest extends PowerMockTestCase {

    @Mock
    OathVerifierNodeConfig configMock;

    private final OffsetDateTime now = OffsetDateTime.of(2019, 4, 1, 11, 59, 55, 0, ZoneOffset.UTC);
    private final OathDeviceSettings settings = new OathDeviceSettings();


    private TotpVerifier verifier;

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

        verifier = new TotpVerifier(configMock, settings, now.toEpochSecond());

        settings.setSharedSecret("abcd");
    }

    @Test
    public void verify_whenFirstLoginInWindow_thenSucceed() throws OathVerificationException {

        // Make sure last login is outside of the current time step
        settings.setLastLogin(now.minusSeconds(120).toEpochSecond(), TimeUnit.SECONDS);

        verifier.verify("433484");
        assertThat(settings.getClockDriftSeconds()).isEqualTo(0);
        // This is rounded down to the start of the window
        assertThat(settings.getLastLogin()).isEqualTo(now.withSecond(30).toEpochSecond());
    }

    @Test
    public void verify_whenSecondLoginInWindow_thenFail() {

        // The last login happened in the same step as this one
        settings.setLastLogin(now.minusSeconds(1).toEpochSecond(), TimeUnit.SECONDS);

        assertThatThrownBy(() -> verifier.verify("433484"))
                .isInstanceOf(OathVerificationException.class)
                .hasMessageStartingWith("Login failed attempting to use the same OTP in same Time Step: ");
    }

    @Test
    public void verify_whenClockHasDrifted_thenSuccessAndStoreDrift() throws OathVerificationException {
        settings.setLastLogin(now.minusSeconds(31).toEpochSecond(), TimeUnit.SECONDS);
        verifier.verify("394482");
        assertThat(settings.getClockDriftSeconds()).isEqualTo(30);
        assertThat(settings.getLastLogin()).isEqualTo(now.plusSeconds(5).toEpochSecond());
    }

    @Test
    public void verify_whenInvalidOtp_thenFail() {
        settings.setLastLogin(now.minusSeconds(31).toEpochSecond(), TimeUnit.SECONDS);
        assertThatThrownBy(() -> verifier.verify("x"))
                .isInstanceOf(OathVerificationException.class);

    }
}
