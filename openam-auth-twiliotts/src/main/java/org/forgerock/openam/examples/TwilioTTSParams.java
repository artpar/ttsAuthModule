/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * $Id: HOTP.java,v 1.1 2009/03/24 23:52:12 pluo Exp $
 *
 */
/*
 * Portions Copyrighted 2013 ForgeRock AS
 */

package org.forgerock.openam.examples;

import java.util.Map;

/**
 * Class to hold the authentication modules HOTP configuration settings.
 */
public class TwilioTTSParams {

    private final long codeValidityDuration;
    private final int codeLength;
    private final String telephoneLdapAttributeName;
    private final Map<?, ?> config;
    private final String accountSid;
    private final String tokenId;
    private final String controlUrl;
    private final String fromPhone;
    
    public TwilioTTSParams(final long codeValidityDuration, final String telephoneLdapAttributeName, final Map<?, ?> config, int codeLength, String accountSid, String tokenId, String controlUrl, String fromPhone) {
        this.codeValidityDuration = codeValidityDuration;
        this.telephoneLdapAttributeName = telephoneLdapAttributeName;
        this.config = config;
        this.codeLength = codeLength;
        this.accountSid = accountSid;
        this.tokenId = tokenId;
        this.controlUrl = controlUrl;
        this.fromPhone = fromPhone;
    }    

   public long getCodeValidityDuration() {
        return codeValidityDuration;
    }

    public String getTelephoneLdapAttributeName() {
        return telephoneLdapAttributeName;
    }

    public Map<?, ?> getConfig() {
        return config;
    }
    
    public int getCodeLength() {
        return codeLength;
    }
    
    public String getAccountSid() {
        return accountSid;
    }
    
    public String getTokenId() {
        return tokenId;
    }
    
    public String getControlUrl() {
        return controlUrl;
    }
    
    public String getFromPhone() {
        return fromPhone;
    }

}
