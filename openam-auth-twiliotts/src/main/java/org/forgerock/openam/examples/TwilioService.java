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
 * $Id: TwilioTTS.java,v 1.1 2009/03/24 23:52:12 pluo Exp $
 *
 * Portions Copyrighted 2013-2016 ForgeRock AS.
 * Portions Copyrighted 2014-2015 Nomura Research Institute, Ltd.
 */

package org.forgerock.openam.examples;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;


/**
 * Provides the functionality to send OTP codes to a users Telephone and email.
 */
public class TwilioService {

    private static final Debug DEBUG = Debug.getInstance(TwilioTTS.amAuthTwilioTTS);

    // TODO : the moving factor should be retrieved from user's profile
    private static int movingFactor = 0;

    private final AMIdentityRepository amIdentityRepo;
    private final long codeValidityDuration;
    private String telephoneAttribute;
    private SecureRandom secureRandom;
    private final Map<?, ?> currentConfig;
    private final String userName;
    private final int codeLength;
    private final String fromPhone;
    private final String controlUrl;
  
    private String sentVOTPCode;
    private long sentVOTPCodeTime;
   
    private TwilioUtil twiUtil;
    
   
    /**
     * Constructs an instance of the TwilioService.
     *
     * @param amIdentityRepo An instance of the AMIdentityRepository.
     * @param userName The user's name.
     * @param TwilioTTSParams The authentication modules configuration settings.
     */
    public TwilioService(AMIdentityRepository amIdentityRepo, String userName, TwilioTTSParams TwilioTTSParams) {
    	DEBUG.message("TwilioService:init() 1");

        this.amIdentityRepo = amIdentityRepo;
        this.userName = userName;
        this.codeValidityDuration = TwilioTTSParams.getCodeValidityDuration();
        this.telephoneAttribute = TwilioTTSParams.getTelephoneLdapAttributeName();
        this.codeLength = TwilioTTSParams.getCodeLength();
        this.currentConfig = TwilioTTSParams.getConfig();
        this.fromPhone = TwilioTTSParams.getFromPhone();
        this.controlUrl = TwilioTTSParams.getControlUrl();
        
        twiUtil = new TwilioUtil(TwilioTTSParams.getAccountSid(),TwilioTTSParams.getTokenId());
        
        DEBUG.message("TwilioService:init() 2");

        
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            DEBUG.error("TwilioTTS.VOTP() : TwilioTTS : Initialization Failed", ex);
            secureRandom = null;
        }
    }

    /**
     * Sends a otp code to the users telephone number and/or email address, based on the authentication module's
     * configuration settings.
     *
     * @throws AuthLoginException If there is a problem sending the OTP code.
     */
    public void sendVOTP() throws AuthLoginException {
        try {
            sentVOTPCode = HOTPAlgorithm.generateOTP(getSharedSecret(), getMovingFactor(), codeLength, false, 16);
        } catch (NoSuchAlgorithmException e) {
            DEBUG.error("TwilioTTS.sendVOTPCode() : " + "no such algorithm", e);
            throw new AuthLoginException("amAuth", "noSuchAlgorithm", null);
        } catch (InvalidKeyException e) {
            DEBUG.error("TwilioTTS.sendVOTPCode() : " + "invalid key",e);
            throw new AuthLoginException("amAuth", "invalidKey", null);
        }
        sendVOTP(sentVOTPCode);
        sentVOTPCodeTime = System.currentTimeMillis();
    }

    private byte[] getSharedSecret() {
        return Long.toHexString(secureRandom.nextLong()).getBytes();
    }

    private int getMovingFactor() {
        return movingFactor++;
    }

    /**
     * Determines if the given OTP code matches the OTP code that was sent previously.
     *
     * @param enteredVOTPCode The OTP code to verify.
     * @return Whether the OTP code matches the OTP code that was sent to the user.
     */
    public boolean isValidVOTP(String enteredVOTPCode) {

        if (sentVOTPCode != null && sentVOTPCode.equals(enteredVOTPCode)) {
            long timePassed = System.currentTimeMillis() - sentVOTPCodeTime;
            if (timePassed <= (codeValidityDuration * 60000)) {
                // one time use only
                sentVOTPCode = null;
                return true;
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("TwilioTTS.process() : TwilioTTS code has expired");
                }
                return false;
            }
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("TwilioTTS.process() : TwilioTTS code is not valid");
            }
            return false;
        }
    }

    /**
     * Sends the otp code to a voice calling service
     *
     * @param otpCode The OTP code to send.
     * @throws AuthLoginException If there is a problem sending the OTP code.
     */
    private void sendVOTP(String otpCode) throws AuthLoginException {

        Exception cause = null;
        try {
            AMIdentity identity = getIdentity();
            if (identity == null) {
                throw new AuthLoginException("TwilioTTS.sendVOTP() : Unable to send OTP code "
                        + "because of error searching identities with username : " + userName);
            }

            String phone = getTelephoneNumber(identity);
         
            boolean delivered = false;
            if (phone != null) {
               // SMSGateway gateway = Class.forName(gatewaySMSImplClass).asSubclass(SMSGateway.class).newInstance();
                
            	//initiate twilio with an echo TWIMLET
            	////http://twimlets.com/echo?Twiml=%3CResponse%3E%3CSay%3EHi+there.%3C%2FSay%3E%3C%2FResponse%3E
            	///2010-04-01/Accounts/{AccountSid}/Calls
            	//post: from, to, url
            	
            	try {
                        if (phone != null) {
                            //gateway.sendVOTPMessage(from, phone, subject, message, otpCode, currentConfig);
                         
                            // twilio here!
                            twiUtil.outboundCall(fromPhone, phone, otpCode, controlUrl);
                            
                            delivered = true;
                        }
                    } catch (AuthLoginException ale) {
                        DEBUG.error("Error while sending TwilioTTS code to user", ale);
                        cause = ale;
                    }
                   
                    if (!delivered && cause != null) {
                        throw cause;
                    }
             
            } else {
                if (DEBUG.messageEnabled()) {
                    DEBUG.message("TwilioTTS.sendVOTP() : IdRepo: no phone or email found with username : " + userName);
                }
                throw new AuthLoginException("TwilioTTS.sendVOTP() : Unable to send OTP code "
                        + "because no phone or e-mail found for user: " + userName);
            }
        } catch (ClassNotFoundException ee) {
            DEBUG.error("TwilioTTS.sendVOTP() : " + "class not found SMSGateway class", ee);
            cause = ee;
        } catch (InstantiationException ie) {
            DEBUG.error("TwilioTTS.sendVOTP() : " + "can not instantiate SMSGateway class", ie);
            cause = ie;
        } catch (IdRepoException e) {
            DEBUG.error("TwilioTTS.sendVOTP() : error searching Identities with username : " + userName, e);
            cause = e;
        } catch (AuthLoginException e) {
            throw e;
        } catch (Exception e) {
            DEBUG.error("TwilioTTS.sendVOTP() : TwilioTTS module exception : ", e);
            cause = e;
        }
        if (cause != null) {
            throw new AuthLoginException("TwilioTTS.sendVOTP() : Unable to send OTP code", cause);
        }
    }

    private AMIdentity getIdentity() {
        AMIdentity amIdentity = null;
        IdSearchControl idsc = new IdSearchControl();
        idsc.setRecursive(true);
        idsc.setTimeOut(0);
        final Set<String> returnAttributes = getReturnAttributes();
        idsc.setReturnAttributes(returnAttributes);
        // search for the identity
        Set<AMIdentity> results = Collections.EMPTY_SET;
        idsc.setMaxResults(0);

        IdSearchResults searchResults;
        try {
            searchResults = amIdentityRepo.searchIdentities(IdType.USER, userName, idsc);
            

            if (searchResults != null) {
                results = searchResults.getSearchResults();
            }

            if (results.isEmpty()) {
                DEBUG.error("TwilioTTS:getIdentity : User " + userName + " is not found");
            } else if (results.size() > 1) {
                DEBUG.error("TwilioTTS:getIdentity : More than one user found for the userName " + userName);
            } else {
                amIdentity = results.iterator().next();
            }
        } catch (IdRepoException e) {
            DEBUG.error("TwilioTTS.getIdentity : Error searching Identities with username : " + userName, e);
        } catch (SSOException e) {
            DEBUG.error("TwilioTTS.getIdentity : Module exception : ", e);
        }
        return amIdentity;
    }

    /**
     * Gets the Telephone number of the user.
     *
     * @param identity The user's identity.
     * @return The user's telephone number.
     * @throws IdRepoException If there is a problem getting the user's telephone number.
     * @throws SSOException If there is a problem getting the user's telephone number.
     */
    private String getTelephoneNumber(AMIdentity identity) throws IdRepoException, SSOException {

        if (telephoneAttribute == null || telephoneAttribute.trim().length() == 0) {
            telephoneAttribute="telephoneNumber";
        }
        if (DEBUG.messageEnabled()) {
            DEBUG.message("TwilioTTS.sendVOTP() : Using phone attribute of " + telephoneAttribute);
        }
        Set telephoneNumbers = identity.getAttribute(telephoneAttribute);

        String phone = null;
        Iterator itor = null;
        if (telephoneNumbers != null && !telephoneNumbers.isEmpty()) {
            // use the first number in the set
            itor = telephoneNumbers.iterator();
            phone = (String) itor.next();
            
            if (DEBUG.messageEnabled()) {
                DEBUG.message("TwilioTTS.sendVOTP() : " + "IdRepoException : phone number found " + phone
                        + " with username : " + userName);
                    /*
                     * Log a message if the carrier is unknown.  The SMSGateway module is designed to use AT&T's SMS gateway
                     * as default.  Not sure why the product uses a default in this situation instead of simply not attempting 
                     * to send a text message but we don't want to break any existing installations so just log it for debug
                     * purposes.
                     * 
                     */
                if (!phone.contains("@")) {
                    DEBUG.message("TwilioTTS.sendVOTP() : No carrier detected - SMSGateway module will use default of "
                            + "@txt.att.net ");
                }
            }
        } else {
            if (DEBUG.messageEnabled()) {
                DEBUG.message("TwilioTTS.sendVOTP() : " + "IdRepoException : no phone number found with username : "
                        + userName);
            }
        }

        return phone;
    }
    
    /**
     * 
     * @return the attributes to be returned when querying the data store
     */
    private Set<String> getReturnAttributes() {
        Set<String> returnAttributes = new HashSet<String>(2);
     
        if ((telephoneAttribute != null) && (telephoneAttribute.trim().length() != 0)) {
            returnAttributes.add(telephoneAttribute);
        }
        
        return returnAttributes;
    }
}
