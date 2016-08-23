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
 * Portions Copyrighted 2012-2015 ForgeRock AS.
 * Portions Copyrighted 2014 Nomura Research Institute, Ltd
 */

package org.forgerock.openam.examples;

import com.iplanet.dpro.session.service.InternalSession;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.authentication.service.AMAuthErrorCode;
import com.sun.identity.authentication.spi.AuthErrorCodeException;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.PasswordCallback;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

public class TwilioTTS extends AMLoginModule {

	private final static String DEBUG_NAME = "amAuthTwilioTTS";
	private final static Debug debug = Debug.getInstance(DEBUG_NAME);
    protected static final String amAuthTwilioTTS = "amAuthTwilioTTS";
    ResourceBundle bundle = null;

    private String userName = null;
    private String userUUID = null;
    private int currentState;
    private Map sharedState;
    public Map currentConfig;
    protected Principal userPrincipal;

    private String enteredTTTSCode = null;

    // Module specific properties
    private static final String CODEVALIDITYDURATION = "iplanet-am-auth-twiliotts-validity-duration";
    private static final String CODELENGTH = "iplanet-am-auth-twiliotts-password-length";
    private static final String AUTHLEVEL = "iplanet-am-auth-twiliotts-auth-level";
    private static final String ATTRIBUTEPHONE = "openamTelephoneAttribute";
    private static final String AUTO_CLICKING = "iplanet-am-auth-twiliotts-auto-clicking";
    private static final String ACCOUNT_SID = "iplanet-am-auth-twiliotts-account-sid";
    private static final String TOKENID = "iplanet-am-auth-twiliotts-tokenid";
    private static final String CONTROLURL = "iplanet-am-auth-twiliotts-url";
    private static final String FROM_PHONE = "iplanet-am-auth-twiliotts-from";
    
    private static final String SKIP_TWILIOTTS = "skipTwilioTTS";
    
    private String codeValidityDuration = null;
    private String codeLength = null;
    private String telephoneAttribute = null;
    private String fromPhone = null;
    private String controlUrl = null;
    private String accountSid = null;
    private String tokenId = null;
    private boolean skip = false;
    private boolean TTTSAutoClicking = false;

    private int START_STATE = 2;

    private TwilioService TwilioService;
    
    private Set<String> userSearchAttributes = Collections.emptySet();

    public void init(Subject subject, Map sharedState, Map options) {
    	try {
    	
    	debug.message("TwilioTTS:init()");
    	
        currentConfig = options;
        String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);
        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("TwilioTTS.init() : " + "Unable to set auth level " + authLevel, e);
            }
        }

        debug.message("TwilioTTS:init() 1");
        
        codeValidityDuration = CollectionHelper.getMapAttr(options,
        		CODEVALIDITYDURATION);
        codeLength = CollectionHelper.getMapAttr(options, CODELENGTH);

        telephoneAttribute = CollectionHelper.getMapAttr(options, ATTRIBUTEPHONE);
        
        accountSid = CollectionHelper.getMapAttr(options, ACCOUNT_SID);
        tokenId = CollectionHelper.getMapAttr(options, TOKENID);
        controlUrl = CollectionHelper.getMapAttr(options, CONTROLURL);
        fromPhone = CollectionHelper.getMapAttr(options, FROM_PHONE);
           
        if (debug.messageEnabled()) {
            debug.message("TwilioTTS.init() : " + "telephone attribute=" + telephoneAttribute);
        }

        debug.message("TwilioTTS:init() 2");
        
        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(amAuthTwilioTTS, locale);
        if (debug.messageEnabled()) {
            debug.message("TwilioTTS.init() : " + "TwilioTTS resouce bundle locale=" + locale);
        }

        userName = (String) sharedState.get(getUserKey());
        
        debug.message("TwilioTTS:init() userName:" + userName);
        
        if (userName == null || userName.isEmpty()) {
            try {
                //Session upgrade case. Need to find the user ID from the old session.
                SSOTokenManager mgr = SSOTokenManager.getInstance();
                InternalSession isess = getLoginState("TwilioTTS").getOldSession();
                if (isess == null) {
                    throw new AuthLoginException("amAuth", "noInternalSession", null);
                }
                SSOToken token = mgr.createSSOToken(isess.getID().toString());
                userUUID = token.getPrincipal().getName();
                userName = token.getProperty("UserToken");
                if (debug.messageEnabled()) {
                    debug.message("TwilioTTS.init() : UserName in SSOToken : " + userName);
                }
            } catch (SSOException ssoe) {
                debug.error("TwilioTTS.init() : Unable to retrieve userName from existing session", ssoe);
            } catch (AuthLoginException ale) {
                debug.error("TwilioTTS.init() : Unable to retrieve userName from existing session", ale);
            }
        }
        this.sharedState = sharedState;
        
        debug.message("TwilioTTS:init() 3");

        if (sharedState.containsKey(SKIP_TWILIOTTS)) {
            skip = (Boolean) sharedState.get(SKIP_TWILIOTTS);
        }
        
        debug.message("TwilioTTS:init() 4");

      
        TTTSAutoClicking = CollectionHelper.getMapAttr(options, AUTO_CLICKING).equals("true");
        
        TwilioTTSParams TwilioTTSParams = new TwilioTTSParams(Long.parseLong(codeValidityDuration),
                telephoneAttribute, currentConfig,Integer.parseInt(codeLength),accountSid,tokenId,controlUrl,fromPhone);
        
        debug.message("TwilioTTS:init() 5");

        TwilioService = new TwilioService(getAMIdentityRepository(getRequestOrg()), userName, TwilioTTSParams);
        
        debug.message("TwilioTTS:init() 6");
        
    	} catch (Exception e) {
    		debug.error("Error initialising TwilioTTS:", e);
    	}

    }

    public int process(Callback[] callbacks, int state) throws AuthLoginException {
    	
    	debug.message("TwilioTTS:processs(): state " + state );
    	
        if (skip) {
            debug.message("Skipping TwilioTTS module");
            return ISAuthConstants.LOGIN_SUCCEED;
        }
        
        if (userName == null || userName.length() == 0) {
            throw new AuthLoginException("amAuth", "noUserName", null);
        }

        if (state == 1) {
            if(TTTSAutoClicking) {
                debug.message("Auto sending OTP code");
                try {
                    TwilioService.sendVOTP();
                    // change message in UI
                    substituteHeader(START_STATE, bundle.getString("send.success"));
                } catch (AuthLoginException ale) {
                    throw new AuthErrorCodeException(AMAuthErrorCode.AUTH_ERROR, amAuthTwilioTTS, "send.failure");
                }
            }
            return START_STATE;
        }
        
        currentState = state;
        int action = 0;
        try {    
            if (currentState == START_STATE) {
                // callback[0] is OTP code
                // callback[1] is user selected button index
                // action = 0 is Submit TwilioTTS Code Button
                // action = 1 is Request TwilioTTS Code Button
                if (callbacks != null && callbacks.length == 2) {
                	// expects two callbacks
                    action =
                        ((ConfirmationCallback)
                        callbacks[1]).getSelectedIndex();
                    	// figure out which one was used ( submit code OR request new code)
                    if (debug.messageEnabled()) {
                        debug.message("TwilioTTS.process() : " + "LOGIN page button index: " + action);
                    }

                    if (action == 0) { //Submit TwilioTTS Code
                        enteredTTTSCode = String.valueOf(((PasswordCallback) callbacks[0]).getPassword());
                        if (enteredTTTSCode == null || enteredTTTSCode.length() == 0) {
                            if (debug.messageEnabled()) {
                                debug.message("TwilioTTS.process() : " + "invalid TwilioTTS code");
                            }
                            setFailureID(userName); 
                            throw new InvalidPasswordException("amAuth", "invalidPasswd", null);
                        }

                        // Enforce the code validate time TwilioTTS module config
                        if (TwilioService.isValidVOTP(enteredTTTSCode)) {
                            return ISAuthConstants.LOGIN_SUCCEED;
                        } else {
                            setFailureID(userName);
                            throw new InvalidPasswordException("amAuth", "invalidPasswd", null);
                        }
                    } else { // Send TwilioTTS Code
                    	// resend was pressed
                        try {
                            TwilioService.sendVOTP();
                            substituteHeader(START_STATE, bundle.getString("send.success"));
                        } catch (AuthLoginException ale) {
                            throw new AuthErrorCodeException(AMAuthErrorCode.AUTH_ERROR, amAuthTwilioTTS, "send.failure");
                        }
                        return START_STATE;
                    }
                } else {
                    setFailureID(userName);
                    throw new AuthLoginException(amAuthTwilioTTS, "authFailed", null);
                }

            } else {
                setFailureID(userName);
                throw new AuthLoginException(amAuthTwilioTTS, "authFailed", null);
            }
        } catch (NumberFormatException ex) {
            debug.error("TwilioTTS.process() : NumberFormatException Exception", ex);
            if (userName != null && userName.length() != 0) {
                setFailureID(userName);
            }
            throw new AuthLoginException(amAuthTwilioTTS, "authFailed", null, ex);
        }
    }

    public java.security.Principal getPrincipal() {
        if (userUUID != null) {
            userPrincipal = new TwilioTTSPrincipal(userUUID);
            return userPrincipal;
        } else if (userName != null) {
            userPrincipal = new TwilioTTSPrincipal(userName);
            return userPrincipal;
        } else {
            return null;
        }
    }

    // cleanup state fields
    public void destroyModuleState() {
        nullifyUsedVars();
    }

    public void nullifyUsedVars() {
        bundle = null;
        userName = null;
        sharedState = null;
        currentConfig = null;
        enteredTTTSCode = null;
        userSearchAttributes = Collections.emptySet();
    }
}
