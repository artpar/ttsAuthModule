TwilioTTS ( Text To Speech ) Authentication Module for ForgeRock OpenAM
-------------------------------------------------------------------------

This is an experimental module to use the Twilio service to call users and read out their OTP's. This module has been based largely on the existing HOTP module.

https://www.twilio.com/

You can see a video demo on my blog: http://identity-implementation.blogspot.co.uk/2016/08/openam-text-to-speech-authentication.html

How to build and install:
-------------------------

Download or clone the repo.

Build with "mvn install".

Copy the build jar into the OpenAM WEB-INF/lib directory.

Register the module with OpenAM: 

- /usr/local/env/box/ssoadm/openam/bin/ssoadm create-svc -u amadmin --password-file /usr/local/env/box/ssoadm/openam/bin/passwd.txt --xmlfile src/main/resources/amAuthTwilioTTS.xml

- /usr/local/env/box/ssoadm/openam/bin/ssoadm register-auth-module -u amadmin --password-file /usr/local/env/box/ssoadm/openam/bin/passwd.txt --authmodule org.forgerock.openam.examples.TwilioTTS

Restart the OpenAM container.

Configure an authentication module with the following:

- Twilio Account Sid: Account Sid, can get this from Twilio dashboard.
- Twilio Token Id: Token Id, can get this from Twilio dashboard.
- Twilio Control URL: Should point to TwiML definition, can also use a Twimlet to dynamically generate TwiML e.g. http://twimlets.com/message?Message%5B0%5D=Hello%20Please%20enter%20the%20following%20one%20time%20code
- From Phone: Phone number Twilio will dial from, configurable in Twilio dashboard.

And authentication chain using the OpenAM admin console, for example,

- votpService = DataStore (REQUISITE) -> TwilioTTL (REQUIRED)
