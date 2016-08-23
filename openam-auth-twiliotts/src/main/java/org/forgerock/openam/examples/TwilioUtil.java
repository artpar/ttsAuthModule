package org.forgerock.openam.examples;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import javax.xml.bind.DatatypeConverter;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.debug.Debug;

public class TwilioUtil {

	protected static final Debug debug = Debug.getInstance(TwilioUtil.class.getName());

	private String accountSid; //ACb03fc9d110e1045b9e37df53c23a6266
	private String tokenId; //a752681c48f801bb40ab5862f8dcf567

	public TwilioUtil(String accountSid, String tokenId) {
		this.accountSid = accountSid;
		this.tokenId = tokenId;
	}

	public String outboundCall(String fromPhoneNo, String toPhoneNo, String code, String controlUrl) throws AuthLoginException {
		String json = "";
		try {
			URL url = new URL("https://api.twilio.com/2010-04-01/Accounts/" + accountSid + "/Calls");

			debug.message("TwilioUtil.outboundCall: url : " + url);
			
			debug.message("TwilioUtil.outboundCall: fromPhoneNo : " + fromPhoneNo);		
			
			debug.message("TwilioUtil.outboundCall: telephoneNo : " + toPhoneNo);
			
			debug.message("TwilioUtil.outboundCall: code : " + code);
			
			debug.message("TwilioUtil.outboundCall: controlurl : " + controlUrl);

			
			String auth = accountSid + ":" + tokenId;
			byte[] message = auth.getBytes("UTF-8");
			String encoded = DatatypeConverter.printBase64Binary(message);

			// encode code for speech
			//%201%202%203%204
			String slowCode = slowCode(code);	
			debug.message("TwilioUtil.outboundCall: slowCode : " + slowCode);

			// for each digit in code, build string
				
			String charset = "UTF-8"; // Or in Java 7 and later, use the
										// constant:
										// java.nio.charset.StandardCharsets.UTF_8.name()
			String param1 = fromPhoneNo; //+441412803033
			String param2 = toPhoneNo;
			String param3 = controlUrl + "%20" + slowCode;
			//http://twimlets.com/message?Message%5B0%5D=Please%20enter%20the%20following%20code
			
			String query = String.format("From=%s&To=%s&Url=%s", URLEncoder.encode(param1, charset),
					URLEncoder.encode(param2, charset), URLEncoder.encode(param3, charset));

			debug.message("TwilioUtil.outboundCall(): Query: " + query);

			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setDoInput(true); // POST.
			conn.setDoOutput(true); // POST.
			conn.setRequestMethod("POST");
			conn.setRequestProperty("Authorization", "Basic " + encoded);
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);

			DataOutputStream output = new DataOutputStream(conn.getOutputStream());
			output.writeBytes(query);
			output.close();

			if (conn.getResponseCode() == 200 || conn.getResponseCode() == 201) {
				debug.message("TwilioUtil.outboundCall(): HTTP failed, response code:" + conn.getResponseCode());

				BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				
				in.close();
				debug.message("TwilioUtil.outboundCall(): HTTP failed, response:" + response);
			} else {
				debug.message("TwilioUtil.outboundCall(): HTTP failed, response code:" + conn.getResponseCode());

				BufferedReader in = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
				debug.message("TwilioUtil.outboundCall(): HTTP failed, response:" + response);
				throw new RuntimeException("TwilioUtil : HTTP error code : " + conn.getResponseCode());
			}

			conn.disconnect();
		} catch (Exception e) {
			  throw new AuthLoginException("Failed to send OTP code to " + toPhoneNo, e);
		}
		return json;
	}
	
	/***
	 * Take code and return in a format that Twilio will read slowly.. i.e. 1... 2... 3... 4....
	 * @return
	 */
	private String slowCode(String code) {
		String slowCode = "";
		
		// for each character
		
		char[] chars = code.toCharArray();
		for (int i = 0, n = chars.length; i < n; i++) {
		    char c = chars[i];
		    
		    //slowCode = slowCode.concat("%20%20%20%20" + c);
		    slowCode = slowCode.concat("%20%2C%20%2C%20%2C" + c);
		}
		
		
		return slowCode;
	}

	public static void main(String[] args) {

//		TwilioUtil tutil = new TwilioUtil();
//		try {
//			tutil.outboundCall("+447796247626", "1234");
//		} catch (AuthLoginException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

	}

}
