package org.iotashan.oauth
{
	import com.hurlant.crypto.Crypto;
	import com.hurlant.crypto.hash.HMAC;
	import com.hurlant.util.Hex;
	
	import flash.utils.ByteArray;
	
	public class OAuthSignatureMethod_HMAC_SHA1 implements IOAuthSignatureMethod
	{
		public function OAuthSignatureMethod_HMAC_SHA1()
		{
		}
		
		public function get name():String {
			return "HMAC-SHA1";
		}
		
		public function signRequest(request:OAuthRequest):String {
			// get the signable string
			var toBeSigned:String = request.getSignableString();
			
			// get the secrets to encrypt with
			var aSec:Array = new Array();
			aSec.push(request.consumer.secret);
			if (request.token)
				aSec.push(request.token.secret);
			var sSec:String = aSec.join("&");
			
			// hash them
			var hmac:HMAC = Crypto.getHMAC("SHA-1");
			var key:ByteArray = Hex.toArray(Hex.fromString(sSec));
			var message:ByteArray = Hex.toArray(Hex.fromString(toBeSigned));
			var result:ByteArray = hmac.compute(key,message);
			
			return Hex.toString(Hex.fromArray(result));
		}
	}
}