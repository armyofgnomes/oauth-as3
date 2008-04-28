package org.iotashan.oauth
{
	import org.iotashan.utils.URLEncoding;
	
	public class OAuthSignatureMethod_PLAINTEXT implements IOAuthSignatureMethod
	{
		public function OAuthSignatureMethod_PLAINTEXT()
		{
		}
		
		public function get name():String {
			return "PLAINTEXT";
		}
		
		public function signRequest(request:OAuthRequest):String {
			var aSignature:Array = new Array();
			aSignature.push(URLEncoding.encode(request.consumer.secret));
			if (request.token)
				aSignature.push(URLEncoding.encode(request.token.secret));
			
			return aSignature.join("&");
		}
	}
}