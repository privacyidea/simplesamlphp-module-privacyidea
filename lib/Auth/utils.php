<?php
/**
 * The functions, which are needed in more than one class, are listed below.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */
class sspmod_privacyidea_Auth_utils {

	public function curl($params, $headers, $serverconfig, $url_ending, $method_post) {
		$curl_instance = curl_init();
		$url = $serverconfig['privacyideaserver'] . $url_ending;

		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_HEADER, true);
		if ($headers != null) {
			curl_setopt($curl_instance, CURLOPT_HTTPHEADER, $headers);
		}
		curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp");

		if ($method_post) {
			curl_setopt($curl_instance, CURLOPT_POST, 3);
			curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);
		}
		if ($serverconfig['sslverifyhost']) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 2);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
		}

		if ($serverconfig['sslverifypeer']) {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 2);
		} else {
			curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
		}

		if (!$response = curl_exec($curl_instance)) {
			throw new SimpleSAML_Error_BadRequest("privacyIDEA: Bad request to PI server: " . curl_error($curl_instance));
		}
		$header_size = curl_getinfo($curl_instance, CURLINFO_HEADER_SIZE);
		$body = json_decode(substr($response, $header_size));
		return $body;
	}

}
