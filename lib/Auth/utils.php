<?php
/**
 * The functions, which are needed in more than one class, are listed below.
 * @author Micha Preußer <micha.preusser@netknights.it>
 */
class sspmod_privacyidea_Auth_utils {


	/**
	 * @param $params
	 * All params, which are needed for the http request (e.g. user, pass, realm, etc.)
	 *
	 * @param $headers
	 * The headers for the http request (e.g. authentication token)
	 *
	 * @param $serverconfig
	 * The whole configuation for the server (e.g. url, verify host, verify peer)
	 *
	 * @param $api_endpoint
	 * This is the path for the request (e.g. /validate/samlcheck)
	 *
	 * @param $http_method
	 * Some requests need POST or GET method. This can be entered here.
	 *
	 * @return array
	 * We will return the JSON decoded body, because all the requests need different data.
	 *
	 * @throws SimpleSAML_Error_BadRequest
	 */
	public function curl($params, $headers, $serverconfig, $api_endpoint, $http_method) {
		$curl_instance = curl_init();
		$url = $serverconfig['privacyideaserver'] . $api_endpoint;

		curl_setopt($curl_instance, CURLOPT_URL, $url);
		curl_setopt($curl_instance, CURLOPT_HEADER, true);
		if ($headers != null) {
			curl_setopt($curl_instance, CURLOPT_HTTPHEADER, $headers);
		}
		curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl_instance, CURLOPT_USERAGENT, "simpleSAMLphp");

		if ($http_method === "POST") {
			curl_setopt($curl_instance, CURLOPT_POST, 3);
			curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);
		} elseif ($http_method === "GET") {
			$params_str = '?';
			foreach ($params as $key => $value) {
				$params_str .=$key . "=" . $value . "&";
			}
			curl_setopt($curl_instance, CURLOPT_URL, $url . $params_str);
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

	public function fetchAuthToken($serverconfig) {
		$params = array(
			"username" => $serverconfig['serviceAccount'],
			"password" => $serverconfig['servicePass'],
		);

		$body = self::curl($params, null, $serverconfig, "/auth", "POST");
		try {
			$result = $body->result;
			$value = $result->value;
			$token = $value->token;
		} catch (Exception $e) {
			throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
		}
		return $token;
	}

}
