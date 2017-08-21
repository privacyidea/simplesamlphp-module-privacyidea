<?php

$url = "https://localhost/pi/validate/check";

$params = array(
	"user" => "kölbel@ad",
	"pass" => "test"
);
$curl_instance = curl_init();
curl_setopt($curl_instance, CURLOPT_URL, $url);
curl_setopt($curl_instance, CURLOPT_HEADER, TRUE);
curl_setopt($curl_instance, CURLOPT_RETURNTRANSFER, TRUE);
curl_setopt($curl_instance,
CURLOPT_USERAGENT,'simpleSAMLphp/1.4');
// Add POST params
curl_setopt($curl_instance, CURLOPT_POST, 3);
curl_setopt($curl_instance, CURLOPT_POSTFIELDS, $params);
curl_setopt($curl_instance, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($curl_instance, CURLOPT_SSL_VERIFYPEER, 0);
$response = curl_exec($curl_instance);
$header_size = curl_getinfo($curl_instance,
	CURLINFO_HEADER_SIZE);
$body = json_decode(substr($response, $header_size));
print $response;

?>

