<?php

/**
 * 
 * @author   Ricardo Santana <ricaxavier@outlook.com.br>
 */

include("Certificate.php");

//php_webservice_esocial

class ws_esocial {

    public function __construct() {
      error_reporting ( E_ALL );
      ini_set ( 'display_errors', 'On' );
    }

    public function consome( $xmlPost, $url, $cert_file, $cert_password, $soapaction = "") {

        $headers = array (
            "Content-type: text/xml;charset=\"utf-8\"",
            "Accept: text/xml",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "SOAPAction: " . $soapaction,
            "Content-length: " . strlen ( $xmlPost )
        ); // SOAPAction: your op URL

        $cerDir = "certificado/";

        ( new Certificate(null,$cert_file, $cerDir, $cert_password) );

        $ch = curl_init ();

        curl_setopt ( $ch, CURLOPT_POST, true );
        curl_setopt ( $ch, CURLOPT_POSTFIELDS, $xmlPost ); // the SOAP request

      $options = array (
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)',
            CURLOPT_URL => $url,
            CURLOPT_SSLCERT => $cerDir . "key.pem",
            CURLOPT_SSLCERTPASSWD => $cert_password
      );

        curl_setopt_array ( $ch, $options );

        $output = curl_exec ( $ch );

        if (! $output) {
            $output = "Curl Error : " . curl_errno($ch) ." - " .curl_error ( $ch );
        } else {
            $output = utf8_decode ( htmlspecialchars_decode ( $output ) );
        }

        curl_close($ch);

        echo $output;
    }
}
