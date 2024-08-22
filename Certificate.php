<?php

/**
 * criar certificado.pem
 *
 * @author   Ricardo Santana <ricaxavier@outlook.com.br>
 */
class Certificate {
  
  private $privateKey;
  private $publicKey;
  private $X509Certificate;
  private $key;
  private $passphrase;
  private $pkcs12;
  private $certDir;
  
  public function __construct($docXML = '', $Certificado, $CaminhoCertificado, $Senha) {
    
    error_reporting ( E_ALL );
    ini_set ( 'display_errors', 'On' );
    
    $this->ArquivoXml = $docXML;
    $this->passphrase = $Senha;
    $this->pkcs12 = $Certificado;
    $this->certDir = $CaminhoCertificado;
    
    $this->privateKey = $this->certDir . 'privatekey.pem';
    $this->publicKey  = $this->certDir . 'publickey.pem';
    $this->key        = $this->certDir . 'key.pem';
    
    if ($this->loadCert ()) {
      error_log ( __METHOD__ . ': Certificate is OK!' );
    } else {
      error_log ( __METHOD__ . ': Certificate is not OK!' );
    }
  }
  private function validateCert($cert) {
    $data = openssl_x509_read ( $cert );
    $certData = openssl_x509_parse ( $data );
    
    $certValidDate = gmmktime ( 0, 0, 0, substr ( $certData ['validTo'], 2, 2 ), substr ( $certData ['validTo'], 4, 2 ), substr ( $certData ['validTo'], 0, 2 ) );
    
    if ($certValidDate < time ()) {
      error_log ( __METHOD__ . ': Certificate expired in ' . date ( 'Y-m-d', $certValidDate ) );
      return false;
    }
    
    return true;
  }
  private function loadCert() {

    $x509CertData = array ();
    
    if (! openssl_pkcs12_read ( file_get_contents ( $this->pkcs12 ), $x509CertData, $this->passphrase )) {
      error_log ( __METHOD__ . ': Certificate cannot be read. File is corrupted or invalid format.' );
      
      return false;
    }
    
    $this->X509Certificate = preg_replace ( "/[\n]/", '', preg_replace ( '/\-\-\-\-\-[A-Z]+ CERTIFICATE\-\-\-\-\-/', '', $x509CertData ['cert'] ) );
    
    if (! self::validateCert ( $x509CertData ['cert'] )) {
      return false;
    }
    
    if (! is_dir ( $this->certDir )) {
      if (! mkdir ( $this->certDir, 0777 )) {
        error_log ( __METHOD__ . ': Cannot create folder ' . $this->certDir );
        return false;
      }
    }
    
    if (! file_exists ( $this->privateKey )) {
      if (! file_put_contents ( $this->privateKey, $x509CertData ['pkey'] )) {
        error_log ( __METHOD__ . ': Cannot create file ' . $this->privateKey );
        return false;
      }
    }
    
    if (! file_exists ( $this->publicKey )) {
      if (! file_put_contents ( $this->publicKey, $x509CertData ['cert'] )) {
        error_log ( __METHOD__ . ': Cannot create file ' . $this->publicKey );
        return false;
      }
    }
    
    if (! file_exists ( $this->key )) {
      if (! file_put_contents ( $this->key, $x509CertData ['cert'] . $x509CertData ['pkey'] )) {
        error_log ( __METHOD__ . ': Cannot create file ' . $this->key );
        return false;
      }
    }
    
    return true;
  }
}

