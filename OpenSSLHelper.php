<?php
namespace App\OpenSSL;

use Log;
use Config;
use Exception;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\ProcessBuilder;
use Symfony\Component\Process\Exception as ProcessException;

use App\Filesystem\StorageManager;

/**
* Facade OpenSSL functions
*/
class OpenSSLHelper
{
  
  /**
   * @const string File extension for encrypted file
   */
  const ENCRYPTED_FILE_EXTENSION = "pkcs7";

  /**
   * @const string constants with full path to PEM certificate
   */
  const CONFIG_PATH_FILE_PEM = 'constants.MAIL_TL_PKCS7_PEM';

  /**
   * @const string Set cipher in param
   */
  const CIPHER_AES_128_CBC = '-aes-128-cbc';

  /**
   * @const int Maximum time for compleate task
   */
  const TASK_TIMEOUT_SEC = 2;
  
  /**
   * @var string File name to public key
   */
  private $pkcs7_pem_file;
  
  private $filename;
  private $storagefolder;

  public function __construct($filename, $storagefolder) {
    $this->pkcs7_pem_file = Config::Get(self::CONFIG_PATH_FILE_PEM);
    $this->filename = $filename;
    $this->storagefolder = $storagefolder;
  }

  private function getStoragefilenameByName($filename) {
    return  $this->storagefolder . '/' . $filename;
  }

  private function getStoragefilename() {
    return $this->getStoragefilenameByName($this->filename);
  }

  private function getStoragefilenameEncrypted() {
    return $this->getStoragefilenameByName($this->addEncryptedExtension($this->filename));
  }

  private function addEncryptedExtension($filename) {
    return $filename . '.' . self::ENCRYPTED_FILE_EXTENSION;
  }

  /**
  *   Encrypt file.
  *  
  *   Accoding to "7.2.2 Technical modality of encryption" (CORPS et Annexes v7.20 CDC1.40-Add7.pdf)
  * The encryption of a document has the following characteristics (based on RFC 56523 - PKCS # 7)
  * Ex: "openssl cms -encrypt -in NomDuFichierAChiffrer –binary –aes-128-cbc -outform der -out NomDuFichierAChiffrer.pkcs7 Certificat.pem"
  * 
  *  Use execute process instead of openssl library, because function openssl_pkcs7_encrypt cannot parameter "-outform der".
  *  @return Encrypted filename if success. And NULL - if fail.
  */
  private function encrypt($extra_param) {
    if (!StorageManager::Exists($this->getStoragefilename())) {
      Log::Warning('File "' . $this->getStoragefilename() . '" not found');
      return ;
    }

    $fullfilename_src = StorageManager::GetStorageAbsoluteFilename($this->getStoragefilename());
    $fullfilename_dest = $this->addEncryptedExtension($fullfilename_src);
    $openssl_path = Config::Get('constants.OPENSSL_PATH');
    $openssl_path = !empty($openssl_path) ? $openssl_path : 'openssl';
    $smtp_flow = $extra_param['smtp_flow'];
    $smtp_transmission = $extra_param['smtp_transmission'];
    $file_type = $extra_param['file_type'];

    #get all certificate here 
    $MAIL_TL_PKCS7_FSE_PEM_REAL = Config::Get('constants.MAIL_TL_PKCS7_FSE_PEM_REAL');
    $MAIL_TL_PKCS7_DRE_PEM_REAL = Config::Get('constants.MAIL_TL_PKCS7_DRE_PEM_REAL');
    $MAIL_TL_PKCS7_CESI_PEM_REAL = Config::Get('constants.MAIL_TL_PKCS7_CESI_PEM_REAL');
    $MAIL_TL_PKCS7_OCT_PEM_REAL = Config::Get('constants.MAIL_TL_PKCS7_OCT_PEM_REAL');

    $MAIL_TL_PKCS7_FSE_PEM_TEST = Config::Get('constants.MAIL_TL_PKCS7_FSE_PEM_TEST');
    $MAIL_TL_PKCS7_DRE_PEM_TEST = Config::Get('constants.MAIL_TL_PKCS7_DRE_PEM_TEST');
    $MAIL_TL_PKCS7_CESI_PEM_TEST = Config::Get('constants.MAIL_TL_PKCS7_CESI_PEM_TEST');
    $MAIL_TL_PKCS7_OCT_PEM_TEST = Config::Get('constants.MAIL_TL_PKCS7_OCT_PEM_TEST');

    #check admin selected flow
    if($smtp_flow == "real"){
        if($file_type == "FSE"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_FSE_PEM_REAL;
        }else if($file_type == "DRE"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_DRE_PEM_REAL;
        }
        if($smtp_transmission == "oct"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_OCT_PEM_REAL;
        }
        if($smtp_transmission == "cesi"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_CESI_PEM_REAL;
        }
    }else{
        if($file_type == "FSE"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_FSE_PEM_TEST;
        }else if($file_type == "DRE"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_DRE_PEM_TEST;
        }
        if($smtp_transmission == "oct"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_OCT_PEM_TEST;
        }
        if($smtp_transmission == "cesi"){
          $pkcs7_pem_file = $MAIL_TL_PKCS7_CESI_PEM_TEST;
        }
    }  

    $processBuilder = new ProcessBuilder(array(
      $openssl_path,
      'cms',
      '-encrypt',
      '-in', $fullfilename_src,
      '-binary',
      self::CIPHER_AES_128_CBC,
      '-outform', 'der',
      '-out', $fullfilename_dest,
      $pkcs7_pem_file
    ));
    
    $process = $processBuilder->getProcess();
    $process->setTimeout(self::TASK_TIMEOUT_SEC);

    try {
      $process->mustRun();
    } catch (ProcessException\RuntimeException $exception) {
      Log::Warning('Error encrypting: '.$exception->getMessage());
      return ;
    }

    if (!StorageManager::Exists($this->getStoragefilenameEncrypted())) {
      Log::Warning('Miss encrypted file "' . $this->getStoragefilenameEncrypted() . '" in storage');
      return ;
    }

    return $fullfilename_dest;
  }

  /**
  *  Encrypt file and save result to file with new extension
  *
  * @param filename File name in special storage folder.
  * @param storagefolder Folder.
  * @return Encrypted file name. Absolute path. Null - if fail.
  */
  public static function DoEncrypt($filename, $storagefolder,$extra_param) {
    $openssl = new OpenSSLHelper($filename, $storagefolder);

    $filename_encrypted = '';

    try {
      $filename_encrypted = $openssl->encrypt($extra_param);
    } catch (Exception $e) {
      Log::Error('Unexpected error in encrypting: ' . $e->getMessage());
    }    
    
    return $filename_encrypted;
  }
}
