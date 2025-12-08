/*
 * Biblioteca de Funções Criptográficas para Sistemas Embarcados
 * 
 * Este arquivo contém implementações de funções básicas de criptografia
 * para uso em sistemas embarcados, especialmente em ESP32.
 * 
 * Algoritmos e Tamanhos de Chave:
 * - HMAC-SHA256: Chave de tamanho variável
 * - RSA: Suporta chaves de 1024, 2048 e 4096 bits
 * - AES-256: Chave de 256 bits (32 bytes)
 * - SHA-256: Hash de 256 bits (32 bytes)
 * 
 * Funcionalidades implementadas:
 * - HMAC-SHA256
 * - RSA (Encriptação com Chave Pública e Privada)
 * - Assinatura Digital RSA
 * - AES-256 (Modo CBC com PKCS7)
 * - Hash SHA-256
 * - Geração de Números Aleatórios
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

// Configurações de exemplo (substituir em produção)
const char* ssid = "your_SSID";
const char* password = "your_PASSWORD";
const char* serverName = "http://yourapi.com/endpoint";


// Exemplo de chave pública RSA (substituir pela sua)
const char* publicKeyPem = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n"
"-----END PUBLIC KEY-----\n";

// Exemplo de chave privada RSA (substituir pela sua)
const char* privateKeyPem = 
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEA...\n"
"-----END RSA PRIVATE KEY-----\n";


void setup() {
  Serial.begin(115200);
  Serial.println("\nBiblioteca de Funções Criptográficas - Exemplos\n");
}

/**
 * Aplica HMAC-SHA256 em uma mensagem
 * 
 * @param message Mensagem a ser autenticada
 * @return String Hash HMAC em formato hexadecimal
 * 
 * Exemplo de uso:
 * String mensagem = "Dados sensores";
 * String hmac = applyHMAC(mensagem);
*/
/**
 * Calcula o hash SHA-256 de uma mensagem
 * 
 * @param message Mensagem para calcular o hash
 * @return String Hash em formato hexadecimal (64 caracteres)
 * 
 * Exemplo de uso:
 * String mensagem = "Texto para hash";
 * String hash = calculateSHA256(mensagem);
*/
String calculateSHA256(const String& message) {
  unsigned char hash[32];
  mbedtls_sha256((const unsigned char*)message.c_str(), message.length(), hash, 0);

  String hashString;
  for (int i = 0; i < 32; i++) {
    char str[3];
    sprintf(str, "%02x", (int)hash[i]);
    hashString += str;
  }
  return hashString;
}

/**
 * Gera uma sequência de bytes aleatórios
 * 
 * @param length Quantidade de bytes aleatórios desejada
 * @return String Bytes aleatórios em formato hexadecimal
 * 
 * Exemplo de uso:
 * String randomBytes = generateRandomBytes(16); // 16 bytes aleatórios
*/
/**
 * Gera um par de chaves RSA
 * 
 * @param bits Tamanho da chave em bits (1024, 2048 ou 4096)
 * @return String Array com [0] chave privada e [1] chave pública em formato PEM
 * 
 * Exemplo de uso:
 * String* keyPair = generateRSAKeyPair(2048);
 * String privateKey = keyPair[0];
 * String publicKey = keyPair[1];
 * delete[] keyPair;
*/
String* generateRSAKeyPair(int bits) {
  mbedtls_pk_context key;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  String* keyPair = new String[2];

  mbedtls_pk_init(&key);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
    Serial.println("Falha na inicialização do gerador de números aleatórios");
    return keyPair;
  }

  if(mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
    Serial.println("Falha na configuração da chave RSA");
    return keyPair;
  }

  if(mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, bits, 65537) != 0) {
    Serial.println("Falha na geração das chaves");
    return keyPair;
  }

  unsigned char private_key[16000];
  unsigned char public_key[16000];
  size_t private_len = 0;
  size_t public_len = 0;

  if(mbedtls_pk_write_key_pem(&key, private_key, 16000) != 0) {
    Serial.println("Falha ao exportar chave privada");
    return keyPair;
  }
  private_len = strlen((char*)private_key);

  if(mbedtls_pk_write_pubkey_pem(&key, public_key, 16000) != 0) {
    Serial.println("Falha ao exportar chave pública");
    return keyPair;
  }
  public_len = strlen((char*)public_key);

  keyPair[0] = String((char*)private_key);
  keyPair[1] = String((char*)public_key);

  mbedtls_pk_free(&key);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return keyPair;
}

/**
 * Converte string hexadecimal para array de bytes
 * 
 * @param hexString String em formato hexadecimal
 * @return unsigned char* Array de bytes (precisa ser liberado após uso)
 * 
 * Exemplo de uso:
 * String hex = "48656C6C6F"; // "Hello" em hex
 * unsigned char* bytes = hexToBytes(hex);
 * // usar os bytes
 * delete[] bytes;
*/
unsigned char* hexToBytes(const String& hexString) {
  size_t len = hexString.length();
  if(len % 2 != 0) return NULL;
  
  size_t byteLen = len / 2;
  unsigned char* bytes = new unsigned char[byteLen];
  
  for(size_t i = 0; i < byteLen; i++) {
    String byteString = hexString.substring(i * 2, i * 2 + 2);
    bytes[i] = (unsigned char)strtol(byteString.c_str(), NULL, 16);
  }
  
  return bytes;
}

/**
 * Converte array de bytes para string hexadecimal
 * 
 * @param bytes Array de bytes para converter
 * @param len Tamanho do array de bytes
 * @return String String em formato hexadecimal
 * 
 * Exemplo de uso:
 * unsigned char bytes[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
 * String hex = bytesToHex(bytes, 5);
 */
String bytesToHex(const unsigned char* bytes, size_t len) {
  String hexString;
  for(size_t i = 0; i < len; i++) {
    char hex[3];
    sprintf(hex, "%02x", bytes[i]);
    hexString += hex;
  }
  return hexString;
}

/**
 * Codifica dados em Base64
 * 
 * @param data Dados para codificar
 * @param length Tamanho dos dados
 * @return String Dados codificados em Base64
 * 
 * Exemplo de uso:
 * String texto = "Olá, mundo!";
 * String base64 = base64Encode((unsigned char*)texto.c_str(), texto.length());
 */
String base64Encode(const unsigned char* data, size_t length) {
  size_t outputLength = 4 * ((length + 2) / 3);
  char* encoded = new char[outputLength + 1];
  
  const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  size_t i = 0, j = 0;
  while(i < length) {
    uint32_t octet_a = i < length ? data[i++] : 0;
    uint32_t octet_b = i < length ? data[i++] : 0;
    uint32_t octet_c = i < length ? data[i++] : 0;
    
    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
    
    encoded[j++] = base64Chars[(triple >> 18) & 0x3F];
    encoded[j++] = base64Chars[(triple >> 12) & 0x3F];
    encoded[j++] = base64Chars[(triple >> 6) & 0x3F];
    encoded[j++] = base64Chars[triple & 0x3F];
  }
  
  for(i = 0; i < (3 - length % 3) % 3; i++) {
    encoded[outputLength - 1 - i] = '=';
  }
  
  encoded[outputLength] = '\0';
  String result(encoded);
  delete[] encoded;
  return result;
}

/**
 * Decodifica dados de Base64
 * 
 * @param base64String String em formato Base64
 * @return String Dados decodificados
 * 
 * Exemplo de uso:
 * String base64 = "T2zDoSwgbXVuZG8h"; // "Olá, mundo!" em Base64
 * String texto = base64Decode(base64);
 */
String base64Decode(const String& base64String) {
  const char* data = base64String.c_str();
  size_t length = base64String.length();
  
  const char base64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char* decoded = new char[length * 3 / 4];
  
  size_t i = 0, j = 0;
  uint32_t sextet_a, sextet_b, sextet_c, sextet_d;
  uint32_t triple;
  
  while(i < length) {
    sextet_a = data[i] == '=' ? 0 : strchr(base64Chars, data[i]) - base64Chars;
    sextet_b = data[i+1] == '=' ? 0 : strchr(base64Chars, data[i+1]) - base64Chars;
    sextet_c = data[i+2] == '=' ? 0 : strchr(base64Chars, data[i+2]) - base64Chars;
    sextet_d = data[i+3] == '=' ? 0 : strchr(base64Chars, data[i+3]) - base64Chars;
    
    triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
    
    if(j < length * 3 / 4 - 1) decoded[j++] = (triple >> 16) & 0xFF;
    if(j < length * 3 / 4 - 1) decoded[j++] = (triple >> 8) & 0xFF;
    if(j < length * 3 / 4 - 1) decoded[j++] = triple & 0xFF;
    
    i += 4;
  }
  
  decoded[j] = '\0';
  String result(decoded);
  delete[] decoded;
  return result;
}

String generateRandomBytes(size_t length) {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  unsigned char* random_bytes = new unsigned char[length];

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  mbedtls_ctr_drbg_random(&ctr_drbg, random_bytes, length);

  String randomString;
  for (size_t i = 0; i < length; i++) {
    char str[3];
    sprintf(str, "%02x", random_bytes[i]);
    randomString += str;
  }

  delete[] random_bytes;
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return randomString;
}

/**
 * Aplica HMAC-SHA256 em uma mensagem com uma chave específica
 * 
 * @param message Mensagem a ser autenticada
 * @param key Chave para o HMAC
 * @return String Hash HMAC em formato hexadecimal (64 caracteres)
 * 
 * Exemplo de uso:
 * String mensagem = "Dados sensores";
 * String chave = "chave-secreta-hmac";
 * String hmac = applyHMAC(mensagem, chave);
 */
String applyHMAC(const String& message, const String& key) {
  unsigned char hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)message.c_str(), message.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hmacString;
  for (int i = 0; i < 32; i++) {
    char str[3];
    sprintf(str, "%02x", (int)hmacResult[i]);
    hmacString += str;
  }
  return hmacString;
}

/**
 * Encripta uma mensagem usando chave pública RSA
 * 
 * @param message Mensagem a ser encriptada
 * @param publicKeyPem Chave pública em formato PEM
 * @return String Mensagem encriptada em formato hexadecimal
 * 
 * Exemplo de uso:
 * String mensagem = "Mensagem secreta";
 * String dadosCifrados = encryptWithPublicKey(mensagem, publicKeyPem);
 */
String encryptWithPublicKey(const String& message, const char* publicKeyPem) {
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
   if (ret != 0) {
     char error_buf[100];
     mbedtls_strerror(ret, error_buf, 100);
     Serial.print("Failed to seed random number generator: ");
     Serial.println(error_buf);
     mbedtls_entropy_free(&entropy);
     mbedtls_ctr_drbg_free(&ctr_drbg);
     return "";
   }

   ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)publicKeyPem, strlen(publicKeyPem) + 1);
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    Serial.print("Failed to parse public key: ");
    Serial.println(error_buf);
    mbedtls_pk_free(&pk);
    return "";
  }

  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    Serial.println("Key is not an RSA key");
    mbedtls_pk_free(&pk);
    return "";
  }

  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
  size_t output_len = mbedtls_pk_get_len(&pk);
  unsigned char output[MBEDTLS_MPI_MAX_SIZE];

  ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, output_len, (const unsigned char*)message.c_str(), output);
  if (ret != 0) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    Serial.print("Encryption failed: ");
    Serial.println(error_buf);
    mbedtls_pk_free(&pk);
    return "";
  }

  // Convert encrypted data to base64 or hex string
  String encryptedString = "";
  for (size_t i = 0; i < output_len; i++) {
    char buf[3];
    sprintf(buf, "%02x", output[i]);
    encryptedString += buf;
  }

  mbedtls_pk_free(&pk);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  return encryptedString;
}

/**
 * Encripta uma mensagem usando chave privada RSA
 * 
 * @param message Mensagem a ser encriptada
 * @param privateKeyPem Chave privada em formato PEM
 * @return String Mensagem encriptada em formato hexadecimal
 * 
 * Exemplo de uso:
 * String mensagem = "Mensagem secreta";
 * String dadosCifrados = encryptWithPrivateKey(mensagem, privateKeyPem);
 */
String encryptWithPrivateKey(const String& message, const char* privateKeyPem) {
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  int ret = 1;

  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    Serial.println("Falha na inicialização do gerador de números aleatórios");
    return "";
  }

  ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)privateKeyPem, strlen(privateKeyPem) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.println("Falha ao carregar a chave privada");
    mbedtls_pk_free(&pk);
    return "";
  }

  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    Serial.println("A chave não é RSA");
    mbedtls_pk_free(&pk);
    return "";
  }

  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
  size_t output_len = mbedtls_pk_get_len(&pk);
  unsigned char output[MBEDTLS_MPI_MAX_SIZE];

  size_t olen;
  ret = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, &olen, (const unsigned char*)message.c_str(), output, output_len);
  if (ret != 0) {
    Serial.println("Falha na cifragem com chave privada");
    mbedtls_pk_free(&pk);
    return "";
  }

  String encryptedString = "";
  for (size_t i = 0; i < output_len; i++) {
    char buf[3];
    sprintf(buf, "%02x", output[i]);
    encryptedString += buf;
  }

  mbedtls_pk_free(&pk);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  return encryptedString;
}


/**
 * Cria uma assinatura digital RSA usando chave privada
 * 
 * @param message Mensagem para assinar
 * @param privateKeyPem Chave privada em formato PEM
 * @return String Assinatura em formato Base64
 * 
 * Exemplo de uso:
 * String mensagem = "Documento importante";
 * String assinatura = createDigitalSignature(mensagem, privateKeyPem);
 */
String createDigitalSignature(const String& message, const char* privateKeyPem) {
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  int ret = 1;

  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    Serial.println("Falha na inicialização do gerador de números aleatórios");
    return "";
  }

  ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)privateKeyPem, strlen(privateKeyPem) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.println("Falha ao carregar a chave privada");
    mbedtls_pk_free(&pk);
    return "";
  }

  unsigned char hash[32];
  mbedtls_sha256((const unsigned char*)message.c_str(), message.length(), hash, 0);

  unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
  size_t signature_len = 0;

  ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, MBEDTLS_MPI_MAX_SIZE, &signature_len, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.println("Falha ao criar assinatura digital");
    mbedtls_pk_free(&pk);
    return "";
  }

  String signatureString = "";
  for (size_t i = 0; i < signature_len; i++) {
    char buf[3];
    sprintf(buf, "%02x", signature[i]);
    signatureString += buf;
  }

  mbedtls_pk_free(&pk);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  return signatureString;
}

/**
 * Encripta uma mensagem usando AES-256 em modo CBC com padding PKCS7
 * 
 * @param message Mensagem a ser encriptada
 * @param key Chave AES-256 (32 bytes em formato string)
 * @param iv Vetor de Inicialização (16 bytes em formato string)
 * @return String Mensagem encriptada em formato hexadecimal
 * 
 * Exemplo de uso:
 * String mensagem = "Texto para cifrar";
 * String chaveAES = "0123456789abcdef0123456789abcdef"; // 32 bytes
 * String iv = "0123456789abcdef"; // 16 bytes
 * String textoCifrado = encryptAES(mensagem, chaveAES, iv);
 */
String encryptAES(const String& message, const String& key, const String& iv) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // Padding PKCS7
  int paddingLength = 16 - (message.length() % 16);
  String paddedMessage = message;
  for (int i = 0; i < paddingLength; i++) {
    paddedMessage += (char)paddingLength;
  }

  unsigned char output[paddedMessage.length()];
  mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key.c_str(), 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
                        paddedMessage.length(),
                        (unsigned char*)iv.c_str(),
                        (const unsigned char*)paddedMessage.c_str(),
                        output);

  String encryptedString = "";
  for (size_t i = 0; i < paddedMessage.length(); i++) {
    char buf[3];
    sprintf(buf, "%02x", output[i]);
    encryptedString += buf;
  }

  mbedtls_aes_free(&aes);
  return encryptedString;
}

/**
 * Decripta uma mensagem AES-256 em modo CBC com padding PKCS7
 * 
 * @param encryptedHex Mensagem cifrada em formato hexadecimal
 * @param key Chave AES-256 (32 bytes em formato string)
 * @param iv Vetor de Inicialização (16 bytes em formato string)
 * @return String Mensagem original decifrada
 * 
 * Exemplo de uso:
 * String textoCifrado = "...";
 * String chaveAES = "0123456789abcdef0123456789abcdef";
 * String iv = "0123456789abcdef";
 * String textoOriginal = decryptAES(textoCifrado, chaveAES, iv);
 */
/**
 * Verifica uma assinatura digital RSA usando chave pública
 * 
 * @param message Mensagem original
 * @param signature Assinatura em formato Base64
 * @param publicKeyPem Chave pública em formato PEM
 * @return bool true se a assinatura for válida, false caso contrário
 * 
 * Exemplo de uso:
 * String mensagem = "Documento importante";
 * String assinatura = "...assinatura em base64...";
 * bool valido = verifyRSASignature(mensagem, assinatura, publicKeyPem);
 */
bool verifyRSASignature(const String& message, const String& signature, const char* publicKeyPem) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  if(mbedtls_pk_parse_public_key(&pk, (const unsigned char*)publicKeyPem, strlen(publicKeyPem) + 1) != 0) {
    Serial.println("Erro ao carregar chave pública");
    mbedtls_pk_free(&pk);
    return false;
  }

  unsigned char hash[32];
  mbedtls_sha256((const unsigned char*)message.c_str(), message.length(), hash, 0);

  String decodedStr = base64Decode(signature);
  size_t signature_len = decodedStr.length();
  unsigned char decoded_signature[MBEDTLS_MPI_MAX_SIZE];
  memcpy(decoded_signature, decodedStr.c_str(), signature_len);

  int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                             hash, sizeof(hash),
                             decoded_signature, signature_len);

  mbedtls_pk_free(&pk);
  return ret == 0;
}

String decryptAES(const String& encryptedHex, const String& key, const String& iv) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // Converter hex para bytes
  int messageLen = encryptedHex.length() / 2;
  unsigned char encryptedData[messageLen];
  for (int i = 0; i < messageLen; i++) {
    sscanf(encryptedHex.substring(i * 2, i * 2 + 2).c_str(), "%02hhx", &encryptedData[i]);
  }

  unsigned char output[messageLen];
  mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key.c_str(), 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                        messageLen,
                        (unsigned char*)iv.c_str(),
                        encryptedData,
                        output);

  // Remover padding PKCS7
  int paddingLength = output[messageLen - 1];
  String decryptedString = "";
  for (int i = 0; i < messageLen - paddingLength; i++) {
    decryptedString += (char)output[i];
  }

  mbedtls_aes_free(&aes);
  return decryptedString;
}
void loop() {
  // Exemplo de geração de chaves RSA
  Serial.println("\n=== Gerando par de chaves RSA ===\n");
  String* keyPair = generateRSAKeyPair(2048);
  String privateKey = keyPair[0];
  String publicKey = keyPair[1];
  Serial.println("Chave Privada RSA:\n" + privateKey);
  Serial.println("Chave Pública RSA:\n" + publicKey);
  delete[] keyPair;

  // Exemplo de conversão Hex <-> Bytes
  Serial.println("\n=== Conversão Hex <-> Bytes ===\n");
  String textoOriginal = "Hello, World!";
  unsigned char* bytesTexto = (unsigned char*)textoOriginal.c_str();
  String hexTexto = bytesToHex(bytesTexto, textoOriginal.length());
  Serial.println("Texto para Hex: " + hexTexto);
  
  unsigned char* bytesConvertidos = hexToBytes(hexTexto);
  String textoConvertido((char*)bytesConvertidos);
  Serial.println("Hex para Texto: " + textoConvertido);
  delete[] bytesConvertidos;

  // Exemplo de codificação/decodificação Base64
  Serial.println("\n=== Codificação/Decodificação Base64 ===\n");
  String textoBase64 = "Olá, mundo!";
  String encoded = base64Encode((unsigned char*)textoBase64.c_str(), textoBase64.length());
  Serial.println("Texto para Base64: " + encoded);
  
  String decoded = base64Decode(encoded);
  Serial.println("Base64 para Texto: " + decoded);

  // Exemplos anteriores
  Serial.println("\n=== Funções Criptográficas ===\n");
  
  // HMAC-SHA256
  String mensagem = "Mensagem de teste";
  String chaveHmac = "chave-secreta-hmac";
  String hmac = applyHMAC(mensagem, chaveHmac);
  Serial.println("HMAC-SHA256: " + hmac);

  // Hash SHA-256
  String hash = calculateSHA256(mensagem);
  Serial.println("SHA-256: " + hash);

  // Geração de números aleatórios
  String randomBytes = generateRandomBytes(16);
  Serial.println("Bytes aleatórios (hex): " + randomBytes);

  // Criptografia RSA
  String mensagemRSA = "Texto para criptografar com RSA";
  String encryptedRSA = encryptWithPublicKey(mensagemRSA, publicKey.c_str());
  Serial.println("RSA Encriptado: " + encryptedRSA);

  // Assinatura digital
  String assinatura = createDigitalSignature(mensagemRSA, privateKey.c_str());
  Serial.println("Assinatura Digital: " + assinatura);

  // Verificação da assinatura
  bool verificado = verifyRSASignature(mensagemRSA, assinatura, publicKey.c_str());
  Serial.println("Verificação da Assinatura: " + String(verificado ? "Válida" : "Inválida"));

  // Criptografia AES
  String mensagemAES = "Texto para criptografar com AES";
  String chaveAES = "0123456789abcdef0123456789abcdef"; // Chave AES-256 (32 bytes)
  String iv = "0123456789abcdef"; // IV de 16 bytes
  
  String encryptedAES = encryptAES(mensagemAES, chaveAES, iv);
  Serial.println("AES Encriptado: " + encryptedAES);
  
  String decryptedAES = decryptAES(encryptedAES, chaveAES, iv);
  Serial.println("AES Decriptado: " + decryptedAES);

  delay(10000); // Aumentado para 10 segundos para melhor leitura
    // Nota de Segurança:
  // 1. Substitua as chaves de exemplo por chaves seguras em produção
  // 2. Nunca compartilhe chaves privadas
  // 3. Use IVs únicos para cada mensagem AES
  // 4. Mantenha as chaves e IVs em local seguro
     
      

    
  

  
}