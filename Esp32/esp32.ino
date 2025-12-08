#include <Keypad.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

const byte ROWS = 4; 
const byte COLS = 4;
char hexaKeys[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};

byte rowPins[ROWS] = {13, 12, 14, 27}; 
byte colPins[COLS] = {26, 25, 33, 32};

Keypad customKeypad = Keypad(makeKeymap(hexaKeys), rowPins, colPins, ROWS, COLS); 

String inputBuffer = "";
const char* ssid = "Wokwi-GUEST";
const char* password = "";
const char* serverUrl = "https://cuddly-space-winner-455jx9wq9w525xwg-3000.app.github.dev/users";
const String SECRET_KEY = "0ORt3xlDbSOpiYOwUFw76IQglvHZeyGqaH4Ji3xvDVqUauC7eVTMullFVpixe6CV";

struct User {
  String user_code;
  String senha_hash;
  String hora_inicio;
  String hora_fim;
};

#define MAX_USERS 50
User Users[MAX_USERS];
int userCount = 0;

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

void downloadUserList(){
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Wi-Fi não conectado!");
        return false;
    }

    HTTPClient http;
    http.begin(serverUrl);
    int httpCode = http.GET();

    if (httpCode != 200) {
        Serial.print("Erro HTTP: ");
        Serial.println(httpCode);
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end();

    DynamicJsonDocument doc(8192);
    DeserializationError error = deserializeJson(doc, payload);
    if (error) {
        Serial.print("Erro ao parsear JSON: ");
        Serial.println(error.c_str());
        return false;
    }

    String hmacReceived = doc["hmac"];
    doc.remove("hmac");

    String jsonWithoutHMAC;
    serializeJson(doc, jsonWithoutHMAC);

    String hmacCalc = applyHMAC(jsonWithoutHMAC, SECRET_KEY);

    if (!hmacCalc.equalsIgnoreCase(hmacReceived)) {
        Serial.println("HMAC inválido! Lista descartada.");
        return false;
    }

    JsonArray arr = doc["users"].as<JsonArray>();
    userCount = 0;
    for (JsonObject userObj : arr) {
        if (userCount >= MAX_USERS) break;
        Users[userCount].user_code = String(userObj["user_code"].as<const char*>());
        Users[userCount].senha_hash = String(userObj["senha"].as<const char*>());
        Users[userCount].hora_inicio = String(userObj["hora_inicio"].as<const char*>());
        Users[userCount].hora_fim = String(userObj["hora_fim"].as<const char*>());
        userCount++;
    }

    Serial.print("Lista de usuários baixada. Total: ");
    Serial.println(userCount);
    return true;
}

bool validateUser(const String& id, const String& senha) {
  for (int i = 0; i < userCount; i++) {
    if (Users[i].user_code == id && Users[i].senha == senha) {
      return true;
    }
  }
  return false;
}

void setup(){
  Serial.begin(9600);
  WiFi.begin(ssid, password);
  Serial.print("Conectando ao Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado!");

  if (downloadUserList()) {
    Serial.println("Lista de usuários válida!");
  }
  Serial.println("Digite o ID + Senha:");
}

void loop(){
 char customKey = customKeypad.getKey();

  if (customKey) {
    if (customKey == 'A') {
      if (inputBuffer.length() == 12) {
        String userID = inputBuffer.substring(0, 8);
        String senha = inputBuffer.substring(8, 12);

        if (validateUser(userID, senha)) {
          Serial.println("Acesso permitido!");
        } else {
          Serial.println("Acesso negado!");
        }

      } else {
        Serial.println("Entrada inválida!");
      }
      inputBuffer = "";
    } else {
      inputBuffer += customKey;
      Serial.print(customKey);
    }
  }
}