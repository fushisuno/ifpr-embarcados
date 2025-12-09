#include <Keypad.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <time.h> 
#include <WiFiClientSecure.h>

const int LED_VERDE = 2;
const int LED_VERMELHO = 4;

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

const char* ssid = "Wokwi-GUEST";
const char* password = "";

const char* serverUrl = "https://cuddly-space-winner-455jx9wq9w525xwg-3000.app.github.dev/users";
const char* logsUrl = "https://cuddly-space-winner-455jx9wq9w525xwg-3000.app.github.dev/logs";

// Chave HMAC
const String SECRET_KEY = "0ORt3xlDbSOpiYOwUFw76IQglvHZeyGqaH4Ji3xvDVqUauC7eVTMullFVpixe6CV"; 

const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = -3 * 3600;
const int   daylightOffset_sec = 0;

struct User {
    String user_code;
    String senha_hash;
    String hora_inicio;
    String hora_fim;
};

#define MAX_USERS 50
User Users[MAX_USERS];
int userCount = 0;
String inputBuffer = "";

unsigned long lastDownloadTime = 0;
const long downloadInterval = 60 * 60 * 1000;

String applySHA256(const String& message) {
    char outputBuffer[65];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); 
    mbedtls_sha256_update(&ctx, (const unsigned char*)message.c_str(), message.length());
    
    unsigned char hash[32];
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    for(int i = 0; i < 32; i++){
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    return String(outputBuffer);
}

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

void setupNTP() {
    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    Serial.println("NTP configurado.");
}

bool downloadUserList() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Wi-Fi não conectado. Falha ao baixar lista.");
        return false;
    }

    WiFiClientSecure client;
    client.setInsecure(); 
    
    HTTPClient http;
    http.begin(client, serverUrl); 

    int httpCode = http.GET();

    if (httpCode != 200) {
        Serial.printf("Erro HTTP ao baixar lista: %d\n", httpCode);
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, payload);
    
    if (error) {
        Serial.printf("Erro ao parsear JSON da lista: %s\n", error.c_str());
        return false;
    }

    String hmacReceived = doc["hmac"];
    JsonArray arr = doc["list"].as<JsonArray>();

    String jsonArrayString;
    serializeJson(arr, jsonArrayString);

    String hmacCalc = applyHMAC(jsonArrayString, SECRET_KEY);

    if (!hmacCalc.equalsIgnoreCase(hmacReceived)) {
        Serial.println("HMAC inválido! Lista descartada por segurança.");
        return false;
    }

    userCount = 0;
    for (JsonObject userObj : arr) {
        if (userCount >= MAX_USERS) break;
        Users[userCount].user_code = String(userObj["user_code"].as<const char*>());
        Users[userCount].senha_hash = String(userObj["senha_hash"].as<const char*>()); 
        Users[userCount].hora_inicio = String(userObj["hora_inicio"].as<const char*>());
        Users[userCount].hora_fim = String(userObj["hora_fim"].as<const char*>());
        userCount++;
    }

    Serial.printf("Lista de usuários baixada e verificada com sucesso. Total: %d\n", userCount);
    lastDownloadTime = millis();
    return true;
}

bool sendLogToServer(String userID, String motivo, bool permitido) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("Sem Wi-Fi. Log não enviado.");
        return false;
    }

    JsonDocument logDoc;
    JsonArray logs = logDoc["logs"].to<JsonArray>();
    JsonObject entry = logs.add<JsonObject>();

    time_t now;
    struct tm timeinfo;
    getLocalTime(&timeinfo);

    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    entry["user_code"] = userID;
    entry["motivo"] = motivo;
    entry["status"] = permitido ? "PERMITIDO" : "NEGADO";
    entry["timestamp"] = timestamp;

    String logsString;
    serializeJson(logs, logsString);

    String hmac = applyHMAC(logsString, SECRET_KEY);

    JsonDocument finalDoc;
    finalDoc["logs"] = logs;
    finalDoc["hmac"] = hmac;

    String output;
    serializeJson(finalDoc, output);

    Serial.println("[LOG DEBUG] Enviando log:");

    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;
    http.begin(client, logsUrl);
    http.addHeader("Content-Type", "application/json");

    int httpCode = http.POST(output);

    if (httpCode == 200) {
        Serial.println("[LOG DEBUG] Log enviado!");
        http.end();
        return true;
    }

    Serial.printf("[LOG DEBUG] Falha ao enviar log: %d\n", httpCode);
    http.end();
    return false;
}

bool validateUser(const String& id, const String& senha) {
    String input_hash = applySHA256(senha); 
    String access_reason = "Credenciais inválidas."; 

    for (int i = 0; i < userCount; i++) {
        if (Users[i].user_code == id) {

            if (Users[i].senha_hash == input_hash) {

                time_t now;
                struct tm timeinfo;

                if (!getLocalTime(&timeinfo)) {
                    Serial.println("Falha ao obter o tempo NTP. Permissão ignorada.");
                    return true; 
                }

                char currentTimeStr[6];
                strftime(currentTimeStr, 6, "%H:%M", &timeinfo);
                String current = String(currentTimeStr);

                String start = Users[i].hora_inicio;
                String end   = Users[i].hora_fim;

                bool permitted;

                if (start <= end) {
                    permitted = (current >= start && current <= end);
                } else {
                    permitted = (current >= start || current <= end);
                }

                if (permitted) {
                    return true;
                } else {
                    access_reason = "Fora do horário permitido. Horário permitido: " 
                                    + start + " até " + end;
                }

            } else {
                access_reason = "Senha incorreta.";
            }
            Serial.println(" ");
            Serial.printf("Acesso negado para ID %s. Motivo: %s\n",
                          id.c_str(), access_reason.c_str());

            return false;
        }
    }

    Serial.printf("Acesso negado. ID %s não encontrado.\n", id.c_str());
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
    Serial.printf(" Conectado!\n");

    setupNTP(); 

    if (downloadUserList()) {
        Serial.println("Sistema pronto!");
    } else {
        Serial.println("Aviso: Falha ao baixar lista inicial. Usando lista antiga/vazia.");
    }

    pinMode(LED_VERDE, OUTPUT);
    pinMode(LED_VERMELHO, OUTPUT);
    
    Serial.println("--------------------------------");
    Serial.println("Aguardando entrada (ID + SENHA + 'A'):");
}

void loop(){
    if (millis() - lastDownloadTime >= downloadInterval) {
        Serial.println("--- Tentando atualizar lista de usuários ---");
        downloadUserList();
    }

    char customKey = customKeypad.getKey();

    if (customKey) {
        if (customKey == 'A') {
            if (inputBuffer.length() >= 8 && inputBuffer.length() <= 12) { 
                int idLength = 8;
                String userID = inputBuffer.substring(0, idLength);
                String senha = inputBuffer.substring(idLength);

                bool permitido = validateUser(userID, senha);

                String motivo;
                if (permitido) {
                    Serial.println("******************");
                    Serial.println("** ACESSO PERMITIDO! **");
                    Serial.println("******************");
                    digitalWrite(LED_VERDE, HIGH);
                    digitalWrite(LED_VERMELHO, LOW);
                    delay(1000);

                    digitalWrite(LED_VERDE, LOW);
                    motivo = "Acesso permitido";
                } else {
                    Serial.println("-----------------");
                    Serial.println("-- ACESSO NEGADO --");
                    Serial.println("-----------------");
                    digitalWrite(LED_VERDE, LOW);
                    digitalWrite(LED_VERMELHO, HIGH);
                    delay(1000);

                    digitalWrite(LED_VERMELHO, LOW);
                    motivo = "Acesso negado (senha incorreta, horario ou usuario inexistente)";
                }

                sendLogToServer(userID, motivo, permitido);

            } else {
                Serial.println("\nEntrada inválida! Formato esperado: ID(8) + Senha(4).");
            }
            inputBuffer = "";
            Serial.println("Aguardando nova entrada:");
        } else if (customKey == '#') {
            inputBuffer = "";
            Serial.println("\nBuffer limpo. Digite novamente.");
        } else {
            inputBuffer += customKey;
            Serial.print(customKey);
        }
    }
}