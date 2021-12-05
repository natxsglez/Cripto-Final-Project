#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include "sodium.h"


void printMenu() {
    std::cout << "BIENVENIDO" << std::endl << "¿Que quieres hacer?" << std::endl << std::endl;
    std::cout << "1 Cifrar archivo" << std::endl;
    std::cout << "2 Descifrar archivo" << std::endl;
    std::cout << "3 Firmar archivo" << std::endl;
    std::cout << "4 Verificar la firma de archivo" << std::endl;
    std::cout << "5 Generar clave" << std::endl;
    std::cout << "6 Recuperar clave" << std::endl << std::endl;
    std::cout << "0 Cerrar" << std::endl << std::endl;
}

void cipherFile() {
    //ABRIR ARCHIVO
    unsigned char* fileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo a cifrar" << std::endl;
    std::cin >> fileName;

    FILE* normalFile;
    fopen_s(&normalFile, reinterpret_cast<char*>(fileName), "rb");

    if (normalFile == NULL) {
        std::cout << "No se pudo abrir el archivo, intenta de nuevo" << std::endl;
        return;
    }

    //OBTENER LONGITUD DEL MENSAJE
    fseek(normalFile, 0, SEEK_END);
    long plainTextLen = ftell(normalFile);
    fseek(normalFile, 0, SEEK_SET);

    unsigned char* normalText = new unsigned char[plainTextLen];
    unsigned char* cipherText = new unsigned char[plainTextLen];

    //GENERAR NONCE Y KEY
    unsigned char KEY[crypto_stream_chacha20_KEYBYTES];
    unsigned char NONCE[crypto_stream_chacha20_NONCEBYTES];

    crypto_secretbox_keygen(KEY);
    randombytes_buf(NONCE, sizeof NONCE);

    //LEER ARCHIVO
    fread(normalText, 1, plainTextLen, normalFile);
    fclose(normalFile);

    //CIFRAR ARCHIVO
    int toCipher = crypto_stream_chacha20_xor(cipherText, normalText, plainTextLen, NONCE, KEY);

    //CREAR ARCHIVO CON MENSAJE CIFRADO, NONCE Y LLAVE
    std::string cipherFileName("cipher_");
    cipherFileName.append(reinterpret_cast<char*>(fileName));
    FILE* cipherFile;
    fopen_s(&cipherFile, cipherFileName.c_str(), "wb");

    std::string nonceFileName("nonce_");
    nonceFileName.append(reinterpret_cast<char*>(fileName));
    FILE* nonceFile;
    fopen_s(&nonceFile, nonceFileName.c_str(), "wb");

    std::string keyFileName("key_");
    keyFileName.append(reinterpret_cast<char*>(fileName));
    FILE* keyFile;
    fopen_s(&keyFile, keyFileName.c_str(), "wb");

    if (cipherFile == NULL || nonceFile == NULL || keyFile == NULL) {
        std::cout << "No se pudo crear uno de los archivos, intenta de nuevo" << std::endl;
        return;
    }

    fwrite(cipherText, plainTextLen, 1, cipherFile);
    fclose(cipherFile);

    fwrite(NONCE, crypto_stream_chacha20_NONCEBYTES, 1, nonceFile);
    fclose(nonceFile);

    fwrite(KEY, crypto_stream_chacha20_KEYBYTES, 1, keyFile);
    fclose(keyFile);

    std::cout << "Mensaje cifrado en: " + cipherFileName << std::endl;
    std::cout << "Key en: " + keyFileName << std::endl;
    std::cout << "Nonce en: " + nonceFileName << std::endl;
}

void decipherFile() {
    //OBTENER NOMBRE DE CADA ARCHIVO: KEY, NONCE, ARCHIVO CIFRADO
    unsigned char* cipherFileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo a descifrar" << std::endl;
    std::cin >> cipherFileName;

    unsigned char* keyFileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo que contiene la llave" << std::endl;
    std::cin >> keyFileName;

    unsigned char* nonceFileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo que contiene el nonce" << std::endl;
    std::cin >> nonceFileName;

    FILE* cipherFile;
    fopen_s(&cipherFile, reinterpret_cast<char*>(cipherFileName), "rb");

    FILE* keyFile;
    fopen_s(&keyFile, reinterpret_cast<char*>(keyFileName), "rb");

    FILE* nonceFile;
    fopen_s(&nonceFile, reinterpret_cast<char*>(nonceFileName), "rb");

    if (cipherFile == NULL || keyFile == NULL || nonceFile == NULL) {
        std::cout << "No se pudieron abrir los archivos, intenta de nuevo" << std::endl;
        return;
    }

    //LEER CIPHER FILE
    fseek(cipherFile, 0, SEEK_END);
    long cipherTextLen = ftell(cipherFile);
    fseek(cipherFile, 0, SEEK_SET);

    unsigned char* cipherText = new unsigned char[cipherTextLen];
    unsigned char* decipherText = new unsigned char[cipherTextLen];
    fread(cipherText, 1, cipherTextLen, cipherFile);
    fclose(cipherFile);

    //LEER KEY FILE
    fseek(keyFile, 0, SEEK_END);
    long keyTextLen = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);

    unsigned char* keyText = new unsigned char[keyTextLen];
    fread(keyText, 1, keyTextLen, keyFile);
    fclose(keyFile);

    //LEER NONCE FILE
    fseek(nonceFile, 0, SEEK_END);
    long nonceTextLen = ftell(nonceFile);
    fseek(nonceFile, 0, SEEK_SET);

    unsigned char* nonceText = new unsigned char[nonceTextLen];
    fread(nonceText, 1, nonceTextLen, nonceFile);
    fclose(nonceFile);

    //DESCRIFRAR ARCHIVO
    int toDecipher = crypto_stream_chacha20_xor(decipherText, cipherText, cipherTextLen, nonceText, keyText);

    //CREAR ARCHIVO CON MENSAJE DESCIFRADO
    std::string decipherFileName("decipher_");
    decipherFileName.append(reinterpret_cast<char*>(cipherFileName));

    FILE* decipherFile;
    fopen_s(&decipherFile, decipherFileName.c_str(), "wb");

    if (decipherFile == NULL) {
        std::cout << "No se pudo crear el archivo descifrado, intenta de nuevo" << std::endl;
        return;
    }

    fwrite(decipherText, cipherTextLen, 1, decipherFile);
    fclose(decipherFile);

    std::cout << "Mensaje descifrado en: " + decipherFileName << std::endl;
}

void generateKeys() {
    //GENERAR PK Y SK
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    //GUARDAR LLAVE PUBLICA Y PRIVADA
    std::string pkFileName("pk.pem");
    FILE* pkFile;
    fopen_s(&pkFile, pkFileName.c_str(), "wb");

    std::string skFileName("sk.pem");
    FILE* skFile;
    fopen_s(&skFile, skFileName.c_str(), "wb");

    if (skFile == NULL || pkFile == NULL) {
        std::cout << "No se pudieron generar los archivos con las llaves, intenta de nuevo" << std::endl;
        return;
    }

    fwrite(pk, crypto_sign_PUBLICKEYBYTES, 1, pkFile);
    fclose(pkFile);

    fwrite(sk, crypto_sign_SECRETKEYBYTES, 1, skFile);
    fclose(skFile);

    std::cout << "Llave publica en: " + pkFileName << std::endl;
    std::cout << "Llave privada en: " + skFileName << std::endl;
}

void getKey() {
    //OBTENER EL ARCHIVO CON LA LLAVE A LEER
    unsigned char* keyFileName = new unsigned char[500];
    std::cout << "Escribe el nombre de la llave a leer" << std::endl;
    std::cin >> keyFileName;

    //LEER EL ARCHIVO
    FILE* keyFile;
    fopen_s(&keyFile, reinterpret_cast<char*>(keyFileName), "rb");

    if (keyFile == NULL) {
        std::cout << "No se pudo abrir el archivo con la llave" << std::endl;
        return;
    }

    fseek(keyFile, 0, SEEK_END);
    long keyLen = ftell(keyFile);
    fseek(keyFile, 0, SEEK_SET);

    unsigned char* key = new unsigned char[keyLen];
    fread(key, 1, keyLen, keyFile);
    fclose(keyFile);

    std::cout << "KEY" << std::endl << key << std::endl;
}

void signFile() {
    //LEER ARCHIVO PARA FIRMAR Y SECRET KEY
    unsigned char* fileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo a firmar" << std::endl;
    std::cin >> fileName;

    unsigned char* skFileName = new unsigned char[500];
    std::cout << "Escribe el nombre de la llave privada" << std::endl;
    std::cin >> skFileName;

    FILE* file;
    fopen_s(&file, reinterpret_cast<char*>(fileName), "rb");

    FILE* skFile;
    fopen_s(&skFile, reinterpret_cast<char*>(skFileName), "rb");

    if (file == NULL || skFile == NULL) {
        std::cout << "No se pudieron abrir los archivos, intenta de nuevo" << std::endl;
        return;
    }

    //OBTENER LONGITUD DE LOS ARCHIVOS
    fseek(file, 0, SEEK_END);
    unsigned long fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    fseek(skFile, 0, SEEK_END);
    unsigned long skFileLen = ftell(skFile);
    fseek(skFile, 0, SEEK_SET);

    //LEER ARCHIVOS
    unsigned char* signedMessage = new unsigned char[crypto_sign_BYTES + fileLen];
    unsigned long long signedMessageLen;
    unsigned char* fileText = new unsigned char[fileLen];

    unsigned char* skText = new unsigned char[skFileLen];

    fread(fileText, 1, fileLen, file);

    fread(skText, 1, skFileLen, skFile);
    fclose(skFile);

    //FIRMAR ARCHIVO
    crypto_sign(signedMessage, &signedMessageLen, fileText, fileLen, skText);

    //GUARDAR ARCHIVO FIRMADO
    std::string signedFileName("signed_");
    signedFileName.append(reinterpret_cast<char*>(fileName));

    FILE* signedFile;
    fopen_s(&signedFile, signedFileName.c_str(), "wb");

    if (signedFile == NULL) {
        std::cout << "No se pudo guardar el archivo firmado, intenta de nuevo" << std::endl;
        return;
    }

    fwrite(signedMessage, crypto_sign_BYTES + fileLen, 1, signedFile);
    fclose(signedFile);

    std::cout << "Archivo firmado en: " + signedFileName << std::endl;
}

void verifySignInFile() {
    //LEER ARCHIVO FIRMADO Y PUBLIC KEY
    unsigned char* signedFileName = new unsigned char[500];
    std::cout << "Escribe el nombre del archivo firmado" << std::endl;
    std::cin >> signedFileName;

    unsigned char* pkFileName = new unsigned char[500];
    std::cout << "Escribe el nombre de la llave publica" << std::endl;
    std::cin >> pkFileName;

    FILE* signedFile;
    fopen_s(&signedFile, reinterpret_cast<char*>(signedFileName), "rb");

    FILE* pkFile;
    fopen_s(&pkFile, reinterpret_cast<char*>(pkFileName), "rb");

    if (signedFile == NULL || pkFile == NULL) {
        std::cout << "No se pudieron abrir los archivos, intenta de nuevo" << std::endl;
        return;
    }

    //OBTENER LONGITUD DE LOS ARCHIVOS
    fseek(signedFile, 0, SEEK_END);
    long signedFileLen = ftell(signedFile);
    fseek(signedFile, 0, SEEK_SET);
    unsigned char* signedText = new unsigned char[signedFileLen];

    fseek(pkFile, 0, SEEK_END);
    long pkFileLen = ftell(pkFile);
    fseek(pkFile, 0, SEEK_SET);
    unsigned char* pkText = new unsigned char[pkFileLen];

    //LEER ARCHIVOS
    fread(signedText, 1, signedFileLen, signedFile);
    fclose(signedFile);

    fread(pkText, 1, pkFileLen, pkFile);
    fclose(pkFile);
    
    unsigned char* unsignedText = new unsigned char[(long long) signedFileLen - crypto_sign_BYTES];
    unsigned long long unsignedFileLen;

    //REVISAR SI LA FIRMA ES VALIDA
    if (crypto_sign_open(unsignedText, &unsignedFileLen, signedText, signedFileLen, pkText) != 0) {
        std::cout << "La firma es incorrecta" << std::endl;
    }
    else {
        std::cout << "La firma es correcta" << std::endl;
    }
}

int main()
{
    if (sodium_init() < 0) {
        std::cout << "EROR CON LIBSODIUM" << std::endl;
        return -1;
    }

    int userEntry;

    printMenu();
    std::cin >> userEntry;

    while (userEntry != 0) {
        switch (userEntry)
        {
        case 0:
            break;
        case 1:
            cipherFile();
            break;
        case 2:
            decipherFile();
            break;
        case 3:
            signFile();
            break;
        case 4:
            verifySignInFile();
            break;
        case 5:
            generateKeys();
            break;
        case 6:
            getKey();
            break;
        default:
            break;
        }

        std::cout << std::endl;
        printMenu();
        std::cin >> userEntry;
    }

    return 1;
}