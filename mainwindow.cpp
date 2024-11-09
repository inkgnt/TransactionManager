#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDebug>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "transaction.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


QString calculateHash(const QString &previousHash, const Transaction &transaction) {
    QByteArray data = previousHash.toUtf8() + transaction.amount.toUtf8()
    + transaction.walletNumber.toUtf8() + transaction.date.toUtf8();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Создаем контекст для хеширования
    if (mdctx == nullptr) {
        return QString();
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return QString();
    }

    if (EVP_DigestUpdate(mdctx, data.constData(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return QString();
    }

    if (EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return QString();
    }

    EVP_MD_CTX_free(mdctx);

    // Преобразуем хеш в строку hex-формата
    QByteArray hashHex = QByteArray(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH).toHex();
    return QString(hashHex);
}

// Функция для загрузки и проверки транзакций
void loadTransactionsFromFile(const QString &fileName, QList<Transaction> &transactions) {
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии файла";
        return;
    }

    QByteArray encryptedData = file.readAll();
    // Предположим, что файл расшифрован и передан в encryptedData
    // Для этого примера будем использовать его как есть (если файл зашифрован, нужно дешифровать)

    QJsonDocument doc = QJsonDocument::fromJson(encryptedData);
    if (doc.isArray()) {
        QJsonArray array = doc.array();
        for (int i = 0; i < array.size(); ++i) {
            QJsonObject obj = array[i].toObject();
            Transaction tx = Transaction::fromJson(obj);
            transactions.append(tx);
        }
    }
}

QByteArray iv= QByteArray::fromHex("1234567890abcdef0123456789abcdef");

QByteArray encryptAES256(const QByteArray& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    QByteArray ciphertext(plaintext.size() + AES_BLOCK_SIZE, Qt::Uninitialized);

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           key, reinterpret_cast<unsigned char*>(iv.data())) != 1)
    {
        qDebug() << "Encryption initialization failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1)
    {
        qDebug() << "Encryption update failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &len) != 1)
    {
        qDebug() << "Encryption finalization failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

QByteArray decryptAES256(const QByteArray& ciphertext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    QByteArray plaintext(ciphertext.size(), Qt::Uninitialized);

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           key, reinterpret_cast<unsigned char*>(iv.data())) != 1)
    {
        qDebug() << "Decryption initialization failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()),
                          &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1)
    {
        qDebug() << "Decryption update failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len) != 1)
    {
        qDebug() << "Decryption finalization failed!";
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
