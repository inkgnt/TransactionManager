#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "ui_mainwindow.h"
#include "transaction.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <QFileDialog>
#include <QMessageBox>
#include <openssl/err.h>

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    encryptAndSaveTransactions();

    loadTransactionsFromFile(QDir::homePath() + "/Desktop/encrypted_trans.json", transactions);
    displayTransactions();
    connect(ui->pushButton, &QPushButton::clicked, this, &MainWindow::onOpenButtonClicked);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::encryptAndSaveTransactions() {
    QFile file(QDir::homePath() + "/Desktop/trans.json");
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии исходного файла";
        return;
    }

    QByteArray data = file.readAll();
    file.close();
    QByteArray pinBytes = "1234";
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(pinBytes.constData()), pinBytes.size(), key);

    QByteArray encryptedData = encryptAES256(data, key);
    QByteArray encryptedHex = encryptedData.toHex();

    QFile outFile(QDir::homePath() + "/Desktop/encrypted_trans.json");
    if (!outFile.open(QIODevice::WriteOnly)) {
        qWarning() << "Ошибка при открытии выходного файла";
        return;
    }

    outFile.write(encryptedHex);
    outFile.close();
}

void MainWindow::onOpenButtonClicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Open", QDir::homePath() + "/Desktop", "JSON Files (*.json)");
    if (!fileName.isEmpty()) {
        transactions.clear();
        loadTransactionsFromFile(fileName, transactions);
        displayTransactions();
    }
}

void MainWindow::loadTransactionsFromFile(const QString &fileName, QList<Transaction> &transactions) {
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии файла";
        return;
    }

    QByteArray encryptedData = QByteArray::fromHex(file.readAll());
    QByteArray pinBytes = "1234";
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(pinBytes.constData()), pinBytes.size(), key);


    QByteArray decryptedData = decryptAES256(encryptedData, key);

    QJsonDocument doc = QJsonDocument::fromJson(decryptedData);

    if (doc.isArray()) {
        QJsonArray array = doc.array();
        for (int i = 0; i < array.size(); ++i) {
            QJsonObject obj = array[i].toObject();
            Transaction tx = Transaction::fromJson(obj);
            transactions.append(tx);
        }
    }
}

void MainWindow::displayTransactions() {
    ui->listWidget->clear();

    bool flag = false;
    for (int i = 0; i < transactions.size(); ++i) {
        const Transaction &tx = transactions[i];

        QString displayText = QString::asprintf("Amount: %s, Wallet: %s, Date: %s, Hash: %s",
                                                tx.amount.toUtf8().constData(),
                                                tx.walletNumber.toUtf8().constData(),
                                                tx.date.toUtf8().constData(),
                                                tx.hash.toUtf8().constData());

        QListWidgetItem *item = new QListWidgetItem(displayText, ui->listWidget);

        if (i == 0) {
            QString calculatedHash = calculateHash("", tx);

            if (calculatedHash != tx.hash) {
                flag = true;
            }
        } else {
            const Transaction &prevTx = transactions[i - 1];
            QString calculatedHash = calculateHash(prevTx.hash, tx);

            if (calculatedHash != tx.hash) {
                flag = true;
            }
        }

        if (flag) {
            item->setBackground(QBrush(Qt::red));
        }

        ui->listWidget->addItem(item);
    }
}

QString MainWindow::calculateHash(const QString &previousHash, const Transaction &transaction) {
    QByteArray data = previousHash.toUtf8() + transaction.amount.toUtf8()
    + transaction.walletNumber.toUtf8() + transaction.date.toUtf8();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
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

    QByteArray hashHex = QByteArray(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH).toHex();
    return QString(hashHex);
}

QByteArray iv= QByteArray::fromHex("1234567890abcdef0123456789abcdef");

QByteArray MainWindow::encryptAES256(const QByteArray& plaintext, const unsigned char* key) {
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

QByteArray MainWindow::decryptAES256(const QByteArray& ciphertext, const unsigned char* key) {
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
