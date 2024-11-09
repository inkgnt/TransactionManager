#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "ui_mainwindow.h"
#include "transaction.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonArray>

#include <QRegularExpression>
#include <QRegularExpressionMatch>

#include <QDebug>



unsigned char* MainWindow::staticKey = nullptr;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    staticKey = readKeyFromFile(QDir::homePath() + "/Desktop/key.txt");

    encryptAndSaveTransactions();

    loadTransactionsFromFile(QDir::homePath() + "/Desktop/encrypted_trans.json", transactions);
    displayTransactions();
    /*
    connect(ui->pushButton_1, &QPushButton::clicked, this, &MainWindow::on_pushButton_1_clicked);
    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::on_pushButton_2_clicked);
    connect(ui->pushButton_3, &QPushButton::clicked, this, &MainWindow::on_pushButton_3_clicked);
    connect(ui->pushButton_4, &QPushButton::clicked, this, &MainWindow::on_pushButton_4_clicked);
    */
}

MainWindow::~MainWindow()
{
    delete ui;

    if (staticKey) {
        delete[] staticKey;
        staticKey = nullptr;
    }
}


void MainWindow::loadTransactionsFromFile(const QString &fileName, QList<Transaction> &transactions) {
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии файла";
        return;
    }

    QByteArray encryptedData = QByteArray::fromHex(file.readAll());
    QByteArray decryptedData = decryptAES256(encryptedData, staticKey);

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

bool MainWindow::isValidTransactionInput() {
    QString amount = ui->lineEdit->text();
    QString walletNumber = ui->lineEdit_2->text();
    QString date = ui->lineEdit_3->text();

    static const QRegularExpression amountRegex("^\\d{7}$");
    static const QRegularExpression walletRegex("^\\d{6}$");
    static const QRegularExpression dateRegex("^\\d{4}\\.\\d{2}\\.\\d{2}_\\d{2}:\\d{2}:\\d{2}$");

    if (!amountRegex.match(amount).hasMatch()) {
        QMessageBox::warning(this, "Ошибка", "Неверный формат суммы.");
        return false;
    }

    if (walletNumber.isEmpty() || !walletNumber.contains(walletRegex)) {
        QMessageBox::warning(this, "Ошибка", "Номер счета должен состоять только из цифр.");
        return false;
    }

    if (!dateRegex.match(date).hasMatch()) {
        QMessageBox::warning(this, "Ошибка", "Неверный формат даты (должен быть YYYY-MM-DD).");
        return false;
    }

    return true;
}


unsigned char* MainWindow::readKeyFromFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии файла с ключом";
        return nullptr;
    }

    QByteArray keyData = file.readAll();
    file.close();

    keyData = keyData.trimmed();

    if (keyData.size() != 64) {
        qWarning() << "Неверный формат ключа, ожидается 64 символа для AES-256";
        return nullptr;
    }

    QByteArray key = QByteArray::fromHex(keyData);

    unsigned char* keyArray = new unsigned char[key.size()];
    std::memcpy(keyArray, key.data(), key.size());

    return keyArray;
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

void MainWindow::encryptAndSaveTransactions() {
    QFile file(QDir::homePath() + "/Desktop/trans.json");
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Ошибка при открытии исходного файла";
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QByteArray encryptedData = encryptAES256(data, staticKey);
    QByteArray encryptedHex = encryptedData.toHex();

    QFile outFile(QDir::homePath() + "/Desktop/encrypted_trans.json");
    if (!outFile.open(QIODevice::WriteOnly)) {
        qWarning() << "Ошибка при открытии выходного файла";
        return;
    }

    outFile.write(encryptedHex);
    outFile.close();
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

void MainWindow::on_pushButton_1_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Open", QDir::homePath() + "/Desktop", "JSON Files (*.json)");
    if (!fileName.isEmpty()) {
        transactions.clear();
        loadTransactionsFromFile(fileName, transactions);
        displayTransactions();
    }
}

void MainWindow::on_pushButton_2_clicked()
{
    transactions.clear();
    displayTransactions();
}


void MainWindow::on_pushButton_3_clicked()
{
    if (!isValidTransactionInput()) {
        return;
    }

    QString amount = ui->lineEdit->text();
    QString walletNumber = ui->lineEdit_2->text();
    QString date = ui->lineEdit_3->text();

    Transaction newTransaction;
    newTransaction.amount = amount;
    newTransaction.walletNumber = walletNumber;
    newTransaction.date = date;

    QString prevHash = transactions.isEmpty() ? "" : transactions.last().hash;
    newTransaction.hash = calculateHash(prevHash, newTransaction);

    transactions.append(newTransaction);

    displayTransactions();

    ui->lineEdit->clear();
    ui->lineEdit_2->clear();
    ui->lineEdit_3->clear();

    QMessageBox::information(this, "Добавление", "Транзакция успешно добавлена.");
}


void MainWindow::on_pushButton_4_clicked()
{
    ui->lineEdit->clear();
    ui->lineEdit_2->clear();
    ui->lineEdit_3->clear();
}


void MainWindow::on_pushButton_5_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Сохранить файл", QDir::homePath() + "/Desktop", "JSON Files (*.json)");
    if (fileName.isEmpty()) {
        return;
    }

    QJsonArray transactionArray;
    for (const auto &transaction : transactions) {
        transactionArray.append(transaction.toJson());
    }

    QJsonDocument doc(transactionArray);
    QByteArray jsonData = doc.toJson();

    QByteArray encryptedData = encryptAES256(jsonData, staticKey);
    if (encryptedData.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Ошибка при шифровании данных");
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Ошибка", "Не удалось открыть файл для записи");
        return;
    }

    file.write(encryptedData.toHex());
    file.close();

    QMessageBox::information(this, "Сохранено", "Текущие транзакции успешно сохранены и зашифрованы.");
}

