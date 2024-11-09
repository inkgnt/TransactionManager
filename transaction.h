#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <QString>
#include <QJsonObject>

struct Transaction {
    QString amount;        // Сумма
    QString walletNumber;  // Номер криптокошелька
    QString date;          // Дата
    QString hash;          // Хеш транзакции
    QString previousHash;  // Хеш предыдущей транзакции

    // Сериализация в JSON
    QJsonObject toJson() const {
        QJsonObject json;
        json["amount"] = amount;
        json["walletNumber"] = walletNumber;
        json["date"] = date;
        json["hash"] = hash;
        return json;
    }

    // Десериализация из JSON
    static Transaction fromJson(const QJsonObject &json) {
        Transaction transaction;
        transaction.amount = json["amount"].toString();
        transaction.walletNumber = json["walletNumber"].toString();
        transaction.date = json["date"].toString();
        transaction.hash = json["hash"].toString();
        return transaction;
    }
};

#endif // TRANSACTION_H
