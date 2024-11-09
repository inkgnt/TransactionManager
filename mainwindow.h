#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>
#include "transaction.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onOpenButtonClicked();  // Слот для обработки нажатия кнопки "Открыть"

private:
    Ui::MainWindow *ui;
    QList<Transaction> transactions;  // Список транзакций

    // Функция для загрузки транзакций из файла
    void loadTransactionsFromFile(const QString &fileName, QList<Transaction> &transactions);

    // Функция для отображения транзакций в QListWidget
    void displayTransactions();

    // Функция для вычисления хеша транзакции
    QString calculateHash(const QString &previousHash, const Transaction &transaction);
};

#endif // MAINWINDOW_H
