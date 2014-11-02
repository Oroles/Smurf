#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "maincontroller.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void closeEvent(QCloseEvent *event);

private slots:
    void sendPackagesClicked();
    void stopClicked();

private:
    Ui::MainWindow *ui;
    MainController* controler;
};

#endif // MAINWINDOW_H
