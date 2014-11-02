#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    controler = new MainController(this);

    connect(this->ui->pushButtonSend,SIGNAL(clicked()),this,SLOT(sendPackagesClicked()));
    connect(this->ui->pushButtonStop,SIGNAL(clicked()),this,SLOT(stopClicked()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::sendPackagesClicked()
{
    QString ip = this->ui->lineEditIp->text();
    if ( ip != "" )
    {
        controler->sendPackages(ip);
    }
}

void MainWindow::stopClicked()
{
    controler->stopSendingPackage();
}
