#include "maincontroller.h"

MainController::MainController(QObject *parent) :
    QObject(parent)
{
    controler = new PortControler(this);

    senderICMP = new SenderICMP();
    senderICMP->moveToThread( &senderICMPThread );
    connect( &senderICMPThread, SIGNAL(destroyed()), senderICMP, SLOT(deleteLater()));
    connect( this, &MainController::startSendingICMP, senderICMP, &SenderICMP::startWork );

    senderARP = new SenderARP();
    senderARP->moveToThread( &senderARPThread );
    connect( &senderARPThread, SIGNAL(destroyed()), senderARP, SLOT(deleteLater()));
    connect( this, SIGNAL(startSendingARP()), senderARP, SLOT(startWork()));
    connect( senderARP, SIGNAL(foundMacAddress(QString)),this, SLOT(foundMacAddress(QString)));

    receiver = new Receiver();
    receiver->moveToThread( &receiverThread );
    connect( &receiverThread, SIGNAL(destroyed()), receiver, SLOT(deleteLater()));
    connect( this, SIGNAL(startReceiver()), receiver, SLOT(startWork()));
    connect( receiver, SIGNAL(newPackage(u_char*)), senderARP, SLOT(receivePackage(u_char*)));
}

MainController::~MainController()
{
    senderICMPThread.quit();
    senderICMPThread.wait();

    senderARPThread.quit();
    senderARPThread.wait();

    receiverThread.quit();
    receiverThread.wait();
}

void MainController::sendPackages(QString ip)
{
    initControler();
    initReceiver();
    initSenderARP(ip);
    initSenderICMP(ip);
    emit startReceiver();
    emit startSendingARP();
}

void MainController::stopSendingPackage()
{
    receiver->stopWork();
    senderICMP->stopWork();
    senderARP->stopWork();
}

void MainController::initControler()
{
    controler->initPcap();
    controler->setFilter( createArpFilter( findLocalIp(controler->getNetworkInterface()) ) );
}

void MainController::initReceiver()
{
    receiver->setHandle( controler->get_handle() );
    receiverThread.start();
}

void MainController::initSenderICMP(QString ip)
{
    senderICMP->setHandle( controler->get_handle() );
    senderICMP->setNetworkInterface( controler->getNetworkInterface() );
    senderICMP->setIp( ip );

}

void MainController::initSenderARP(QString ip)
{
    senderARP->setHandle( controler->get_handle() );
    senderARP->setIp( ip );
    senderARP->setNetworkInterface( controler->getNetworkInterface() );
    senderARPThread.start();
}

void MainController::foundMacAddress(QString macAddress)
{
    disconnect(receiver,SIGNAL(newPackage(u_char*)),senderARP,SLOT(receivePackage(u_char*)));

    senderICMP->setMac( macAddress );
    senderICMPThread.start();
    emit startSendingICMP();
}
