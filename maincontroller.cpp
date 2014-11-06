#include "maincontroller.h"

MainController::MainController(QObject *parent) :
    QObject(parent)
{
    controler = new PortControler(this);

    senderICMP = new SenderICMP();
    senderICMP->moveToThread( &senderICMPThread );
    connect( &senderICMPThread, SIGNAL(destroyed()), senderICMP, SLOT(deleteLater()));
    connect( this, SIGNAL(startSendingICMP()), senderICMP, SLOT(startWork()) );
    connect( senderICMP, SIGNAL(foundIpAddress(QString)), this, SLOT(foundIpAddress(QString)));

    senderARP = new SenderARP();
    senderARP->moveToThread( &senderARPThread );
    connect( &senderARPThread, SIGNAL(destroyed()), senderARP, SLOT(deleteLater()));
    connect( this, SIGNAL(startSendingARP()), senderARP, SLOT(startWork()));
    connect( senderARP, SIGNAL(foundMacAddress(QString)),this, SLOT(foundMacAddress(QString)));

    receiver = new Receiver();
    receiver->moveToThread( &receiverThread );
    connect( &receiverThread, SIGNAL(destroyed()), receiver, SLOT(deleteLater()));
    connect( this, SIGNAL(startReceiver()), receiver, SLOT(startWork()));
    //connect( receiver, SIGNAL(newPackage(u_char*)), senderARP, SLOT(receivePackage(u_char*)));


    connect( receiver, SIGNAL(newPackage(u_char*)), senderICMP, SLOT(receivePackage(u_char*)));
    controler->initPcap();
    controler->setFilter( createICMPFilter( findLocalIp( controler->getNetworkInterface() )));

    receiver->setHandle( controler->get_handle() );
    receiverThread.start();
    emit startReceiver();

    senderICMP->setHandle( controler->get_handle() );
    senderICMP->setNetworkInterface( controler->getNetworkInterface() );
    senderICMP->setIp( findLocalIp( controler->getNetworkInterface() ) );
    senderICMP->setMac( findLocalMac( controler->getNetworkInterface() ) );
    senderICMPThread.start();
    emit startSendingICMP();
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
    disconnect( receiver, SIGNAL(newPackage(u_char*)), senderICMP, SLOT(receivePackage(u_char*)));
    connect( receiver, SIGNAL(newPackage(u_char*)), senderARP, SLOT(receivePackage(u_char*)));

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

void MainController::foundIpAddress(QString ipAddress)
{
    if ( ipAddress != "" )
    {
        emit newIpAddress(ipAddress);
    }
}
