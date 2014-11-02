#ifndef MAINCONTROLLER_H
#define MAINCONTROLLER_H

#include <QObject>
#include <QThread>

#include "portcontroler.h"
#include "sendericmp.h"
#include "senderarp.h"
#include "receiver.h"
#include "utils.h"

class MainController : public QObject
{
    Q_OBJECT
public:
    explicit MainController(QObject *parent = 0);
    ~MainController();
    void sendPackages(QString ip);
    void stopSendingPackage();
signals:
    void startSendingICMP();
    void startSendingARP();
    void startReceiver();

public slots:
    void foundMacAddress(QString macAddress);

private:
    void initControler();
    void initSenderARP(QString ip);
    void initSenderICMP(QString ip);
    void initReceiver();

    PortControler* controler;

    SenderICMP* senderICMP;
    QThread senderICMPThread;
    SenderARP* senderARP;
    QThread senderARPThread;

    Receiver* receiver;
    QThread receiverThread;


};

#endif // MAINCONTROLLER_H
