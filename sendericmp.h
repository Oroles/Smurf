#ifndef SENDER_H
#define SENDER_H

/*
 * This file is used to send and check ICMP package
 */


#include <QObject>
#include <QString>
#include <QNetworkInterface>
#include <QtEndian>
#include <Winsock2.h>

#include "pcap.h"
#include "protocolheaders.h"
#include "utils.h"

class SenderICMP : public QObject
{
    Q_OBJECT
public:
    explicit SenderICMP(QObject *parent = 0);
    bool getStatus();
    void setHandle(pcap_t** hand);
    void setIp(QString ip);
    void setMac(QString mac);
    void setNetworkInterface(QNetworkInterface inter);
    void sendOnePackage();
signals:
    void foundIpAddress(QString address);
public slots:
    void startWork();
    void stopWork();
    void receivePackage(u_char* package);

private:
    void createPackage(u_char *package);

    bool running;
    pcap_t* handle;

    QString destIp;
    QString destMac;
    QNetworkInterface currentNetwork;
};

#endif // SENDER_H
