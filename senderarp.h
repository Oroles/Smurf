#ifndef SENDARP_H
#define SENDARP_H

#include <QObject>
#include <QList>
#include <QNetworkInterface>

#include "pcap.h"
#include "protocolheaders.h"
#include "utils.h"

class SenderARP : public QObject
{
    Q_OBJECT
public:
    explicit SenderARP(QObject *parent = 0);
    void setHandle(pcap_t** hand);
    void setNetworkInterface(QNetworkInterface inter);
    void setIp(QString ip);
    bool getStatus();
signals:
    void foundMacAddress(QString macAddress);

public slots:
    void startWork();
    void stopWork();
    void receivePackage(u_char* package);

private:
    void createPackage(u_char* package);

    bool running;
    pcap_t* handle;
    QString destIp;

    QNetworkInterface currentNetwork;

};

#endif // SENDARP_H
