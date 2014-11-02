#ifndef PORTCONTROLER_H
#define PORTCONTROLER_H

#include <QObject>
#include <QString>
#include <QNetworkInterface>

#include "pcap.h"

class PortControler : public QObject
{
    Q_OBJECT
public:
    explicit PortControler(QObject *parent = 0);
    bool initPcap();
    pcap_t** get_handle();
    QNetworkInterface getNetworkInterface();
    bool setFilter(QString filter);
signals:

public slots:


private:

    int findNameInPcap(QNetworkInterface &network);
    int getActiveNetworkInterfaceIndex();

    pcap_if_t* allDevs;
    pcap_if_t* currDev;
    pcap_t* handle;
    char errBuf[PCAP_ERRBUF_SIZE];

    QNetworkInterface currentNetwork;
};

#endif // PORTCONTROLER_H
