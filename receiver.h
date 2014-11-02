#ifndef RECEIVER_H
#define RECEIVER_H

#include <QObject>
#include <QCoreApplication>

#include "pcap.h"
#include "utils.h"

class Receiver : public QObject
{
    Q_OBJECT
public:
    explicit Receiver(QObject *parent = 0);
    void setHandle(pcap_t** hand);
signals:
    void newPackage(u_char* package);
public slots:
    void startWork();
    void stopWork();

private:
    bool readPackage(pcap_pkthdr **header,const u_char **package);

    bool running;
    pcap_t* handle;
};

#endif // RECEIVER_H
