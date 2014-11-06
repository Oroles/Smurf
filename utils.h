#ifndef UTILS_H
#define UTILS_H

#include <QString>
#include <QList>
#include <QStringList>
#include <QNetworkInterface>

#include "pcap.h"
#include "protocolheaders.h"

QList<byte> splitIpAddress(QString ip, QString spl);
QList<u_char> splitMacAddress(QString mac,QString spl);
u_short cksum (const void * addr, unsigned len, u_short init);
QString findLocalIp(QNetworkInterface currentNetwork);
QString findLocalMac(QNetworkInterface currentNetwork);
QString createArpFilter(QString ip);
QString createTcpFilter(QString ip);
QString createICMPFilter(QString ip);
QString getMacAddressFromARP(const u_char* package);
QString getMacFromPackage(sniff_arp *arp);
QString getBroadcastAddress(QString ip, QNetworkInterface networkInterface);
#endif // UTILS_H
