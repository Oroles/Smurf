#include "senderarp.h"

SenderARP::SenderARP(QObject *parent) :
    running(false),handle(nullptr),QObject(parent)
{
}

void SenderARP::startWork()
{
    running = true;

    u_char package[100];
    this->createPackage(package);
    for( int i = 0; i < 1; ++i )
    {
        pcap_sendpacket( handle, package, ARP_PACKAGE_SIZE );
    }
}

void SenderARP::stopWork()
{
    running = false;
}

bool SenderARP::getStatus()
{
    return running;
}

void SenderARP::setHandle(pcap_t** hand)
{
    handle = *hand;
}

void SenderARP::setNetworkInterface(QNetworkInterface network)
{
    currentNetwork = network;
}

void SenderARP::setIp(QString ip)
{
    destIp = ip;
}

void SenderARP::createPackage(u_char* package)
{
    sniff_ethernet ethernet;

    ethernet.ether_dhost[0] = 255;
    ethernet.ether_dhost[1] = 255;
    ethernet.ether_dhost[2] = 255;
    ethernet.ether_dhost[3] = 255;
    ethernet.ether_dhost[4] = 255;
    ethernet.ether_dhost[5] = 255;

    QList<u_char> localaddr = splitMacAddress( findLocalMac(currentNetwork) ,":");
    for( int i = 0; i < localaddr.size(); ++i )
    {
        ethernet.ether_shost[i] = localaddr[i];
    }

    ethernet.ether_type = 0x0608;

    //complete arp package
    sniff_arp arp;
    arp.hrd = 0x0100; //hardware type
    arp.eth_type = 0x0008; //protocol type
    arp.maclen = 0x06; //mac length
    arp.iplen = 0x04; // protocol address length
    arp.opcode = 0x0100; //request
    for ( int i = 0; i < localaddr.size(); ++i )
    {
        arp.smac[i] = localaddr[i]; //local mac
    }
    QList<byte> localIpAddr = splitIpAddress( findLocalIp(currentNetwork), "." ); //local ip
    arp.saddr.byte1 = localIpAddr[0];
    arp.saddr.byte2 = localIpAddr[1];
    arp.saddr.byte3 = localIpAddr[2];
    arp.saddr.byte4 = localIpAddr[3];
    arp.dmac[0] = 0x00; //destination mac;
    arp.dmac[1] = 0x00;
    arp.dmac[2] = 0x00;
    arp.dmac[3] = 0x00;
    arp.dmac[4] = 0x00;
    arp.dmac[5] = 0x00;
    localIpAddr = splitIpAddress( destIp, "." ); //destination ip
    arp.daddr.byte1 = localIpAddr[0];
    arp.daddr.byte2 = localIpAddr[1];
    arp.daddr.byte3 = localIpAddr[2];
    arp.daddr.byte4 = localIpAddr[3];

    memcpy( package, &ethernet, SIZE_ETHERNET );
    memcpy( &package[SIZE_ETHERNET], &arp,SIZE_ARP );
    for( int i = SIZE_ETHERNET + SIZE_ARP; i < 100; ++i )
    {
        package[i] = 0x00;
    }
}

void SenderARP::receivePackage(u_char* package)
{
    QString destMac = getMacAddressFromARP(package);
    if ( destMac != "" )
    {
        emit foundMacAddress(destMac);
    }
}
