#include "sendericmp.h"

SenderICMP::SenderICMP(QObject *parent) :
    running(false),destIp(""),QObject(parent)
{
}

void SenderICMP::startWork()
{
    running = true;
    u_char package[100];
    this->createPackage(package);
    while( running )
    {
        //pcap_sendpacket( handle, package, ICMP_PACKAGE_SIZE );
        this->sendOnePackage();
    }
}

void SenderICMP::sendOnePackage()
{
    u_char package[100];
    this->createPackage(package);
    pcap_sendpacket( handle, package, ICMP_PACKAGE_SIZE );
}

void SenderICMP::stopWork()
{
    running = false;
}

bool SenderICMP::getStatus()
{
    return running;
}

void SenderICMP::setHandle(pcap_t **hand)
{
    this->handle = *hand;
}

void SenderICMP::setIp(QString ip)
{
    destIp = ip;
    destIp = findLocalIp( currentNetwork );
}

void SenderICMP::setMac(QString mac)
{
    destMac = mac;
    destMac = findLocalMac( currentNetwork );
}

void SenderICMP::setNetworkInterface(QNetworkInterface inter)
{
    currentNetwork = inter;
}

void SenderICMP::createPackage(u_char* package)
{
    sniff_ethernet ethernet;

    ethernet.ether_dhost[0] = 255;
    ethernet.ether_dhost[1] = 255;
    ethernet.ether_dhost[2] = 255;
    ethernet.ether_dhost[3] = 255;
    ethernet.ether_dhost[4] = 255;
    ethernet.ether_dhost[5] = 255;

    QList<u_char> localaddr = splitMacAddress( destMac ,":");
    for( int i = 0; i < localaddr.size(); ++i )
    {
        ethernet.ether_shost[i] = localaddr[i];
    }

    ethernet.ether_type = htons( 0x0800 );

    static u_short ip_id_count = 1;
    static u_short icmp_id_count = 1;
    static u_short icmp_seq_count = 0x2c00;

    sniff_ip ip;
    ip.ip_vhl = 0x45;
    ip.ip_tos = 0x00;
    ip.ip_len = htons( SIZE_IPV4 + SIZE_ICMP );
    ip.ip_id = htons( ip_id_count );
    ip.ip_off = htons( 0x0000 );
    ip.ip_ttl = 0x80;
    ip.ip_p = 0x01;
    ip.ip_sum = htons( 0x0000 );
    QList<u_char> ipAddress = splitIpAddress( destIp,"." ); //local ip
    ip.ip_src.byte1 =  ipAddress[0];
    ip.ip_src.byte2 =  ipAddress[1];
    ip.ip_src.byte3 =  ipAddress[2];
    ip.ip_src.byte4 =  ipAddress[3];
    QList<u_char> broadcastAddress = splitIpAddress( getBroadcastAddress(destIp, currentNetwork), "." );
    ip.ip_dst.byte1 = broadcastAddress[0];
    ip.ip_dst.byte2 = broadcastAddress[1];
    ip.ip_dst.byte3 = broadcastAddress[2];
    ip.ip_dst.byte4 = broadcastAddress[3];
    ip.ip_sum = ( cksum( &ip, SIZE_IPV4, 0 ) );

    sniff_icmp icmp;
    icmp.ic_type = 0x08;
    icmp.ic_code = 0x00;
    icmp.ic_sum = htons( 0x00 );
    icmp.ic_id = htons( icmp_id_count++ );
    icmp.ic_seq = htons ( icmp_seq_count++ );
    icmp.ic_sum = ( cksum ( &icmp, SIZE_ICMP, 0 ) );

    memcpy( package, &ethernet, SIZE_ETHERNET );
    memcpy( &package[SIZE_ETHERNET], &ip, SIZE_IPV4 );
    memcpy( &package[SIZE_ETHERNET + SIZE_IPV4], &icmp, SIZE_ICMP );

    for ( int i = SIZE_ETHERNET + SIZE_IPV4 + SIZE_ICMP; i < 100; ++i )
    {
        package[i] = 0;
    }
}

void SenderICMP::receivePackage(u_char *package)
{
    if ( package != NULL )
    {
        sniff_ip* ip = (sniff_ip*)package[SIZE_ETHERNET];
        if ( ip->ip_p == 0x01 )
        {
            QString localIp = findLocalIp( currentNetwork );
            QString receiveIp = QString(ip->ip_dst.byte1) + "." + QString(ip->ip_dst.byte2) + "." +
                                QString(ip->ip_dst.byte3) + "." + QString(ip->ip_dst.byte4);
            if (localIp == receiveIp )
            {
                QString sourceIp = QString(ip->ip_src.byte1) + "." + QString(ip->ip_src.byte2) + "." +
                                   QString(ip->ip_src.byte3) + "." + QString(ip->ip_src.byte4);
                emit foundIpAddress( sourceIp );
            }
        }
    }
}


