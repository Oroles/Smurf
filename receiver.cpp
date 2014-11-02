#include "receiver.h"

Receiver::Receiver(QObject *parent) :
    running(false),handle(nullptr),QObject(parent)
{
}

void Receiver::startWork()
{
    running = true;

    while( running )
    {
        struct pcap_pkthdr *header = nullptr;
        const u_char *pkt_data = nullptr;

        if ( !this->readPackage( &header, &pkt_data ) )
        {
            {
                running = false;
            }
            continue;
        }
        if( pkt_data == nullptr )
        {
            continue;
        }
        u_char data[100];
        memcpy( data, pkt_data, 100 );
        emit newPackage(data);
        QCoreApplication::processEvents();
    }
}

void Receiver::stopWork()
{
    running = false;
}

void Receiver::setHandle(pcap_t **hand)
{
    handle = *hand;
}

bool Receiver::readPackage(pcap_pkthdr **header,const u_char **package)
{
    int retVal = pcap_next_ex( handle, header, package );
    if ( retVal < 0 )
    {
        return false;
    }
    if ( (*header)->caplen == 0 )
    {
        return false;
    }
    if ( package == nullptr )
    {
        return false;
    }
    return true;
}
