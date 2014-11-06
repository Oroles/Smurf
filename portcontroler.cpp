#include "portcontroler.h"

PortControler::PortControler(QObject *parent) :
    QObject(parent)
{
}

bool PortControler::initPcap()
{
    pcap_findalldevs( &allDevs, errBuf );
    currentNetwork = getActiveNetworkInterfaceIndex();
    int index = findNameInPcap( currentNetwork );
    if( index != -1 )
    {
        int  i = 0;
        for ( currDev = allDevs; i < index; currDev = currDev->next, ++i );
        handle = pcap_open_live( currDev->name, 65536, 1, 1000, errBuf );
        return true;
    }
    return false;
}

bool PortControler::setFilter(QString filter)
{
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;
    if ( pcap_lookupnet( currDev->name, &net, &mask, errBuf ) == -1 )
    {
        return false;
    }

    struct bpf_program fp;
    if ( pcap_compile( handle, &fp, filter.toStdString().c_str(), 0, mask ) == -1 )
    {
        return false;
    }

    if ( pcap_setfilter( handle, &fp ) == -1 )
    {
        return false;
    }

    return true;
}

int PortControler::findNameInPcap(QNetworkInterface &network)
{
    QString networkName = network.name();
    int i = 0;
    for ( currDev = allDevs; currDev != nullptr; currDev = currDev->next )
    {
        QString intName = currDev->name;
        if ( intName.contains( networkName ) )
        {
           return i;
        }
        ++i;
    }
    return -1;
}

QNetworkInterface PortControler::getActiveNetworkInterfaceIndex()
{
    QList<QNetworkInterface> networkInterfaces = QNetworkInterface::allInterfaces();
    QNetworkInterface auxCurrentInterface;
    for( auto inter : networkInterfaces )
    {
        QNetworkInterface::InterfaceFlags flags = inter.flags();
        if ( ( flags & QNetworkInterface::IsRunning ) != 0 )
        {
            int index = this->findNameInPcap( inter );
            if ( index != -1 )
            {
                QString name =  inter.humanReadableName();
                if ( name == "Wi-Fi")
                {
                    auxCurrentInterface = inter;
                }
                if ( name == "Ethernet" )
                {
                    return auxCurrentInterface;
                }
            }
        }
    }
    return auxCurrentInterface;
}

pcap_t** PortControler::get_handle()
{
    return &handle;
}

QNetworkInterface PortControler::getNetworkInterface()
{
    return currentNetwork;
}
