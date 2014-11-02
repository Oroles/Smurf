#include "utils.h"

byte modifyByte( byte val )
{
    if ( val > 57 )
    {
        return val - 55;
    }
    else
    {
        return val - 48;
    }
}

QList<u_char> splitMacAddress(QString mac,QString spl)
{
    QStringList list = mac.split( spl );
    QList<u_char> results;
    for ( int i = 0; i < list.size(); ++i )
    {
        if ( list[i].size() > 1 )
        {
            byte firstByte = modifyByte ( list[i].at(0).cell() );
            byte secondByte = modifyByte( list[i].at(1).cell() );
            results.push_back( ( ( firstByte << 4 ) | secondByte ) );
        }
        else
        {
            byte firstByte = modifyByte( list[i].at(0).cell() );
            results.push_back( firstByte );
        }
    }
    return results;
}

QList<byte> splitIpAddress(QString ip, QString spl)
{
    QStringList list = ip.split( spl );
    QList<byte> results;
    for( int i = 0; i < list.size(); ++i )
    {
        results.push_back( static_cast<byte>( list[i].toInt() ) );
    }
    return results;
}

u_short cksum (const void * addr, unsigned len, u_short init)
{
  u_int sum;
  const u_short * word;

  sum = init;
  word = (u_short*)addr;

  while ( len >= 2 ) {
    sum += *( word++ );
    len -= 2;
  }

  if (len > 0) {
    u_short tmp;

    *(u_char *)(&tmp) = *(u_char *)word;
  }

  sum = ( sum >> 16 ) + ( sum & 0xffff );
  sum += ( sum >> 16 );
  return ( (u_short)~sum );
}

QString findLocalIp(QNetworkInterface currentNetwork)
{
    QList<QNetworkAddressEntry> addEntries = currentNetwork.addressEntries();
    for( int i = 0; i < addEntries.size(); ++i )
    {
        QString ip = addEntries[i].ip().toString();
        if( !ip.contains( "%" ) )
        {
            return ip;
        }
    }
    return "";
}

QString findLocalMac(QNetworkInterface currentNetwork)
{
    QString macAddress = currentNetwork.hardwareAddress();
    return macAddress;
}

QString createArpFilter(QString ip)
{
    return "arp and dst host " + ip;
}

QString createTcpFilter(QString ip)
{
    return "dst host " + ip + " and tcp port 51655";
}

QString getMacAddressFromARP(const u_char* package)
{
    sniff_ethernet* ether = (sniff_ethernet*)( package );
    if ( ether->ether_type == 0x0608  || ether->ether_type == 0x0806 )
    {
        sniff_arp* arp = (sniff_arp*)( package + SIZE_ETHERNET );
        if( arp->opcode == 0x0200 || arp->opcode == 0x0002 )
        {
            return getMacFromPackage(arp);
        }
    }
    return "";
}

QString getMacFromPackage(sniff_arp *arp)
{
    u_char mac[ETHER_ADDR_LEN];
    memcpy( mac, arp->smac, ETHER_ADDR_LEN );
    QString result;
    for ( int i = 0; i < ETHER_ADDR_LEN-1; ++i )
    {
        result += QString::number( mac[i], 16 ) + ":";
    }
    result += QString::number( mac[ETHER_ADDR_LEN-1], 16 );
    return result.toUpper();
}

QString getBroadcastAddress(QString ip)
{
    QString result;
    return result;
}
