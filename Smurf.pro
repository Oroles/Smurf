#-------------------------------------------------
#
# Project created by QtCreator 2014-10-31T00:32:32
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Smurf
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    maincontroller.cpp \
    portcontroler.cpp \
    receiver.cpp \
    sendericmp.cpp \
    utils.cpp \
    senderarp.cpp

HEADERS  += mainwindow.h \
    maincontroller.h \
    portcontroler.h \
    receiver.h \
    sendericmp.h \
    protocolheaders.h \
    utils.h \
    senderarp.h

FORMS    += mainwindow.ui

LIBS += -lws2_32

INCLUDEPATH += C:/Work/WpdPack/Include
INCLUDEPATH += $$PWD/../WpdPack/Lib/x64
DEPENDPATH += $$PWD/../WpdPack/Lib/x64

win32:LIBS += C:/Work/WpdPack/Lib/wpcap.lib
win32:LIBS += C:/Work/WpdPack/Lib/Packet.lib

LIBS += -L$$PWD/../WpdPack/Lib/x64 -lPacket
LIBS += -L$$PWD/../WpdPack/Lib/x64 -lwpcap

win32:INCLUDEPATH += $$PWD/../WpdPack/Lib
win32:DEPENDPATH += $$PWD/../WpdPack/Lib
