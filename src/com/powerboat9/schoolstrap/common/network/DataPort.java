package com.powerboat9.schoolstrap.common.network;

import sun.rmi.transport.tcp.TCPChannel;
import sun.rmi.transport.tcp.TCPConnection;
import sun.rmi.transport.tcp.TCPEndpoint;
import sun.rmi.transport.tcp.TCPTransport;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;

public class DataPort {
    private KeyPair keys;
    private SocketChannel channel;

    private DataPort(KeyPair keysIn, SocketAddress ip, int clientPort, int serverPort) throws IOException {
        keys = keysIn;
        Socket sock = new Socket("127.0.0.1", clientPort);
        sock.connect(ip, serverPort);
        sock.getChannel().finishConnect();
    }

    public Packet receivePacket() {
    }
}
