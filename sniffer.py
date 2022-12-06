import socket
import struct
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_IP)
host = socket.gethostbyname(socket.gethostname())
print(host)
s.bind((host,0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
while(True):
    info,addr = s.recvfrom(65565)
    #print('{}'.format(data))
##    dest_mac, src_mac, proto = struct.unpack('!6s 6s 2s', data[:14])
##    info = data[14:]
##    print(proto,int.from_bytes(proto, "big"))
##    proto = int.from_bytes(proto, "big")
##    dest_mac = ":".join(map('{:02x}'.format,dest_mac))
##    src_mac = ":".join(map('{:02x}'.format,src_mac))
##    #print("Mac de destino {} --- Mac de origem {}".format(dest_mac,src_mac))
##    print(socket.ntohs(proto))
    if(True):

        print("O protocolo é ipv4 -- extraindo dados")
        version_header_len = info[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl, proto2, src, target = struct.unpack('! 8x B B 2x 4s 4s', info[:20])
        destino = ".".join(map(str,target))
        origem = ".".join(map(str,src))
        print("Ip de destino {} --- Ip de origem {}".format(destino,origem))
        info2 = info[header_len:]

        if(proto2==6):

            print("Protocolo TCP identificado --- extraindo dados")
            if(len(info2)>=24):
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack('! H H L L H H H H H H', info2[:24])
                print("Porta de destino {} --- porta de origem {}".format(dest_port,src_port))
                conteudo = info2[24:]
                
                print("Conteudo do pacote:{}\n".format(conteudo))
        elif(proto2==17):

            print("Protocolo UDP identificado --- extraindo dados")
            src_port, dest_port, size = struct.unpack('! H H 2x H', info2[:8])
            print("Porta de destino {} --- porta de origem {}".format(dest_port,src_port))
            conteudo = info2[8:]
            
            print("Conteudo do pacote:{}\n".format(conteudo))
    else:
        print('-------------')
        print('falha ao decodificar a mensagem')
