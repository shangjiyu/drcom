import socket
import struct
import hashlib
import re
import string
import array
import sys
import time
import datetime
import threading
import multiprocessing


########################################################################
class drcom:
    """"""
    #----------------------------------------------------------------------
    def __init__(self,ip,mac,username,password):
        self.auth_info = array.array('B',[0,]*16)
        self.UDP_IP = ip
        self.UDP_PORT = 61440
        self.username = username
        self.password = password
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.challenge = None
        self.login_a_md5 = None
        self.mac = array.array('B', [0x00,0x16,0xea,0xb9,0x6f,0x50])
    #----------------------------------------------------------------------
    def Send_Start_Request(self):
        package1 = [1,0,0,0,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        buffer = struct.pack('%sB'%len(package1), *package1)
        self.sock.sendto(buffer, (self.UDP_IP, self.UDP_PORT))
        data,addr = self.sock.recvfrom(2048)
        data = list(tuple(data))
        print data
        challenge = ''.join(data[4:8])
        self.challenge = struct.unpack('%sB'%len(challenge), challenge)
        print self.challenge
    #----------------------------------------------------------------------
    def Send_Login_Auth(self):
        username = array.array('B', self.username)
        passward = array.array('B', self.password)
        challenge = array.array('B',self.challenge)
        mac = array.array('B', [0x00,0x16,0xea,0xb9,0x6f,0x50])
        mac_length = len(mac)
        data_head = array.array('B', [0x03,0x01,0x00,len(username)+20])
        md5_content = array.array('B', [0x03, 0x01])
        md5_content.extend(challenge)
        md5_content.extend(passward)
        self.login_a_md5 = array.array('B', self.md5_key(md5_content))
        username_zero = array.array('B', [0,]*38)
        username_zero[0:len(username)] = username
        username_zero[36] = 0x20
        username_zero[37] = 0x01    
        mac_xor = array.array('B', [])
        for i in range(mac_length):
            mac_xor.append(mac[i]^self.login_a_md5[i])
        md5_content = array.array('B', [1])
        md5_content = md5_content + passward + challenge + array.array('B', [0,]*4)
        login_b_md5 = array.array('B', self.md5_key(md5_content))
        nic_ip_zero = array.array('B', [0,]*12)
        num_nic = array.array('B', [1])
        address = array.array('B', [0,]*16)
        data_front = data_head + self.login_a_md5 + username_zero + mac_xor + login_b_md5 + num_nic + address + nic_ip_zero
        md5_content = data_front + array.array('B', [0x14, 0x00, 0x07, 0x0b ])
        login_c_md5 = array.array('B', [0,]*8)
        c_md5 = array.array('B',self.md5_key(md5_content))
        login_c_md5[0:8] = c_md5[0:8]
        host_name = array.array('B', [0,]*32)
        host_dnsp = array.array('B',[211,64,192,1])
        host_dnss = array.array('B',[8,8,4,4])
        dhcp = array.array('B',[0xff,0xff,0xff,0xff])
        host_unknown0 = array.array('B',[ 0x94, 0x00, 0x00, 0x00 ])
        os_major = array.array('B',[ 0x06, 0x00, 0x00, 0x00])
        os_minor = array.array('B',[ 0x01, 0x00, 0x00, 0x00 ])
        os_build = array.array('B',[0xB0, 0x1D, 0x00, 0x00])
        host_unknown1 = array.array('B',[0x02, 0x00, 0x00, 0x00])
        kernel_version = array.array('B',[0,]*32)
        host_info = host_name + host_dnsp + dhcp + host_dnss + array.array('B', [0,]*8) + host_unknown0 + os_major + os_minor + os_build + host_unknown1 + kernel_version
        zero3 = array.array('B', [0,]*96)
        md5left = array.array('B', [ 0x09, 0x00, 0x02, 0x0C,0x00, 0x00, 0x00,0x00, 0x00, 0x00 ])
        md5left[4:8] = c_md5[10:]    
        send_data = data_front + login_c_md5 + array.array('B', [ 0x01, 0x00, 0x00, 0x00,0x00]) + host_info + zero3 + md5left + mac + array.array('B', [0x00,0x00,0xf9,0xf7])
        buffer = struct.pack('%sB'%len(send_data), *send_data)    
        self.sock.sendto(buffer, (self.UDP_IP, self.UDP_PORT))
        data,addr = self.sock.recvfrom(2048)
        self.auth_info = array.array('B',struct.unpack('%sB'%len(data), data))[23:23+len(self.auth_info)]
        
        time.sleep(0.1)
    #----------------------------------------------------------------------
    def Send_Alive(self):
        print 'send_alive'
        mtime =(int(time.time()) %86400)
        btime = array.array('B', [mtime&0xff,mtime >> 8 & 0xff]);        
        print (btime)
        send_data =  array.array('B', [0,]*20)
        send_data[0] = 0xff
        send_data[1:16] = self.login_a_md5[0:]
        print len(send_data)
        send_data = send_data + self.auth_info + btime + array.array('B', [0,]*4) 
        buffer = struct.pack('%sB'%len(send_data), *send_data) 
        print len(send_data)
        self.sock.sendto(buffer, (self.UDP_IP, self.UDP_PORT))
        
        
        
    #----------------------------------------------------------------------
    def Send_Logout_Auth(self):
        data_head = array.array('B',[0x06,0x01,0x00,len(self.username)+20])
        md5_content = array.array('B',[0x06,0x01])+array.array('B',[0x02,0x00,0x00,0x00])+array.array('B', self.password)
        login_a_md5 = array.array('B', self.md5_key(md5_content))
        username_zero = array.array('B',[0,]*38)
        username_zero[0:len(self.username)] = array.array('B',self.username)[0:]
        username_zero[36] = 0x20
        username_zero[37] = 0x01
        mac_length = len(self.mac)
        mac_xor = array.array('B', [])
        for i in range(mac_length):
            mac_xor.append(self.mac[i]^login_a_md5[i])
        send_data = data_head + login_a_md5 + mac_xor + array.array('B', [0x44,0x72,0x63,0x6f,0xc0,0xa8,0x06,0x01,0x0e,0x63,0x0a,0x08,0xc2,0x95,0x01,0xf6])
        buffer = struct.pack('%sB'%len(send_data), *send_data) 
        self.sock.sendto(buffer, (self.UDP_IP, self.UDP_PORT))
    #----------------------------------------------------------------------
    def md5_key(self,md5_content):
        m = hashlib.md5()
        m.update(md5_content)
        login_md5 = m.digest()
        return login_md5
    
 
    
    

if __name__ == "__main__" :
    mydrcom = drcom('192.168.6.1',None,'zym','1qwert')
    mydrcom.Send_Start_Request()
    mydrcom.Send_Login_Auth()
    mydrcom.Send_Alive()
    #mydrcom.Send_Logout_Auth()
