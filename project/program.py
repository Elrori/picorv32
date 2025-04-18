#!/bin/python
import sys
import time
import socket
import queue
import threading
from datetime import datetime
import select
import logging
import math

logging.basicConfig(format="[%(levelname)s] %(message)s",level=logging.DEBUG)

BASE_PARSE      = 0x00000000
BASE_PARSE_FUNC = 0x01000000
BASE_EEPROM     = 0x02000000
BASE_GLOBAL_REG = 0x03000000
BASE_MDIO       = 0x04000000
BASE_TCM        = 0x05000000
BASE_PARSE_RM   = 0x06000000

class streamIface(threading.Thread):

    def __init__(self, bindAddress, bindPort, rxq:queue.Queue, txq:queue.Queue):
        threading.Thread.__init__(self)
        self.runing = True
        self.udp_socket = None
        self.bindAddress= bindAddress
        self.bindPort   = bindPort
        self.bindUDP(self.bindAddress,self.bindPort)
        self.rxq = rxq
        self.txq = txq

    def stop(self):
        self.runing = False
    
    def bindUDP(self,bindAddress,bindPort):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((bindAddress,bindPort))
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.setblocking(False)

    def run(self) -> None:
        while True:
            """
            udp recv

            """
            try:
                readable, writable, exceptional = select.select([self.udp_socket], [], [], 0)
                for s in readable:
                    recv_data, addr = s.recvfrom(65535)
                    if recv_data:
                        # print(f'RECV:{addr} {recv_data}')
                        if not self.rxq.full():
                            self.rxq.put((recv_data,addr))
                        else:
                            logging.warning(f'warning rxq full')
            except BlockingIOError:
                logging.error(f'receiving data: BlockingIOError')
                pass
            except Exception as e:
                logging.error(f'exception receiving data {e}')
            """
            udp send

            """
            if (not self.txq.empty()):
                msg, daddr = self.txq.get()
                try:
                    self.udp_socket.sendto(msg, daddr)
                except Exception as e:
                    logging.error(f'exception send data {e}')
            """
            stop threads

            """ 
            if not self.runing:
                if self.udp_socket != None:
                    self.udp_socket.close()
                # logging.info('stop stream threads...')
                break
            time.sleep(0.001)


class tlwa_support(threading.Thread):

    def __init__(self,rxq:queue.Queue,txq:queue.Queue):
        threading.Thread.__init__(self)
        self.rxq = rxq
        self.txq = txq

    def rxWait(self,ctype:bytes, timeout=1):
        pretime = time.time()
        while True:
            if time.time() - pretime > timeout:
                return b''
            if not self.rxq.empty():
                msg, source = self.rxq.get()
                if msg[20:22] == ctype:
                    return msg
            time.sleep(0.01)
                

    def tlwa_write(self, addr:int, data:bytes):
        if len(data) % 2 == 1:
            logging.error(f'write data length is odd {len(data)}')
            return
        suid = b'\xff\xff\xff\xfe'
        rdlen = (0).to_bytes(2, byteorder='big')
        ctype = b'\x03\x01'
        payloads = b'TLWA' + b'\xff\xff\xff\xff' + suid + b'\x00\x00' + rdlen + b'\x00\x00\x00\x00' + ctype + addr.to_bytes(6, byteorder='big') + data
        self.txq.put((payloads, ('255.255.255.255', 8000)))
        ret = self.rxWait(b'\x03\x02')
        if ret == b'':
            logging.error(f'write tlwa timeout')
        return ret != b''

    def tlwa_read(self, addr:int, length:int):
        suid = b'\xff\xff\xff\xfe'
        rdlen = (length).to_bytes(2, byteorder='big')
        ctype = b'\x02\x01'
        payloads = b'TLWA' + b'\xff\xff\xff\xff' + suid + b'\x00\x00' + rdlen + b'\x00\x00\x00\x00' + ctype + addr.to_bytes(6, byteorder='big')
        self.txq.put((payloads, ('255.255.255.255', 8000)))
        ret = self.rxWait(b'\x02\x02')
        return ret[28:]
    
    def get_protocol_module_version(self):
        return self.tlwa_read(0x0,4)
    
    def get_protocol_module_cntfin(self):
        ret = self.tlwa_read(0x00005804,8)[2:]
        return int.from_bytes(ret, byteorder='big')
    
    def get_protocol_module_cntfout(self):
        ret = self.tlwa_read(0x0000580c,8)[2:]
        return int.from_bytes(ret, byteorder='big')
    
    def get_protocol_module_msicinfo(self):
        return self.tlwa_read(0x00005818,4)
    
    def get_funcode_module_version(self):
        return self.tlwa_read(0x01000000,4)
    
    def get_funcode_module_cntfin(self):
        ret = self.tlwa_read(0x01009004,8)[2:]
        return int.from_bytes(ret, byteorder='big')
    
    def get_funcode_module_cntfout(self):
        ret = self.tlwa_read(0x0100900c,8)[2:]
        return int.from_bytes(ret, byteorder='big')

    def get_funcode_module_msicinfo(self):
        return self.tlwa_read(0x01009014,4)
    
    def get_rm_module_version(self):
        return self.tlwa_read(0x06000100,4)
    
    def get_rm_module_fifo_status(self):
        return self.tlwa_read(0x06000000,4)
    
    def get_rm_module_cntfin(self):
        ret = self.tlwa_read(0x06000004,8)[2:]
        return int.from_bytes(ret, byteorder='big')
    
    def get_rm_module_cntfout(self):
        ret = self.tlwa_read(0x0600000C,8)[2:]
        return int.from_bytes(ret, byteorder='big')

    def get_rm_module_bypass_status(self):
        return self.tlwa_read(0x06000014,4)



    def mdio_wr(self,phy_nums:int,regaddr:int,data:bytes):
        if len(data) != 2:
            logging.error(f'mdio_wr data length is not 2 {len(data)}')
        phy_addr_list = [0x1,0x2,0x1,0x2,0x1,0x2,0x1,0x2,0x1]
        phy_bus_list  = [0,0,1,1,2,2,3,3,4]
        bus = phy_bus_list[phy_nums]
        phyaddr = phy_addr_list[phy_nums]
        addrs = (bus << 12) | (phyaddr << 7) | (regaddr << 2) | 0x04000000
        self.tlwa_write(addrs,b'\x00\x00'+data)
        # print(f'mdio_wr {hex(addrs)} {data.hex()}')

    def mdio_rd(self,phy_nums:int,regaddr:int):
        phy_addr_list = [0x1,0x2,0x1,0x2,0x1,0x2,0x1,0x2,0x1]
        phy_bus_list  = [0,0,1,1,2,2,3,3,4]
        bus = phy_bus_list[phy_nums]
        phyaddr = phy_addr_list[phy_nums]
        addrs = (bus << 12) | (phyaddr << 7) | (regaddr << 2) | 0x04000000
        return self.tlwa_read(addrs,4)[2:]
    
    def mdio_wr_ext(self,phy_nums:int,extaddr:bytes,data:bytes):
        if len(data) != 2 or len(extaddr) != 2:
            logging.error(f'mdio_wr_ext data length is not 4 {len(data)}')
        self.mdio_wr(phy_nums,0x1e,extaddr)
        self.mdio_wr(phy_nums,0x1f,data)

    def mdio_rd_ext(self,phy_nums:int,extaddr:bytes):
        if len(extaddr) != 2:
            logging.error(f'mdio_wr_ext data length is not 2 {len(extaddr)}')
        self.mdio_wr(phy_nums,0x1e,extaddr)
        return self.mdio_rd(phy_nums,0x1f)

    def mdio_phy_rxdly_init(self):
        # self.mdio_wr_ext(0,b'\xa0\x01',b'\x80\x30')
        # self.mdio_wr_ext(1,b'\xa0\x01',b'\x80\x30')
        # self.mdio_wr_ext(2,b'\xa0\x01',b'\x80\x30')
        # self.mdio_wr_ext(3,b'\xa0\x01',b'\x80\x30')
        # self.mdio_wr_ext(4,b'\xa0\x01',b'\x80\x30')
        # self.mdio_wr_ext(5,b'\xa0\x01',b'\x81\x30')
        # self.mdio_wr_ext(6,b'\xa0\x01',b'\x81\x30')
        # self.mdio_wr_ext(7,b'\xa0\x01',b'\x81\x30')
        # self.mdio_wr_ext(8,b'\xa0\x01',b'\x81\x30')
        # return
        def deg2hexstr(deg):
            if deg < 0:
                deg = 0
            ns    = 8*deg/360
            en2ns = False
            if ns >= 2:
                rem = ns - 2
                en2ns = True
            else:
                rem = ns
            rem_step = math.ceil(rem / 0.15)
            if rem_step>=16:
                print('delay error {}, rebound to 190'.format(rem_step))
                rem_step = 15
            s = '1' if en2ns else '0'
            s = s + hex(rem_step)[2]    
            return s
        
        def mdio_set_rxcdly_s(phy_nums = 0, phs = 5):
            hexstr   = deg2hexstr(phs)
            en2ns    = hexstr[0] == '1'
            rem_step = int(hexstr[1],16)
            self.mdio_wr_ext(phy_nums,b'\xa0\x01',b'\x81\x30' if en2ns else b'\x80\x30')
            tmp = rem_step << 10
            tmp += 0xfd
            self.mdio_wr_ext(phy_nums,b'\xa0\x03',tmp.to_bytes(2, byteorder='big'))

        def mdio_set_rxcdly(d = 90, c2 = 45,c1 = 90,b3 = 90,a3 = 0,b2 = 0,a2 = 0,b1 = 0,a1 = 0):
            # PH1A180 C2网口需要45度相移
            # PH1A90  C2网口需要90度相移
            # 其他用默认值
            mdio_set_rxcdly_s(0, phs = a1)
            mdio_set_rxcdly_s(1, phs = b1)
            mdio_set_rxcdly_s(2, phs = a2)
            mdio_set_rxcdly_s(3, phs = b2)
            mdio_set_rxcdly_s(4, phs = a3)
            mdio_set_rxcdly_s(5, phs = b3)
            mdio_set_rxcdly_s(6, phs = c1)
            mdio_set_rxcdly_s(7, phs = c2)
            mdio_set_rxcdly_s(8, phs = d )

        mdio_set_rxcdly()


    def program_cpu(self,hex_file:str):
        with open(hex_file, 'r') as f:
            hex_data = f.read()
        hex_data = hex_data.replace('\n', '')
        bytes_data = bytes.fromhex(hex_data)
        maxlen = 950 # FPGA内部FIFO最大1024字节，实际分包大小最多950字节
        bytes_data_list = [bytes_data[i:i+maxlen] for i in range(0,len(bytes_data),maxlen)]
        base_addr_tcm = 0x05000000
        for i in range(len(bytes_data_list)):
            self.tlwa_write(base_addr_tcm,bytes_data_list[i])
            base_addr_tcm += len(bytes_data_list[i])
        # print(bytes_data.hex())

    def time_sync(self):
        timestamp = int(time.time())
        timestamp_bytes = timestamp.to_bytes(5, 'big')
        timestamp_ns = time.time_ns()
        ns_part200 = (timestamp_ns % 1_000_000_000 )// 200
        timestamp_bytes_ns = ns_part200.to_bytes(3, 'big')
        # print(f'timestamp_bytes: {timestamp_bytes.hex()}')
        # print(f'timestamp_bytes_ns: {timestamp_bytes_ns.hex()}')
        self.tlwa_write(0x03000024,timestamp_bytes+timestamp_bytes_ns)

    def device_enumerate_print(self):
        if self.tlwa_read(0x0,4) != b'\x25\x03\xe5\x99':
            logging.error('device not found or unsupport device!')
            return False
        print('* Device found!\n')

        print('* 去重器模块版本  : 0x{}'.format(self.get_rm_module_version().hex()))
        v=self.get_rm_module_bypass_status().hex()
        s='模块BYPASS' if v == '00000001' else '模块开启'
        print('  去重模块旁路状态: 0x{} ({})'.format(v,s))
        fifo_st = self.get_rm_module_fifo_status()
        fifo_st_int = int.from_bytes(fifo_st, byteorder='big')
        s = ['dbg_fifo_side_overflow','dbg_fifo_side_bad_frame','dbg_fifo_side_good_frame','dbg_fifo_out_overflow','dbg_fifo_out_bad_frame','dbg_fifo_out_good_frame']
        ss = ''
        for i in range(6):
            if fifo_st_int & (1<<i):
                ss = ss + s[i] + ', '
        print('  去重器队列状态  : 0x{} ({})'.format(fifo_st.hex(),ss))
        print('  输入报文计数值  : {}'.format(self.get_rm_module_cntfin()))
        print('  输出报文计数值  : {}\n'.format(self.get_rm_module_cntfout()))

        print('* 协议解析器版本  : 0x{}'.format(self.get_protocol_module_version().hex()))
        st = self.get_protocol_module_msicinfo()
        fifo_st_int = int.from_bytes(st, byteorder='big')
        ss = ''
        s = ['dbg_status_good_frame','dbg_status_bad_frame','dbg_status_overflow','dbg_order_logic_stuck','dbg_sync_fifo_full','dbg_order_fifo_full']
        for i in range(6):
            if fifo_st_int & (1<<i):
                ss = ss + s[i] + ', '
        print('  触发寄存器数值  : 0x{} ({})'.format(st.hex(),ss))
        print('  输入报文计数值  : {}'.format(self.get_protocol_module_cntfin()))
        print('  输出报文计数值  : {}\n'.format(self.get_protocol_module_cntfout()))

        print('* 功码解析器版本  : 0x{}'.format(self.get_funcode_module_version().hex()))
        st = self.get_funcode_module_msicinfo()
        fifo_st_int = int.from_bytes(st, byteorder='big')
        ss = ''
        s = ['dbg_extractor_stuck','dbg_extractor_demux_full','dbg_extractor_mux_full','dbg_sync_fifo_full','dbg_pkg_fifo_overflow']
        for i in range(5):
            if fifo_st_int & (1<<i):
                ss = ss + s[i] + ', '
        print('  触发寄存器数值  : 0x{} ({})'.format(st.hex(),ss))
        print('  输入报文计数值  : {}'.format(self.get_funcode_module_cntfin()))
        print('  输出报文计数值  : {}\n'.format(self.get_funcode_module_cntfout()))

        # b'\x00\x00\x00\x00'： 汇聚口使用16字节格式，新协议解析汇聚功能
        # b'\x00\x00\x00\x01'： 汇聚口使用24字节格式，老数采汇聚功能
        # b'\x00\x00\x00\x02'： 汇聚口使用RAW格式
        # print('设置汇聚口模式中')
        # self.tlwa_write(0x03000038,b'\x00\x00\x00\x00')
        print('* 转发口模式      : 0x{}'.format(self.tlwa_read(0x03000034,4).hex()))
        v=self.tlwa_read(0x03000038,4).hex()
        s='附加20字节' if v == '00000000' else '附加28字节' if v == '00000001' else '原始报文输出'
        print('  汇聚口模式      : 0x{} ({})\n'.format(v,s))

        st0 = self.tlwa_read(0x03000040,4)
        st1 = self.tlwa_read(0x03000044,4)
        st2 = self.tlwa_read(0x03000048,4)
        interface_fifo_st = st2+st1+st0
        interface_fifo_st = int.from_bytes(interface_fifo_st, byteorder='big')
        s =             ['tx_d_error_underflow ', 'tx_d_fifo_overflow ', 'tx_d_fifo_bad_frame ', 'tx_d_fifo_good_frame ', 'rx_d_error_bad_frame',  'rx_d_error_bad_fcs ', 'rx_d_fifo_overflow ', 'rx_d_fifo_bad_frame ', 'rx_d_fifo_good_frame ',
                         'tx_c2_error_underflow', 'tx_c2_fifo_overflow', 'tx_c2_fifo_bad_frame', 'tx_c2_fifo_good_frame', 'rx_c2_error_bad_frame', 'rx_c2_error_bad_fcs', 'rx_c2_fifo_overflow', 'rx_c2_fifo_bad_frame', 'rx_c2_fifo_good_frame',
                         'tx_c1_error_underflow', 'tx_c1_fifo_overflow', 'tx_c1_fifo_bad_frame', 'tx_c1_fifo_good_frame', 'rx_c1_error_bad_frame', 'rx_c1_error_bad_fcs', 'rx_c1_fifo_overflow', 'rx_c1_fifo_bad_frame', 'rx_c1_fifo_good_frame',
                         'tx_b3_error_underflow', 'tx_b3_fifo_overflow', 'tx_b3_fifo_bad_frame', 'tx_b3_fifo_good_frame', 'rx_b3_error_bad_frame', 'rx_b3_error_bad_fcs', 'rx_b3_fifo_overflow', 'rx_b3_fifo_bad_frame', 'rx_b3_fifo_good_frame',
                         'tx_a3_error_underflow', 'tx_a3_fifo_overflow', 'tx_a3_fifo_bad_frame', 'tx_a3_fifo_good_frame', 'rx_a3_error_bad_frame', 'rx_a3_error_bad_fcs', 'rx_a3_fifo_overflow', 'rx_a3_fifo_bad_frame', 'rx_a3_fifo_good_frame',
                         'tx_b2_error_underflow', 'tx_b2_fifo_overflow', 'tx_b2_fifo_bad_frame', 'tx_b2_fifo_good_frame', 'rx_b2_error_bad_frame', 'rx_b2_error_bad_fcs', 'rx_b2_fifo_overflow', 'rx_b2_fifo_bad_frame', 'rx_b2_fifo_good_frame',
                         'tx_a2_error_underflow', 'tx_a2_fifo_overflow', 'tx_a2_fifo_bad_frame', 'tx_a2_fifo_good_frame', 'rx_a2_error_bad_frame', 'rx_a2_error_bad_fcs', 'rx_a2_fifo_overflow', 'rx_a2_fifo_bad_frame', 'rx_a2_fifo_good_frame',
                         'tx_b1_error_underflow', 'tx_b1_fifo_overflow', 'tx_b1_fifo_bad_frame', 'tx_b1_fifo_good_frame', 'rx_b1_error_bad_frame', 'rx_b1_error_bad_fcs', 'rx_b1_fifo_overflow', 'rx_b1_fifo_bad_frame', 'rx_b1_fifo_good_frame',
                         'tx_a1_error_underflow', 'tx_a1_fifo_overflow', 'tx_a1_fifo_bad_frame', 'tx_a1_fifo_good_frame', 'rx_a1_error_bad_frame', 'rx_a1_error_bad_fcs', 'rx_a1_fifo_overflow', 'rx_a1_fifo_bad_frame', 'rx_a1_fifo_good_frame']
        print('* 接口FIFO状态0   : 0x{}'.format(st0.hex()))
        print('  接口FIFO状态1   : 0x{}'.format(st1.hex()))
        print('  接口FIFO状态2   : 0x{}'.format(st2.hex()))
        print('  接口FIFO可读结果: ')
        for i in range(81):
            interface_fifo_st_bit = (interface_fifo_st & 1)
            interface_fifo_st >>= 1
            if interface_fifo_st_bit == 1:
                print('  '+s[80-i])
        print('\n')


        print('* 读取EEPROM 66字节数据:', end='')
        print(self.tlwa_read(0x02000000,32).hex(' '),end=' ')
        print(self.tlwa_read(0x02000000+32,34).hex(' '))
        print('')

        print('*',end='')
        for i in range(9):
            phy_name_list = ['PHY_A1','PHY_B1','PHY_A2','PHY_B2','PHY_A3','PHY_B3','PHY_C1','PHY_C2','PHY_D ']
            h='  ' if i !=0 else ' '
            print(h + 'MDIO {} 厂商识别寄存器: 0x{}'.format(phy_name_list[i],self.mdio_rd(i,2).hex()))
        # print('* 设置相移中')
        # self.mdio_phy_rxdly_init()
        for i in range(9):
            phy_name_list = ['PHY_A1','PHY_B1','PHY_A2','PHY_B2','PHY_A3','PHY_B3','PHY_C1','PHY_C2','PHY_D ']
            print('  MDIO {} EXTA001/A003寄存器 : 0x{} 0x{}'.format(phy_name_list[i],self.mdio_rd_ext(i,b'\xa0\x01').hex(),self.mdio_rd_ext(i,b'\xa0\x03').hex()))

        ts8 = self.tlwa_read(0x03000024,8)
        ts8_ns = int.from_bytes(ts8[5:], byteorder='big')*200
        ts8_unix = int.from_bytes(ts8[0:5], byteorder='big')
        ts8_unix = datetime.fromtimestamp(ts8_unix)
        print('\n* 时间戳TS8： 0x{} ({}:{}ns)\n'.format(ts8.hex(),ts8_unix,ts8_ns))

        # self.clr_all_counter()
        # self.tlwa_write(0x03000038,b'\x00\x00\x00\x01') # 设置汇聚口模式

    def clr_all_counter(self):
        self.tlwa_write(0x00005800,b'\x00\x00\x00\x03') # clear parse_top counter(soft_rst, clear_trig, clear_cnt)
        self.tlwa_write(0x01009000,b'\x00\x00\x00\x03') # clear funcode_top counter(soft_rst, clear_trig, clear_cnt)
        self.tlwa_write(0x06000000,b'\x00\x00\x00\x00') # clear parse_duplicate_rm fifo status
        self.tlwa_write(0x06000004,b'\x00\x00\x00\x00') # clear parse_duplicate_rm cnt_in counter
        self.tlwa_write(0x0600000C,b'\x00\x00\x00\x00') # clear parse_duplicate_rm cnt_out counter
        self.tlwa_write(0x03000040,b'\x00\x00\x00\x00') # clear interface fifo status
        self.tlwa_write(0x03000044,b'\x00\x00\x00\x00') # clear interface fifo status
        self.tlwa_write(0x03000048,b'\x00\x00\x00\x00') # clear interface fifo status

    def run(self) -> None:
        time.sleep(0.01)

def main():
    if len(sys.argv) == 3:
        bindaddress = sys.argv[1]
        bindport = int(sys.argv[2])
    else:
        logging.error('Usage: python parse_udp_controler.py bindaddress bindport')
        return
    # bindaddress = '192.168.9.9'
    # bindport = 8000
    rxq = queue.Queue()
    txq = queue.Queue()
    tStream = streamIface(bindaddress, bindport, rxq, txq)
    tlwa = tlwa_support(rxq, txq)
    tStream.start()

    # tlwa.time_sync()
    # tlwa.device_enumerate_print()
    tlwa.program_cpu('picorv32.txt')
    tlwa.tlwa_write(0x03000030,b'\x00\x00\x00\x01')# rst cpu
    tlwa.tlwa_write(0x03000030,b'\x00\x00\x00\x00')# run cpu
    # tlwa.tlwa_write(0x07000004,b'\x00\x00\x00'+b'l')
    # tlwa.tlwa_write(0x07000004,b'\x00\x00\x00'+b's')
    # tlwa.tlwa_write(0x07000004,b'\x00\x00\x00'+b'\n')

    tStream.stop()
    tStream.join()
    return
    while True:
        input_str = input('input command: ')
        if input_str == 'q':
            tStream.stop()
            tStream.join()
            break

main()