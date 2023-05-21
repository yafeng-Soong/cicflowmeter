import csv
import time
from scapy.sendrecv import AsyncSniffer

from flow_session import generate_session_class
import utils
from os.path import exists
import os
from os.path import join
import threading
from multiprocessing import Process
import gc

def test(name: str, out_file: str, pack_num=150):
    sniffer = create_sniffer(
        name,
        'flow',
        out_file,
        pack_num=pack_num,
        filter='udp',
        proto='UDP'
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
        exit(0)
    finally:
        sniffer.join()

def create_sniffer(
    input_file, output_mode, output_file, filter = 'tcp', url_model=None
):

    NewFlowSession = generate_session_class(output_mode, output_file, url_model)
    return AsyncSniffer(
        offline=input_file,
        filter=filter,
        prn=None,
        session=NewFlowSession,
        store=False,
    )

def parse_path(dir_path: list, out_file: str):
    if not os.path.isdir(dir_path):
        print(dir_path, '不存在')
        return
    file_list = os.listdir(dir_path)
    # print(fileList)
    for filename in file_list:
        name = join(dir_path, filename)
        print(name)
        sniffer = create_sniffer(
            name,
            'flow',
            out_file,
        )
        sniffer.start()

        try:
            sniffer.join()
        except KeyboardInterrupt:
            sniffer.stop()
            exit(0)
        finally:
            sniffer.join()
        print(name, 'over')

def direct(base_path: str):
    path_list = [
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230206',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230208',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230212',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230216',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230217',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230415',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230416',
        '/media/syf/Extreme SSD/DataSet/serverside/direct/20230428',
    ]
    for path in path_list:
        parse_path(path, base_path + 'direct.csv')

def center(base_path: str):
    path_list = [
        '/media/syf/Extreme SSD/DataSet/serverside/xiaoxiang/20230209',
        '/media/syf/Extreme SSD/DataSet/serverside/xiaoxiang/20230210',
    ]
    for path in path_list:
        parse_path(path, base_path + 'center.csv')

def resident(base_path: str):
    path_list = [
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230213',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230214',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230216',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230427',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230428',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab/20230428-2',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab_us/20230216',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab_as/20230304',
        '/media/syf/Extreme SSD/DataSet/serverside/oxylab_as/20230305',
    ]
    for path in path_list:
        parse_path(path, base_path + 'resident.csv')

def defence(base_path: str):
    path_list = [
        '/media/syf/Extreme SSD/DataSet/serverside/defence/20230415',
        '/media/syf/Extreme SSD/DataSet/serverside/defence/20230416',
    ]
    for path in path_list:
        parse_path(path, base_path + 'defence.csv')

def job():
    base_path = 'out/serverside2/'
    if not exists(base_path):
        os.makedirs(base_path)
    with open(base_path + 'direct.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(utils.csv_hearders())
    with open(base_path + 'center.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(utils.csv_hearders())
    with open(base_path + 'resident.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(utils.csv_hearders())
    with open(base_path + 'defence.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(utils.csv_hearders())
    
    p = Process(target=direct, args=(base_path,))
    p.start()
    p = Process(target=center, args=(base_path,))
    p.start()
    p = Process(target=resident, args=(base_path,))
    p.start()
    p = Process(target=defence, args=(base_path,))
    p.start()
    
    
    
    
    


if __name__ == '__main__':
    job()
    # for size in size_list:
    #     # p = Process(target=job, args=(size,))
    #     # p = Process(target=udp_job, args=(size,))
    #     # p = Process(target=bridge_job, args=(size,))
    #     p = Process(target=job, args=(size,))
    #     p.start()
        # udp_job(size)
    