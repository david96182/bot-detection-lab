import multiprocessing as mp
from datetime import datetime
import pyshark.tshark.tshark


def get_process_by_name(process_name):
    """
    Return a process instance giving the process name
    @param process_name: name of the process
    @return: process instance
    """
    process = None
    processes = filter(lambda p: p.name == process_name, mp.active_children())
    process = list(processes)[0]

    return process


def get_processes_names():
    """
    Return a list with the name of all the processes that are alive(running)
    @return: list with process names
    """
    processes = mp.active_children()
    processes_names = [p.name for p in processes]
    return processes_names


def get_date_string(date_str):
    """
    Return a date giving the date as string. Patch applied also to remove
    space found in some dates from networks packets
    @return: datetime object
    """
    date_spl = date_str.split(' ')
    if '' in date_spl:
        date_spl.remove('')
    date_str = date_spl[0] + ' ' + date_spl[1] + ' ' + date_spl[2] + ' ' + date_spl[3][:-3] + ' ' + date_spl[4]
    date_str = datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %Z')

    return date_str


def verify_interface(interface):
    """
    Verify if the interface is recognizable and available
    @param interface: interface name
    @return: True if interface is found else False
    """
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    if interface in interfaces:
        return True
    return False

