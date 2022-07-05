import threading
from datetime import datetime


def get_thread_by_name(thread_name):
    """
    Return a thread instance giving the thread name
    :param thread_name: name of the thread
    :return: thread instance
    """
    thread = None
    threads = filter(lambda t: t.name == thread_name, threading.enumerate())
    thread = list(threads)[0]

    return thread


def get_threads_names():
    """
    Return a list with the name of all the threads alive
    :return: list with threads names
    """
    threads = threading.enumerate()
    threads_names = [t.name for t in threads]
    return threads_names


def get_date_string(date_str):
    """
    Return a date giving the date as string
    :return: datetime object
    """
    date_spl = date_str.split(' ')
    if '' in date_spl:
        date_spl.remove('')
    date_str = date_spl[0] + ' ' + date_spl[1] + ' ' + date_spl[2] + ' ' + date_spl[3][:-3] + ' ' + date_spl[4]
    date_str = datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %Z')

    return date_str


