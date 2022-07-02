import threading


def get_thread_by_name(thread_name):
    thread = None
    threads = filter(lambda t: t.name == thread_name, threading.enumerate())
    thread = list(threads)[0]

    return thread


def get_threads_names():
    threads = threading.enumerate()
    threads_names = [t.name for t in threads]
    return threads_names
