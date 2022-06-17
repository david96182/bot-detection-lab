import threading


def get_thread_by_name(thread_name):
    thread = None
    threads = filter(lambda t: t.name == thread_name, threading.enumerate())
    thread = list(threads)[0]

    return thread
