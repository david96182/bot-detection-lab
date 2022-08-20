import datetime
import os
import queue
import signal
from multiprocessing import Process
import multiprocessing as mp
from pyshark import LiveCapture

from settings import logger as logging
import random
import threading
import time
from threading import Thread


def capture():
    out_file = '../capture.pcap'
    interface = 'wlp1s0'
    logging.error('Starting capture on interface: %s' % interface)
    # check if interface is correct

    capture = LiveCapture(interface, output_file=out_file)
    capture.sniff(timeout=0)
    for packet in capture.sniff_continuously():
        print('packet')
        print(packet)
        #print(packet.layers)
        #print(packet.frame_info)
        #print(packet.frame_info.field_names)
        #print(packet.length)
        #print(packet.frame_info.time)
        #start_time = datetime.datetime.strptime(packet.frame_info.time, '%m %d, %Y %H:%M:%S.%f %Z')
        # packet.pretty_print()             %Y-%m-%d %H:%M:%S.%f


class my_thread(Thread):

    def run(self):
        time.sleep(random.uniform(0.5, 1.66))
        print(f'{datetime.datetime.now()}running thread {threading.current_thread().name}')
        times = datetime.datetime.now()
        with open('log.txt', 'a') as f:
            f.write(f'{datetime.datetime.now()}running thread {threading.current_thread().name}\n')
        time.sleep(5)


def test_threads():
    thread1 = my_thread(name='thread1')
    thread2 = my_thread()
    thread3 = my_thread()
    thread4 = my_thread()
    thread5 = my_thread()
    thread6 = my_thread()
    thread7 = my_thread()
    thread8 = my_thread()
    thread9 = my_thread()
    thread10 = my_thread()
    thread11 = my_thread()
    thread12 = my_thread()
    thread13 = my_thread()
    thread14 = my_thread()
    thread15 = my_thread()
    thread16 = my_thread()
    thread17 = my_thread()
    thread18 = my_thread()
    thread19 = my_thread()
    thread20 = my_thread()
    thread21 = my_thread()
    thread22 = my_thread()

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    thread9.start()
    thread10.start()
    thread11.start()
    thread12.start()
    thread13.start()
    thread14.start()
    thread15.start()
    thread16.start()
    thread17.start()
    thread18.start()
    thread19.start()
    thread20.start()
    thread21.start()
    thread22.start()
    # print all threads
    time.sleep(10)
    # kill thread 22

    threadxd = my_thread(name='thread1')
    threadxd.start()
    thread1.start()
    threadss = list(threading.enumerate())
    for thread in threadss:
        print(thread.name)


def test_datetime():
    date_str = 'Jul  1, 2022 10:01:16.783730974 CDT'  #    Jun 14, 2022 18:06:49.954406844 CDT
    dat = date_str.split(' ')
    if '' in dat:
        dat.remove('')
    print(dat)
    date_str = dat[0] + ' ' + dat[1] + ' ' + dat[2] + ' ' + dat[3][:-3] + ' ' + dat[4]
    print(date_str)
    # convert Jun 14, 2022 18:06:49.954406844 CDT to datetime object
    # date_obj = datetime.datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %z')
    start_time = datetime.datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %Z')
    print(start_time)
    # print(date_obj)


def test_mp_file():
    def task():
        with open('log.txt', 'a') as f:
            f.write(f'{datetime.datetime.now()}running thread {threading.current_thread().name}\n')
        print('Worker closing down')

    # create and configure a new process
    process = Process(target=task)
    process2 = Process(target=task)
    process3 = Process(target=task)
    # start the new process
    process.start()
    process2.start()
    process3.start()
    # wait for the new process to finish
    process.join()
    process2.join()
    process3.join()


def test_andor():
    keys = ['12', '1234', '12345', '123456']
    key1 = '1'
    key2 = '12346'
    if key1 in keys or key2 in keys:
        print('key in keys')
    else:
        print('key not in keys')


class TimeoutProcess(Process):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wait_time = 70
        self.status = 'init'
        self.numbers = ['1']
        self.continue_flag = False

    def run(self):
        print('from run function', mp.current_process())
        self.status = 'Running'
        self.timeout()

    def timeout(self):
        self.status = 'Timeout'
        self.continue_flag = True
        try:
            while self.continue_flag and self.wait_time >= 0:
                time.sleep(1)
                self.wait_time = self.wait_time - 1
                print(self.numbers, self.wait_time, self.status, mp.current_process(), flush=True)
                if self.status != 'Timeout':
                    print('interrupting the timeout')
                    continue_flag = False
                    break
        except Exception as e:
            logging.error(e)
        print('timeout HERE')
        if self.wait_time == 0:
            self.status = 'Finished'
            print('Process finished', flush=True)
            pass

    def interrupt_handler(self):
        self.status = 'Running'
        self.wait_time = 0
        self.continue_flag = False
        self.run()
        print(mp.current_process(), 'interrupting the process', flush=True)
        # kill parent process
        os.kill(os.getpid(), signal.SIGINT)
        # kill running timeout
        print('interrupting handler')
        print('timeout:' , self.wait_time, flush=True)
        #self.timeout()


class TimeoutProcessLock(Process):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wait_time = 70
        self.status = 'init'
        self.numbers = ['1']
        self.lock = mp.Lock()

    def run(self):
        self.status = 'Running'
        self.timeout()

    def timeout(self):
        self.status = 'Timeout'
        continue_flag = False#True
        self.lock.acquire(block=True, timeout=1)
        try:
            while continue_flag and self.wait_time >= 0:
                time.sleep(1)
                self.wait_time = self.wait_time - 1
                print(self.numbers, self.wait_time, self.status, flush=True)
                if self.status != 'Timeout':
                    print('interrupting the timeout')
                    continue_flag = False
                    break
        except Exception as e:
            logging.error(e)
        print('timeout HERE')
        if self.wait_time == 0:
            self.status = 'Finished'
            print('Process finished', flush=True)
            pass

    def interrupt_handler(self):
        self.status = 'Running'
        self.wait_time = 15
        # kill running timeout
        print('interrupting handler')
        print('timeout:', self.wait_time, flush=True)
        self.timeout()


def test_timeout_process():
    # create and configure a new process
    process = TimeoutProcess()
    # start the new process
    process.start()
    time.sleep(5)
    print(mp.active_children(),flush=True)
    time.sleep(5)
    process.interrupt_handler()
    print(mp.active_children(), flush=True)


def test_timeout_process_lock():
    process = TimeoutProcessLock()
    process.start()
    time.sleep(5)
    print(mp.active_children(), flush=True)
    time.sleep(5)


class TestThread(threading.Thread):
    def __init__(self,name, loop_time=1.0/60):
        super().__init__(name=name)
        self.status = 'init'
        self.q = queue.Queue()
        self.timeout = loop_time
        self.wait_time = 50
        self.continue_flag = True

    def onThread(self, function, *args, **kwargs):
        print('onThread', threading.current_thread())
        self.q.put((function, args, kwargs))

    def run(self):
        while self.continue_flag and self.wait_time > 0:
            print(self.wait_time)
            time.sleep(1)
            self.wait_time = self.wait_time - 1
            try:
                function, args, kwargs = self.q.get(timeout=self.timeout)
                function(*args, **kwargs)
                print('run', threading.current_thread())
                self.wait_time = 50
            except queue.Empty:
                self.idle()
        self.se_acabo()

    def idle(self):
    #put the code you would have put in the `run` loop here
        pass

    def do_smtg(self):
        print('do_smtg',threading.current_thread())
        #time.sleep(5)
        #self.time_out()

    def time_out(self):
        print('time_out',threading.current_thread())
        try:
            while self.wait_time >= 0:
                time.sleep(1)
                self.wait_time = self.wait_time - 1
                print(self.wait_time, self.status, flush=True)
                if self.q.empty():
                    print('interrupting the timeout')
                    break
        except Exception as e:
            logging.error(e)
        self.continue_flag = False

    def aqui(self):
        print('aqui',threading.current_thread(), flush=True)

    def se_acabo(self):
        print('finitooooooo')


def test_threads():
    name = 'test_thread'
    thread = TestThread(name)
    thread.start()
    print(threading.current_thread())
    thread.onThread(thread.do_smtg)
    thread2 = TestThread('test_thread2')
    thread2.start()

    threads = threading.enumerate()
    threads_names = [t.name for t in threads]
    print(threads_names)

    time.sleep(5)
    thread.onThread(thread.do_smtg)
    print('MAIN', threading.current_thread())
    threadss = filter(lambda x: x.name == name, threading.enumerate())
    thread1 = list(threadss)[0]
    print('EL THREAD 11111111111111:', thread1)
    thread1.onThread(thread1.aqui)


class TestProcess(Process):
    def __init__(self,name, loop_time=1.0/60):
        super().__init__(name=name)
        self.status = 'init'
        self.q = queue.Queue()
        self.timeout = loop_time
        self.wait_time = 50
        self.continue_flag = True

    def onProc(self, function, *args, **kwargs):
        print('onThread', mp.current_process())
        self.q.put((function, args, kwargs))

    def run(self):
        while self.continue_flag and self.wait_time > 0:
            print(self.wait_time)
            time.sleep(1)
            self.wait_time = self.wait_time - 1
            try:
                function, args, kwargs = self.q.get(timeout=self.timeout)
                function(*args, **kwargs)
                print('run', mp.current_process())
                self.wait_time = 50
            except queue.Empty:
                self.idle()

    def idle(self):
    #put the code you would have put in the `run` loop here
        pass

    def do_smtg(self):
        print('do_smtg',mp.current_process())
        time.sleep(5)

    def aqui(self):
        print('aqui',mp.current_process(), flush=True)

def test_process():
    name = 'test_proc'
    proc = TestProcess(name)
    proc.start()
    print(mp.current_process())
    proc.onProc(proc.do_smtg)
    time.sleep(5)
    proc.onProc(proc.do_smtg)
    print('MAIN', mp.current_process())
    procss = filter(lambda x: x.name == name, mp.active_children())
    proc1 = list(procss)[0]
    print('EL THREAD 11111111111111:', proc1)
    proc1.onProc(proc1.aqui)


if __name__ == '__main__':
    #capture()
    #test_datetime()
    # test_mp_file()
    # test_andor()
    #test_timeout_process()
    #test_timeout_process_lock()
    #test_threads()
    #test_process()

    FLAGS_ORDER = 'FSRPAECU'
    flags_before = FLAGS_ORDER[:FLAGS_ORDER.index('P')]
    state_update = ''
    print(flags_before)
    #if not flags_before:
    #    state_update = ''.join(['P', state_update])
    #
    index = None
    for flag in flags_before:
        if flag in state_update:
           index = state_update.index(flag)
    print(index)
    if index is not None:
       index += 1
       state_update = ''.join([state_update[:index], 'P', state_update[index:]])
    else:
        state_update = ''.join(['P', state_update])
    print(state_update)
    if not 'P' in state_update:
        print('features-capture')