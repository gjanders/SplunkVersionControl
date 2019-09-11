from subprocess import Popen, PIPE
import Queue
import threading

#Run an OS process with a timeout, this way if a command gets "stuck" waiting for input it is killed
#Had inconsistent results using Popen without a threaded process
#thanks to https://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
def runOSProcess(command, logger, timeout=20):
    def target(q):
        logger.debug("Begin OS process run of %s" % (command))
        process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
        (stdoutdata, stderrdata) = process.communicate()
        if process.returncode != 0:
            logger.debug("OS process exited with non-zero code of %s, for command %s" % (process.returncode, command))
            q.put(stdoutdata)
            q.put(stderrdata)
            q.put(False)
        else:
            logger.debug("OS process exited with zero code, for command %s" % (command))
            q.put(stdoutdata)
            q.put(stderrdata)
            q.put(True)

    #Keep the arguments in the queue for use once the thread finishes
    q = Queue.Queue()
    thread = threading.Thread(target=target, args=(q,))
    thread.daemon=False
    thread.start()
    thread.result_queue = q
    thread.join(timeout)
    if thread.is_alive():
        process.terminate()
        thread.join()
        logger.warn("OS timeout after %s seconds while running %s" % (timeout, command))
        return "", "timeout after %s seconds" % (timeout), False
    logger.debug("Successful run of OS process %s within timeout %s" % (command, timeout))

    return q.get(), q.get(), q.get()

