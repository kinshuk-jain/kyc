import os
import signal
import multiprocessing


class ProcessManager:
    """Class to manage and fork processes"""

    # reaps child process that have finished to not have zombies
    def _grim_reaper(self, signum, frame):
        """Internal Only. Collects all processes that sent SIGCHLD. Does not block while waiting

        This function is needed to avoid creation of zombies. They will be created if parent does not wait for child to finish
        Args:
            see signal handler python
        Returns:
            None
        """
        while True:
            try:
                pid, status = os.waitpid(
                    -1,  # Wait for any child process
                    os.WNOHANG,  # Do not block and return EWOULDBLOCK error
                )
            except OSError:
                return

            if pid == 0:  # no more zombies
                return

    def fork_processes(self, num_process):
        """forks processes specified by argument.

        This function will not fork more processes than number of cores at a time. Be careful of the number of processes to be forked as it is
        a very expensive operation

        Args:
            num_process: number of processes to be forked
        Returns:
            None
        """
        num_cores = multiprocessing.cpu_count()
        # if num_process is more than 1, register a reaper to collect zombies
        if num_process > 1:
            signal.signal(signal.SIGCHLD, self._grim_reaper)
            if num_cores < num_process:
                print(
                    "Only {num_cores} avaliable, cant fork {num_process} processes. {num_cores} processes will be forked".format(
                        num_cores=num_cores, num_process=num_process
                    )
                )
            num_processes = min(num_cores, num_process)
            for i in range(num_processes - 1):
                try:
                    pid = os.fork()
                    # if child process, come out of loop
                    # this is extremely important as without this, even child will start forking in loop
                    # and num_processes^2 processes will be created
                    if pid == 0:
                        break
                except Exception as e:
                    raise Exception("Could not fork process") from e

    def kill_all_processes(self):
        """cleans up all child processes including parent

        Args:
            None
        Returns:
            None
        """
        # get process group id
        process_group_id = os.getpgid()
        os.killpg(process_group_id, signal.SIGTERM)

    def kill_process(self):
        """kill current process. If it is group leader, kill all child processes too otherwise it will create zombies"""
        current_pid = os.getpid()
        # if current process is parent
        if os.getpgid() == current_pid:
            self.kill_all_processes()
        else:
            os.kill(current_pid, signal.SIGTERM)


class ProcessManagerFactory:
    """Factory to return ProcessManager objects"""

    @staticmethod
    def getProcessManager(*params, **kwargs):
        return ProcessManager(*params, **kwargs)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
