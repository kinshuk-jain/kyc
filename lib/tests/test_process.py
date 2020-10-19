import pytest
import signal
import multiprocessing
import os
from lib import process
from unittest.mock import Mock

pytestmark = pytest.mark.lib


@pytest.fixture
def get_process_manager():
    return process.ProcessManager()


def test_process_manager_factory():
    obj = process.ProcessManagerFactory.getProcessManager()
    assert isinstance(
        obj, process.ProcessManager
    ), "process manager factory returns process manager objects"


def test_forks_processes(get_process_manager, monkeypatch):
    current_pid = os.getpid()
    signal_mock = Mock()

    multiprocessing.cpu_count = Mock(return_value=1)
    monkeypatch.setattr(signal, "signal", signal_mock)
    get_process_manager.fork_processes(5)
    assert os.getpid() == current_pid, "Does not fork more than num CPUs"
    assert signal_mock.called == True
    signal_mock.assert_called_once_with(
        signal.SIGCHLD, get_process_manager._grim_reaper
    )


def test_kill_processes(get_process_manager):
    current_pid = os.getpid()
    multiprocessing.cpu_count = Mock(return_value=2)
    get_process_manager.fork_processes(2)
    if os.getpid() != current_pid:
        get_process_manager.kill_process()
    assert os.getpid() == current_pid, "Forks 2 processes but kills only child"
