"""Module for utils related to errors
"""


def get_errno_from_exception(e):
    """Gets errno from exception

    Args:
        e: Exception
    Returns:
        errno if available, None otherwise
    """
    if hasattr(e, "errno"):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
