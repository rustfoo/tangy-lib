"""Create and validate a local tool prefix before downloading or executing tools.

Parent directories must be owned by the caller or root and protected against
other users' writes. Sticky shared directories such as /tmp are allowed as
parents. Directory handles and O_NOFOLLOW prevent traversal through symlinks.
Existing contents must be caller-owned and protected from group/other writes;
package symlinks may point only inside the prefix.
"""

import os
from pathlib import Path
import stat
import sys


def check_directory(info, path, *, prefix=False):
    owners = {os.getuid()} if prefix else {0, os.getuid()}
    shared_sticky = not prefix and info.st_mode & stat.S_ISVTX
    if info.st_uid not in owners or (info.st_mode & 0o022 and not shared_sticky):
        raise ValueError(f"Unsafe directory ownership or write permissions: {path}")


def open_directory(parent, name, path, *, prefix=False):
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        check_directory(os.fstat(fd), path, prefix=prefix)
    except BaseException:
        os.close(fd)
        raise
    return fd


def check_contents(prefix):
    def unreadable(error):
        raise error

    for directory, dirs, files in os.walk(prefix, followlinks=False, onerror=unreadable):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            if info.st_uid != os.getuid():
                raise ValueError(f"Prefix entry belongs to another user: {path}")
            if stat.S_ISLNK(info.st_mode):
                if name == "env.sh" and path.parent == prefix:
                    raise ValueError(f"Activation file must not be a symlink: {path}")
                if not path.resolve(strict=True).is_relative_to(prefix):
                    raise ValueError(f"Prefix symlink points outside the installation: {path}")
            elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError(f"Prefix entry is not a file or directory: {path}")
            elif info.st_mode & 0o022:
                raise ValueError(f"Prefix entry is writable by other users: {path}")


def prepare_prefix(value):
    prefix = Path(os.path.abspath(value))
    if prefix == Path("/"):
        raise ValueError("The installation prefix must not be the filesystem root")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        check_directory(os.fstat(fd), Path("/"))
        current = Path("/")
        for part in prefix.parts[1:]:
            current /= part
            next_fd = open_directory(fd, part, current, prefix=current == prefix)
            os.close(fd)
            fd = next_fd
        check_contents(prefix)
        # Safe existing 0755 prefixes may be reused, but keep new work private.
        os.fchmod(fd, 0o700)
        for name in ["cache", "state", "log", "packages", "root"]:
            child = open_directory(fd, name, prefix / name, prefix=True)
            os.close(child)
    finally:
        os.close(fd)
    return prefix


if __name__ == "__main__":
    try:
        print(prepare_prefix(sys.argv[1]))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Unsafe interop prefix: {error}", file=sys.stderr)
        sys.exit(1)
