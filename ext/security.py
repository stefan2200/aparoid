"""
Wrapper around pwntool
"""
import pwnlib.exception
from pwnlib.elf import elf


class LibrarySecurityScanner:
    """
    Class used for library security checks
    """

    @staticmethod
    def run_on_shared_object(shared_object_path=None):
        """
        Run on a single shared object
        :param shared_object_path:
        :return:
        """
        try:
            read_sf = elf.ELF(shared_object_path, checksec=True)
            return {
                "canary": read_sf.canary,
                "relro": read_sf.relro,
                "nx": read_sf.nx,
                "aslr": read_sf.aslr,
                "pie": read_sf.pie,
                "fortify": read_sf.fortify,
                "packed": read_sf.packed,
                "arch": read_sf.arch
            }

        except pwnlib.exception.PwnlibException:
            pass
        except Exception:
            pass

    @staticmethod
    def run_on_shared_objects(shared_object_paths=None):
        """
        Runs pwntool on shared objects (.so files)
        :param shared_object_paths:
        :return:
        """
        out_buffer = {}
        for shared_object in shared_object_paths:
            try:
                read_sf = elf.ELF(shared_object, checksec=True)
                shared_object = shared_object.replace(
                    "\\\\", "\\").replace("\\", "/")
                out_buffer[shared_object] = {
                    "canary": read_sf.canary,
                    "relro": read_sf.relro,
                    "nx": read_sf.nx,
                    "aslr": read_sf.aslr,
                    "pie": read_sf.pie,
                    "fortify": read_sf.fortify,
                    "packed": read_sf.packed,
                    "arch": read_sf.arch
                }

            except pwnlib.exception.PwnlibException:
                pass
            except RuntimeError:
                pass
        return out_buffer
