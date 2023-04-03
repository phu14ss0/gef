"""
    1. monitor --range 0x40000000 0x40000100
    2. print set memory
    3. execute asm
    4. if change setting memory -> print memory and mark changed part
"""

class Monitoring(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "mem_mornitor"
    _syntax_  = f"{_cmdline_} --start --end"

    @parse_arguments({"--start": ""}, {"--end": ""})
    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv, **kwargs):
        # let's say we want to print some info about the architecture of the current binary
        args = kwargs["arguments"]

        try:
            if args.start[:2] == "0x" and args.end[:2]:
                start_addr = int(args.start, 16)
                end_addr = int(args.end, 16)
            else:
                start_addr = int(args.start)
                end_addr = int(args.end)
            print(start_addr, end_addr)
        except:
            print("[*] error")
            return
        return

register_external_command(Monitoring())