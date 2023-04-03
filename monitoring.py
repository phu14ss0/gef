"""
    1. monitor --range 0x40000000 0x40000100
    2. print set memory
    3. execute asm
    4. if change setting memory -> print memory and mark changed part
"""


from lib2to3.pgen2.tokenize import StopTokenizing


class PieBreakpointCommand(GenericCommand):
    """Set a PIE breakpoint at an offset from the target binaries base address."""

    _cmdline_ = "pie2 breakpoint"
    _syntax_ = f"{_cmdline_} OFFSET"

    @parse_arguments({"offset": ""}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args = kwargs["arguments"]
        if not args.offset:
            self.usage()
            return

        addr = parse_address(args.offset)
        self.set_pie_breakpoint(lambda base: f"b *{base + addr}", addr)

        # When the process is already on, set real breakpoints immediately
        if is_alive():
            vmmap = gef.memory.maps
            base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
            for bp_ins in gef.session.pie_breakpoints.values():
                bp_ins.instantiate(base_address)
        return

    @staticmethod
    def set_pie_breakpoint(set_func: Callable[[int], str], addr: int) -> None:
        gef.session.pie_breakpoints[gef.session.pie_counter] = PieVirtualBreakpoint(set_func, gef.session.pie_counter, addr)
        gef.session.pie_counter += 1
        return


'''
class MonitoringCo(GenericCommand):
    _cmdline_ = "mem_monitor"
    _syntax_ = f"{_cmdline_}"

    # def set_memory_range():
    #     pass

    @only_if_gdb_running
    # @parse_arguments({"--range": ""}, {})
    def do_invok(self, argv, **kwargs):
        # args = kwargs["arguments"]
        # if not args.--range
        # self.usage()
        # print(args)
        print(f"gef.arch={gef.arch}")
        # or showing the current $pc
        print(f"gef.arch.pc={gef.arch.pc:#x}")
        return

register_external_command(MonitoringCo())
# register_external_command(PieBreakpointCommand())
'''

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