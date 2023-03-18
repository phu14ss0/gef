class NewCommand(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "newcmd"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # let's say we want to print some info about the architecture of the current binary
        print(f"gef.arch={gef.arch}")
        # or showing the current $pc
        print(f"gef.arch.pc={gef.arch.pc:#x}")
        return

register_external_command(NewCommand())
