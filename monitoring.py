class Monitoring(GenericCommand):
    _cmdline_ = "monitor"
    _syntax_ = f"{_cmdline_}"
    
    @only_if_gdb_running
    def do_invok(self, argv):
        # main routine input cmdline
        pass

register_external_command(NewCommand())
