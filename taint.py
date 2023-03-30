class Taint_Reg(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "TaintReg"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):

        # let's say we want to print some info about the architecture of the current binary
        print(f"gef.arch={gef.arch}")
        # or showing the current $pc
        print(f"gef.arch.pc={gef.arch.pc:#x}")
        return

# 명령어 : clear용도
class clear(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "clear"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        clear_screen()
        return

register_external_command(Taint_Reg())
register_external_command(clear())

'''
[알고리즘 구상도]
elf 분석 라이브러리 : pylibelf(X)
=> gefaddrspace존재

----
1. elf구조를 통한 주소, 어셈블리어 추출
=> 사전 작업 + 내부 기능으로 해결
=> capstone.py 참고

2. 오염 분석할 주소 및 레지스터 지정

3. (ni, si중) 실행되면서 만약 레지스터가 오염된다면 alert
=> 오염되는 기준을 정할 레지스터
=> MOV, CALL, LEA, CMP, TEST, 산술 연산자, RET, MOV, PUSH, POP, JUMP
<si는 무시하되 만약 매개변수로 오염변수가 들어간다면 반환값이 오염된다고 가정>
(1) 매 실행마다 적용되는 방법을 찾기
=> 만약 못찾는다면 비동기로 뒤에서 계속 실행하여 주소(pc)가 달라졌을때 반영하게 된다.
(2) (1)이 될 떄 미리 지정한 영향받는 어셈블리어가 들어있을 경우
레지스터 오염 추적 여부를 확인하고 오염됬을시 확인한다.
=> (?) 오염 추적를 어떻게 따라갈껀지 구상해야함


(+) 설정한 값 초기화하는 기능
(+) 현재 진행중인 오염 상황을 출력하는 기능
'''