import angr
import claripy

# auto_load_libs False to focus only on this crackme and
# not the libs it depends on
proj = angr.Project('./crack_me', auto_load_libs = False)

# given in the question
password_len = 11

# BVS: bit vector symbol
# BVV: bit vector value
password_symbols = [claripy.BVS(f'password_char_{i}', 8) for i in range(password_len)]
password_symbols_and_newline = claripy.Concat(*password_symbols + [claripy.BVV(b'\n')])

# ... (the point where arguments start getting passed to fgets which
#      is responsible for accepting password input inside main)
#
# How do I know its this fgets ? Its before the strcpsn call present
# in the decompiled code, the fgets above which accepts password
#
#  40155e: lea    0x20(%rsp),%rdi
#  401563: mov    0x2b46(%rip),%rdx # 4040b0 <stdin@GLIBC_2.2.5>
#  40156a: mov    $0x40,%esi
#  40156f: call   4011b0 <fgets@plt>
#  401574: test   %rax,%rax
#  401577: je     4016fd <main+0x258>
#  40157d: lea    0x20(%rsp),%rbp
#  401582: lea    0xad3(%rip),%rsi        # 40205c <_IO_stdin_used+0x5c>
#  401589: mov    %rbp,%rdi
#  40158c: call   4011a0 <strcspn@plt>
PASS_FGETS_BLOCK_START_ADDR = 0x40155e
start_state = proj.factory.blank_state(addr = PASS_FGETS_BLOCK_START_ADDR,
                                       stdin = password_symbols_and_newline)

# blank state has stack 0 by default, this gives the program a stack
# to work with
start_state.regs.rsp = 0x7fffffffffe000

# constrain symbols to printable ascii range
for symbol in password_symbols:
    start_state.add_constraints(symbol >= 0x20, symbol <= 0x7e)

sim_mgr = proj.factory.simulation_manager(start_state)

STDOUT_FILENO = 1
sim_mgr.explore(find = lambda sim_state: b"FLAG{" in sim_state.posix.dumps(STDOUT_FILENO),
                avoid = lambda sim_state: b"Wrong password" in sim_state.posix.dumps(STDOUT_FILENO))

if sim_mgr.found:
    found_state = sim_mgr.found[0]

    # try seeing for what input was the flag found
    STDIN_FILENO = 0
    found_password = found_state.posix.dumps(STDIN_FILENO)
    found_password = found_password.decode('ascii')

    print(f'Found password: {found_password}')
else:
    print('No password found')







