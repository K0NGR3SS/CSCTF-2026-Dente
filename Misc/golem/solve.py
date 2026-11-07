import socket
import sys
import tarfile
from pathlib import Path

ARCHIVE = Path(__file__).parent / 'files/golem.tar.gz'
HOST = sys.argv[1]
PORT = int(sys.argv[2])

def parse(lines):
    root = []
    stack = [root]
    for raw in lines:
        parts = raw.strip().split()
        if not parts:
            continue
        op = parts[0]
        if op == 'end':
            stack.pop()
        elif op in ('rep', 'ifz', 'ifn'):
            body = []
            stack[-1].append((op, parts[1], body))
            stack.append(body)
        else:
            stack[-1].append(tuple(parts))
    assert len(stack) == 1
    return root

def run(program, tape):
    reg = [0] * 16
    output = []
    tape_pos = 0
    def number(s):
        return int(s[1:])
    def body(nodes):
        nonlocal tape_pos
        for inst in nodes:
            op = inst[0]
            if op == 'rep':
                for _ in range(int(inst[1])):
                    body(inst[2])
            elif op in ('ifz', 'ifn'):
                cond = reg[number(inst[1])] == 0
                if cond == (op == 'ifz'):
                    body(inst[2])
            elif op == 'set':
                reg[number(inst[1])] = int(inst[2]) & 0xffff
            elif op == 'mov':
                reg[number(inst[1])] = reg[number(inst[2])]
            elif op == 'not':
                reg[number(inst[1])] = (~reg[number(inst[2])]) & 0xffff
            elif op == 'in':
                reg[number(inst[1])] = tape[tape_pos] if tape_pos < len(tape) else 65535
                tape_pos += 1
            elif op == 'out':
                output.append(reg[number(inst[1])])
            else:
                dest, y, z = map(number, inst[1:])
                a, b = reg[y], reg[z]
                if op == 'add': val = a + b
                elif op == 'sub': val = a - b
                elif op == 'mul': val = a * b
                elif op == 'div': val = a // b if b else 65535
                elif op == 'mod': val = a % b if b else a
                elif op == 'and': val = a & b
                elif op == 'or': val = a | b
                elif op == 'xor': val = a ^ b
                elif op == 'shl': val = a << (b & 15)
                elif op == 'shr': val = a >> (b & 15)
                else: raise ValueError(op)
                reg[dest] = val & 0xffff
    body(program)
    return output

def check_examples():
    with tarfile.open(ARCHIVE, 'r:gz') as tar:
        lines = tar.extractfile('./examples.txt').read().decode().splitlines()
    count = 0
    i = 0
    while i < len(lines):
        if lines[i] != 'PROGRAM':
            i += 1
            continue
        i += 1
        prog = []
        while lines[i] != '.':
            prog.append(lines[i]); i += 1
        tape = [int(x) for x in lines[i + 1][len('INPUT '):].split()]
        expected = [int(x) for x in lines[i + 2][len('OUTPUT '):].split()]
        actual = run(parse(prog), tape)
        assert actual == expected, (count, actual, expected)
        count += 1
        i += 3
    print('examples matched:', count, flush=True)

def solve():
    check_examples()
    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(20)
    buffer = b''
    def line():
        nonlocal buffer
        while b'\n' not in buffer:
            block = sock.recv(65536)
            if not block:
                raise EOFError(buffer.decode(errors='replace'))
            buffer += block
        out, buffer = buffer.split(b'\n', 1)
        return out.decode(errors='replace').strip()
    def prompt():
        nonlocal buffer
        marker = b'OUTPUT>'
        while marker not in buffer:
            block = sock.recv(65536)
            if not block:
                raise EOFError(buffer.decode(errors='replace'))
            buffer += block
        _, buffer = buffer.split(marker, 1)
    rounds = 0
    while True:
        ln = line()
        if ln.startswith('=== round '):
            assert line() == 'PROGRAM'
            prog = []
            while True:
                item = line()
                if item == '.': break
                prog.append(item)
            input_line = line()
            assert input_line.startswith('INPUT'), input_line
            tape = [int(x) for x in input_line[5:].split()]
            prompt()
            answer = ' '.join(map(str, run(parse(prog), tape)))
            sock.sendall(answer.encode() + b'\n')
            status = line()
            rounds += 1
            print('round', rounds, status, 'output_count', len(answer.split()), flush=True)
            if status != 'OK':
                print('program:', '\n'.join(prog), 'tape', tape, 'answer', answer)
                break
        else:
            print(ln, flush=True)
            if 'CSCTF{' in ln:
                break

if __name__ == '__main__':
    solve()
