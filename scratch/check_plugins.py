import re, sys, glob
sigs = open('compatibility/win32/src/wow64/sigs.rs').read()
w = open('compatibility/win32/src/wow64.rs').read()
handled = set(re.findall(r'sig!\((\w+),', sigs)) | set(re.findall(r'host_override\("(\w+)"', w))
src = ''.join(open(p, encoding='utf-8', errors='ignore').read() for p in glob.glob('compatibility/win32/src/**/*.rs', recursive=True))
def imports(path):
    data = open(path, 'rb').read()
    pe = int.from_bytes(data[0x3c:0x40], 'little')
    n = int.from_bytes(data[pe+6:pe+8], 'little')
    opt = pe + 24
    st = opt + int.from_bytes(data[pe+20:pe+22], 'little')
    secs = []
    for i in range(n):
        sh = data[st+i*40:st+i*40+40]
        secs.append((int.from_bytes(sh[12:16],'little'), int.from_bytes(sh[8:12],'little'), int.from_bytes(sh[16:20],'little'), int.from_bytes(sh[20:24],'little')))
    def off(r):
        for va, vs, rs, ro in secs:
            if va <= r < va + max(vs, rs): return ro + r - va
    rd = int.from_bytes(data[opt+96+8:opt+96+12], 'little')
    o = off(rd); res = {}
    def s(o): return data[o:data.find(b'\0', o)].decode('latin1')
    while data[o:o+20] != b'\0'*20:
        ilt = int.from_bytes(data[o:o+4],'little'); nm = int.from_bytes(data[o+12:o+16],'little'); iat = int.from_bytes(data[o+16:o+20],'little')
        t = off(ilt or iat); lst = []
        while True:
            v = int.from_bytes(data[t:t+4],'little')
            if not v: break
            lst.append('#%d' % (v & 0xffff) if v & 0x80000000 else s(off(v)+2))
            t += 4
        res[s(off(nm))] = lst; o += 20
    return res
for p in sys.argv[1:]:
    print('==', p)
    for dll, l in imports(p).items():
        miss = [i for i in l if i not in handled]
        nohost = [i for i in miss if not re.search(r'\b%s\b' % re.escape(i), src)]
        if miss: print(' ', dll, 'no-sig:', miss, ' no-host-at-all:', nohost)
