"""Brute-force check of Proposition prop:timed on small random models.
Model: n windows, schedule j(s)=s (q=n steps), observers o with one report slot per
window (n_o=1, m_o=1), report alphabet M. Genuine report Y_{o,s} depends on V (random
channel). Cut step K_o in {1..q+1} is an ARBITRARY random function of (V, Y)
(technique- and observation-dependent). Switch B_{o,s} ~ Bernoulli(alpha), persistent
once 0 (exogenous failure), independent of (V,Y,K). Forged symbol J_{o,s} uniform,
independent. Delivered symbol: genuine if b=1 and s<K_o; forged J if b=0; else EMPTY.
Bound: I(V;W) <= H(K) + sum_s sum_o alpha_o(s) * log2(M+1) * P(K_o > s).
"""
import itertools, math, random
from collections import defaultdict

def H(d):
    return -sum(p*math.log2(p) for p in d.values() if p > 0)

def run(seed, nV=4, n=2, nobs=2, M=2):
    rng = random.Random(seed)
    pV = [rng.random() for _ in range(nV)]; z = sum(pV); pV = [x/z for x in pV]
    # channel Y_{o,s} | V
    chan = {}
    for o in range(nobs):
        for s in range(n):
            for v in range(nV):
                w = [rng.random()**3 for _ in range(M)]; t = sum(w)
                chan[(o, s, v)] = [x/t for x in w]
    # K | (V, Y): arbitrary deterministic-or-random rule
    krule = {}
    alpha_first = [rng.uniform(0.3, 1.0) for _ in range(nobs)]  # P(switch stays 1 per window)
    EMPTY = 'e'
    joint_VW = defaultdict(float); joint_K = defaultdict(float)
    PK_gt = defaultdict(float)
    Yspace = list(itertools.product(range(M), repeat=nobs*n))
    Kspace = list(itertools.product(range(1, n+2), repeat=nobs))
    # switch paths: persistent failure; B_{o,s} = 1 until first failure
    Bspace = list(itertools.product([0, 1], repeat=nobs*n))
    def pB(b):
        p = 1.0
        for o in range(nobs):
            alive = True
            for s in range(n):
                bit = b[o*n+s]
                if not alive:
                    if bit == 1: return 0.0
                    continue
                p *= alpha_first[o] if bit == 1 else (1-alpha_first[o])
                if bit == 0: alive = False
        return p
    Jspace = list(itertools.product(range(M), repeat=nobs*n))
    pJ = 1.0/len(Jspace)
    alpha_os = defaultdict(float)
    for b in Bspace:
        pb = pB(b)
        for o in range(nobs):
            for s in range(n):
                alpha_os[(o, s)] += pb * b[o*n+s]
    for v in range(nV):
        for y in Yspace:
            py = pV[v]
            for o in range(nobs):
                for s in range(n):
                    py *= chan[(o, s, v)][y[o*n+s]]
            if py == 0: continue
            key = (v, y)
            if key not in krule:
                w = [rng.random()**4 for _ in Kspace]; t = sum(w); krule[key] = [x/t for x in w]
            for ki, k in enumerate(Kspace):
                pk = py * krule[key][ki]
                if pk == 0: continue
                joint_K[k] += pk
                for o in range(nobs):
                    for s in range(n):
                        if k[o] > s+1: PK_gt[(o, s)] += pk  # step j(s)=s+1 intact iff K_o > j(s)
                for b in Bspace:
                    pb = pB(b)
                    if pb == 0: continue
                    for jf in Jspace:
                        wsym = []
                        for o in range(nobs):
                            for s in range(n):
                                i = o*n+s
                                if b[i] == 1 and s+1 < k[o]: wsym.append(y[i])
                                elif b[i] == 0: wsym.append(('f', jf[i]))
                                else: wsym.append(EMPTY)
                        joint_VW[(v, tuple(wsym))] += pk*pb*pJ
    pv = defaultdict(float); pw = defaultdict(float)
    for (v, w), p in joint_VW.items(): pv[v] += p; pw[w] += p
    I = H(pv) + H(pw) - H(joint_VW)
    bound = H(joint_K) + sum(alpha_os[(o, s)] * math.log2(M+1) * PK_gt[(o, s)]
                             for o in range(nobs) for s in range(n))
    return I, bound, H(joint_K)

worst = 1e9
for seed in range(60):
    I, B, HK = run(seed)
    worst = min(worst, B - I)
    assert I <= B + 1e-9, (seed, I, B)
print('60 random models: bound held; min slack = %.4f bits' % worst)
# half-set example: V uniform on 4, cut (at step 1) iff V in {0,1}, report carries nothing
print('done')
