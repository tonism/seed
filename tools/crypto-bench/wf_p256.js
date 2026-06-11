export const meta = {
  name: 'p256-ecdhe-opt',
  description: 'Optimize real P-256 ECDHE for the 286@6MHz (testbench feasibility)',
  phases: [{ title: 'Optimize' }, { title: 'Combine' }],
}

const BENCH = '/Users/tonis.markus/Projects/seed/tools/crypto-bench'

const SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    name: { type: 'string', description: 'variant file path you created (variants/p256_xxx.inc)' },
    technique: { type: 'string' },
    ok: { type: 'boolean', description: 'p256_eval reported ok (correct vs OpenSSL oracle)' },
    field_mul_cycles: { type: 'number' },
    field_mul_speedup: { type: 'number', description: 'vs baseline p256_real.inc' },
    scalar_instr_ratio: { type: 'number', description: '--full only; >1 means fewer instrs than baseline' },
    bytes: { type: 'number' },
    error: { type: ['string', 'null'] },
    notes: { type: 'string' },
  },
  required: ['name', 'technique', 'ok', 'field_mul_speedup', 'error', 'notes'],
}

function prompt(file, technique, detail, useFull) {
  return `Testbench-only P-256 optimization (NOT shipped code). Read the contract first:
  cd ${BENCH} && cat P256_OPT_CONTRACT.md && sed -n '1,40p' p256_eval.py

Baseline to copy + modify: ${BENCH}/p256_real.inc (the OpenSSL-verified real P-256).
Your variant file: ${file}

Your optimization: **${technique}**
${detail}

PROCESS (real numbers only):
1. cp p256_real.inc ${file}, then apply your optimization to that file. 8086 only.
2. Evaluate: cd ${BENCH} && python3 p256_eval.py ${file}${useFull ? ' --full' : ''}
3. It MUST stay 'ok' (correct vs the OpenSSL oracle). If a field mul or point op breaks,
   the oracle catches it -- fix until ok. Use --full to confirm the full scalar mult
   == PEER_PUBLIC when you change the scalar-mult structure.
4. Iterate to maximize field_mul_speedup (or scalar_instr_ratio for windowing). bytes = wc -c < ${file}.
Report the FINAL p256_eval numbers. A correct 1.3x beats a broken 3x.`
}

phase('Optimize')
const R1 = [
  { file: 'variants/p256_solinas.inc', technique: 'Solinas (direct NIST P-256) reduction',
    detail: `Replace p256_reduce_product (the generic table-driven reduction using p256_reduce_coeffs +
the per-coeff loop) with the DIRECT NIST P-256 fast reduction. The prime's special form (2^256 -
2^224 + 2^192 + 2^96 - 1) lets you reduce a 512-bit product (the 16 high + 16 low 16-bit words in
p256_product) with ~8-9 additions/subtractions of word-aligned 32-bit limbs (FIPS 186-4 D.2:
s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9, each a specific arrangement of the high words), then
a few final conditional subtracts of the prime. No table, no coeff loop. This is the biggest lever on
the 286. Keep p256_mul_product as-is; only replace the reduction. Verify the field mul stays exact.`, full: false },
  { file: 'variants/p256_comba.inc', technique: 'register-resident Comba multiply',
    detail: `p256_mul_product accumulates column-wise but keeps the 3 accumulators in MEMORY
(add [p256_mul_acc0],ax; adc [p256_mul_acc1],dx; adc [p256_mul_acc2],0 every inner step). Keep
acc0/acc1/acc2 in REGISTERS across the whole inner loop (e.g. bp/registers), write to memory only
when a column finishes. Also trim the per-column index recompute. Goal: cut the per-step memory
traffic (the dominant cost on the 286 where MUL is cheap). Keep the reduction as-is.`, full: false },
  { file: 'variants/p256_window.inc', technique: 'windowed/wNAF scalar multiply',
    detail: `p256_scalar_mult_mixed is plain double-and-add (~141 point-adds for a random scalar).
Implement a 4-bit fixed-window (or wNAF) scalar mult: precompute a small table of odd multiples of the
input point, then per window do 4 doublings + 1 add. Cuts adds from ~141 to ~64 (window) / ~51 (wNAF).
You'll need table storage (reuse p256_s* scratch or add buffers in the harness data block -- but the
harness defines the data, so keep to existing buffers or note what you need). Verify with --full:
scalar_mult must still == PEER_PUBLIC, and scalar_instr_ratio should rise.`, full: true },
  { file: 'variants/p256_wild.inc', technique: 'wildcard: combined mul+reduce or Karatsuba/squaring',
    detail: `A genuinely different angle: e.g. a 2-level Karatsuba field multiply (3 half-muls instead of
4 quarters), OR a dedicated squaring path (p256 doubling uses squarings; a squaring is ~0.6x a mul), OR
fuse the multiply and reduction to avoid materializing the full 512-bit product. Keep it correct vs the
oracle.`, full: false },
]

const r1 = await parallel(R1.map((s) => () =>
  agent(prompt(s.file, s.technique, s.detail, s.full),
    { label: `opt:${s.technique.slice(0, 24)}`, phase: 'Optimize', schema: SCHEMA, agentType: 'general-purpose' })))
const ok1 = r1.filter(Boolean).filter(r => r.ok)
const bestReduce = ok1.filter(r => /solinas|reduc/i.test(r.technique)).sort((a,b)=>b.field_mul_speedup-a.field_mul_speedup)[0]
const bestMul = ok1.filter(r => /comba|mul|karat|squ/i.test(r.technique)).sort((a,b)=>b.field_mul_speedup-a.field_mul_speedup)[0]
const bestWin = ok1.filter(r => /window|wnaf|scalar/i.test(r.technique)).sort((a,b)=>(b.scalar_instr_ratio||0)-(a.scalar_instr_ratio||0))[0]
log(`Round 1: reduce=${bestReduce?.field_mul_speedup||'-'}x mul=${bestMul?.field_mul_speedup||'-'}x window=${bestWin?.scalar_instr_ratio||'-'}x`)

phase('Combine')
const combineDetail = `Merge the best round-1 wins into ONE variant:
- reduction from: ${bestReduce ? bestReduce.name : '(none ok -- keep baseline reduction)'}
- multiply from: ${bestMul ? bestMul.name : '(none ok -- keep baseline multiply)'}
- scalar-mult structure from: ${bestWin ? bestWin.name : '(none ok -- keep baseline double-and-add)'}
Read those files, splice the optimized functions together into ${'variants/p256_combined.inc'}, and
verify the WHOLE thing with --full (must be ok == PEER_PUBLIC). Report field_mul_speedup AND
scalar_instr_ratio. This combined variant is what gets measured on a real 286@6.`
const combined = await agent(prompt('variants/p256_combined.inc', 'combine all round-1 wins', combineDetail, true),
  { label: 'combine:all', phase: 'Combine', schema: SCHEMA, agentType: 'general-purpose' })

return {
  round1: r1.filter(Boolean).map(r => ({ name: r.name, technique: r.technique, ok: r.ok, field_mul_speedup: r.field_mul_speedup, scalar_instr_ratio: r.scalar_instr_ratio, error: r.error })),
  combined: combined,
}
