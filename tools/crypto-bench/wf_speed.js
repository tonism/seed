export const meta = {
  name: 'crypto-speed-search',
  description: 'Evolutionary search to speed up Seed 8088 SHA-256 / TLS-PRF',
  phases: [
    { title: 'Round 1' },
    { title: 'Round 2' },
    { title: 'Round 3' },
    { title: 'Round 4' },
  ],
}

const ROOT = '/Users/tonis.markus/Projects/seed'
const BENCH = ROOT + '/tools/crypto-bench'

const VARIANT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    name: { type: 'string', description: 'variant file path you created, e.g. variants/r1_v3.inc' },
    parent: { type: 'string', description: 'leader file you mutated, or "fresh"' },
    idea: { type: 'string', description: 'one sentence: what this variant does' },
    technique: { type: 'string', description: 'short tag, e.g. "inline-sigma-rotates"' },
    ok: { type: 'boolean', description: 'true iff evaluate.py reported ok_sha AND ok_prf' },
    block_cycles: { type: 'number', description: 'evaluate.py block_cycles (0 if rejected)' },
    block_speedup: { type: 'number', description: 'evaluate.py block_speedup vs baseline (0 if rejected)' },
    prf_speedup: { type: 'number', description: 'evaluate.py prf_speedup (0 if rejected)' },
    bytes: { type: 'number', description: 'byte size of the assembled variant (wc -c of the .inc is fine)' },
    error: { type: ['string', 'null'], description: 'rejection reason or null' },
    notes: { type: 'string', description: 'what worked / what to try next' },
  },
  required: ['name', 'parent', 'idea', 'technique', 'ok', 'block_cycles', 'block_speedup', 'prf_speedup', 'error', 'notes'],
}

function agentPrompt({ round, idx, technique, leaders, isWild, triedTechniques }) {
  const file = `variants/r${round}_v${idx}.inc`
  const leaderList = leaders.map(l => `  - ${l.name}: ${l.block_cycles} cyc (${l.block_speedup}x block, ${l.prf_speedup}x prf) [${l.technique}]`).join('\n')
  const best = leaders[0]
  return `You are one agent in an evolutionary search to make Seed's 8088 SHA-256 faster.

FIRST: read the contract and the data layout, then mutate/improve.
  cd ${BENCH}
  cat CONTRACT.md
  sed -n '1,200p' ../../targets/ibm_pc_5150/boot/core/data.inc   # the sha256_* address map

Current leaders (lower block_cycles is better; the ORIGINAL baseline = 735461 cyc):
${leaderList}

Your job: produce ONE new variant at exactly this path: ${file}
${isWild
  ? `You are a WILDCARD: try a STRUCTURALLY DIFFERENT approach (parent="fresh"). Start from the original ../../targets/ibm_pc_5150/boot/core/sha256.inc OR the best leader, but take a genuinely different angle than the leaders' techniques.`
  : `Mutate the BEST leader (${best ? best.name : 'variants/v001_byterot.inc'}) — read it, then apply your assigned technique on top of it. parent = that leader.`}

Your assigned primary technique to pursue: ${technique}

Techniques already represented in the pool (diversify, don't duplicate unless you can clearly beat them): ${triedTechniques.join('; ') || '(none yet)'}

PROCESS (do this for real, do not guess numbers):
1. cp the parent file to ${file} (or write a fresh full sha256.inc replacement there).
2. Apply your optimization. 8086 instructions ONLY (cpu 8086 enforced). Keep the
   sha256_* data layout from data.inc. Define ALL symbols the contract lists.
3. Evaluate: python3 evaluate.py ${file} --json
4. If ok_sha/ok_prf are not BOTH true, fix the bug and re-run. If you cannot make
   it correct after a few tries, keep the closest correct version (even if only
   ~1.0x) or report ok=false with the error. NEVER report a faster number that
   evaluate.py did not actually print.
5. Try to BEAT the best leader's block_cycles. Iterate 2-4 times if it helps.
6. bytes = run: wc -c < ${file}

Report the FINAL evaluate.py numbers for ${file}. Be honest: a correct 1.1x beats
a broken "3x". Return the structured result.`
}

function rank(results) {
  return results.filter(r => r && r.ok && r.block_cycles > 0)
    .sort((a, b) => a.block_cycles - b.block_cycles)
}

// Round 1: diverse techniques seeded onto the byte-rotate leader (v001).
const R1 = [
  { technique: 'inline-Sigma0-Sigma1-rotates (no generic rotr32 call; optimal fixed sequence per shift amount 2/13/22 and 6/11/25)', wild: false },
  { technique: 'inline-sigma0-sigma1-schedule-rotates (fixed 7/18/>>3 and 17/19/>>10, no call/loop)', wild: false },
  { technique: 'load-word-once-in-sigmas (one register copy feeds all three rotates; kill triple [si] reloads)', wild: false },
  { technique: 'register-resident-t1-t2 (accumulate t1/t2 in dx:ax / regs, fewer add [mem],reg round-trips)', wild: false },
  { technique: 'pointer-rotation-of-state (rotate a..h via moving pointers / sliding window, not memory copies)', wild: false },
  { technique: 'rotl-vs-rotr residual minimization + combined byte+bit rotate that picks the cheaper direction', wild: false },
  { technique: 'fresh full rewrite keeping the working set (e,f,g / a,b,c) in registers across each round', wild: true },
]

phase('Round 1')
log('Round 1: 7 agents, diverse techniques on the byte-rotate leader')
let pool = []
let leaders = [
  { name: 'variants/v001_byterot.inc', block_cycles: 481653, block_speedup: 1.527, prf_speedup: 1.512, technique: 'byte-granular-rotate' },
]
let tried = ['byte-granular-rotate']

const r1 = await parallel(R1.map((spec, i) => () =>
  agent(agentPrompt({ round: 1, idx: i + 1, technique: spec.technique, leaders, isWild: spec.wild, triedTechniques: tried }),
    { label: `r1_v${i + 1}:${spec.technique.slice(0, 22)}`, phase: 'Round 1', schema: VARIANT_SCHEMA, agentType: 'general-purpose' })))
pool.push(...r1.filter(Boolean))
let ranked = rank(pool)
leaders = ranked.slice(0, 3)
tried = [...new Set(pool.filter(Boolean).map(r => r.technique))]
log(`Round 1 done. Best: ${leaders[0] ? leaders[0].name + ' ' + leaders[0].block_cycles + ' cyc (' + leaders[0].block_speedup + 'x)' : 'none beat v001'}`)

// Rounds 2-4: build on the leaders + recombine + wildcards.
const LATER = [
  { n: 'Round 2', specs: [
    { technique: 'recombine the two best leaders (merge their winning ideas into one)', wild: false },
    { technique: 'push register residency further across the round loop (spill the fewest words)', wild: false },
    { technique: 'streamline the message schedule memory traffic + inline its rotates', wild: false },
    { technique: 'eliminate sha256_tmp round-trips in all four sigmas (XOR-accumulate in registers)', wild: false },
    { technique: 'minimize per-round 32-bit add chain (Sigma1+ch+k+w into t1) memory writes', wild: false },
    { technique: 'fresh: unrolled round body trading size for fewer loop/pointer ops', wild: true },
  ] },
  { n: 'Round 3', specs: [
    { technique: 'recombine top-2 leaders again with the best schedule + round-body ideas', wild: false },
    { technique: 'shave remaining [si]/[di] address recomputation; use lea / fixed offsets', wild: false },
    { technique: 'optimize ch/maj to fewest 16-bit ops (bitselect identities)', wild: false },
    { technique: 'reduce w-schedule: compute sigma inputs with one load, reuse across i', wild: false },
    { technique: 'fresh: alternative state representation (e.g. interleaved word order) to cut byte-rotate cost', wild: true },
  ] },
  { n: 'Round 4', specs: [
    { technique: 'final recombination of all best ideas into one tightest variant', wild: false },
    { technique: 'micro-optimize the current leader instruction-by-instruction (cycle model guided)', wild: false },
    { technique: 'trade a little size for speed in the hottest inner sequence (note bytes)', wild: false },
    { technique: 'fresh long-shot: table-driven or fundamentally different rotate/schedule', wild: true },
  ] },
]

for (let ri = 0; ri < LATER.length; ri++) {
  const { n, specs } = LATER[ri]
  phase(n)
  const baseIdx = (ri + 2) * 10
  const res = await parallel(specs.map((spec, i) => () =>
    agent(agentPrompt({ round: ri + 2, idx: baseIdx + i + 1, technique: spec.technique, leaders, isWild: spec.wild, triedTechniques: tried }),
      { label: `${n.replace(' ', '').toLowerCase()}:${spec.technique.slice(0, 20)}`, phase: n, schema: VARIANT_SCHEMA, agentType: 'general-purpose' })))
  pool.push(...res.filter(Boolean))
  ranked = rank(pool)
  leaders = ranked.slice(0, 3)
  tried = [...new Set(pool.filter(Boolean).map(r => r.technique))]
  log(`${n} done. Best so far: ${leaders[0] ? leaders[0].name + ' ' + leaders[0].block_cycles + ' cyc (' + leaders[0].block_speedup + 'x block, ' + leaders[0].prf_speedup + 'x prf)' : 'none'}`)
}

const finalRanked = rank(pool)
return {
  total_variants: pool.length,
  correct_variants: finalRanked.length,
  baseline_block_cycles: 735461,
  leaderboard: finalRanked.slice(0, 10).map(r => ({
    name: r.name, technique: r.technique, parent: r.parent,
    block_cycles: r.block_cycles, block_speedup: r.block_speedup,
    prf_speedup: r.prf_speedup, bytes: r.bytes, idea: r.idea,
  })),
  all: pool.map(r => ({ name: r.name, ok: r.ok, technique: r.technique, block_cycles: r.block_cycles, block_speedup: r.block_speedup, error: r.error })),
}
