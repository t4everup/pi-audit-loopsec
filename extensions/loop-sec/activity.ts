// -----------------------------------------------------------------
// Round activity — a counter with NO imports, on purpose
// -----------------------------------------------------------------
//
// THE THIRD TIME A TEST PULLED THE HOST SDK IN. `tools.ts` imports
// `@earendil-works/pi-coding-agent`, which is supplied by the running host and is absent from an
// installed checkout — so every test that wanted "did a tool run this round" failed in the clone
// with `Cannot find module` while passing in the development tree. The counter lives here instead:
// this file imports nothing, so anything may import it.

let secToolCalls = 0;

/**
 * How many `sec_*` tool calls have run in this PROCESS.
 *
 * The round record stores this at prepare time, so a settle can ask "did the model touch anything at
 * all after the brief". The declared SDK reports nothing about how a turn ended
 * (`AgentSettledEvent` carries only a type), so this is the one honest signal available: a round that
 * made ZERO tool calls examined nothing, which is not evidence about the project and must not feed
 * the plateau.
 *
 * Process-local on purpose: it is a delta between two points in the same process, and a value that
 * survived a restart would make the delta meaningless.
 */
export function secToolCallCount(): number {
  return secToolCalls;
}

/**
 * Record that a sec tool ran.
 *
 * Called by every tool's `execute`, and exported for the round tests, which drive `tickLoop`
 * directly and need to represent "the model acted this round".
 */
export function noteSecToolCall(): void {
  secToolCalls++;
}
