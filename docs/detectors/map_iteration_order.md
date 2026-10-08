# map_iteration_order — Map iteration order affects an observable result

Finding code: SANCT_MAP_ITERATION_ORDER
Category: determinism
Severity: Warning

## What it catches

This detector reports Map or HashMap traversal only when iteration position becomes observable: returning a loop-derived entry, overwriting outer state from entries, appending entries to an ordered output or event stream, or using positional iterator selectors such as next() or nth(). Order-insensitive reductions are left alone.

## Vulnerable example

~~~rust
pub fn first_positive(scores: Map<Address, i128>) -> Option<Address> {
    for (addr, score) in scores.iter() {
        if score > 0 {
            return Some(addr);
        }
    }
    None
}
~~~

The result depends on whichever matching entry is visited first.

## Fix

Choose a stable ordering before positional selection, or replace the selection with a deterministic, order-insensitive reduction. For ordered output, collect entries and sort by an explicit stable key before emitting them.

## Detection notes

The rule identifies Map and HashMap parameters and local bindings, follows common iterator chains, and suppresses chains containing an explicit sorting operation. It is intentionally syntactic and does not attempt to prove algebraic commutativity or infer map types returned through arbitrary helper functions.

Related detectors: arg_dos, unbounded_return.
