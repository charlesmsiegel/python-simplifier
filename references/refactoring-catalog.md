# Refactoring Catalog

Design smells that need a reading brain, not a parser. The scripts catch
structural and mechanical issues; the smells below are about *where behavior
lives* and *how change flows through the code* — you find them by reading, then
asking the diagnostic question for each.

For every smell: **spot it → name the refactoring → write a characterization test
first → make the change small.** Behavior must not change.

## Feature envy
**Spot it:** a method that reaches into another object far more than its own —
`order.customer.address.city`, or a function that pulls five fields off `obj` to
compute something `obj` should compute itself.
**Diagnostic:** "Does this logic use another object's data more than its own?"
**Refactoring:** Move Method (move the behavior to the data it envies) or Extract
Method then move the extracted piece. Put the calculation where the data lives.

## Divergent change
**Spot it:** one module/class that you edit for *unrelated* reasons — a change to
the tax rules and a change to the PDF layout both touch the same file.
**Diagnostic:** "Does this thing have more than one reason to change?" (SRP)
**Refactoring:** Extract Class — split the responsibilities so each has a single
axis of change.

## Shotgun surgery
**Spot it:** the opposite — one conceptual change forces tiny edits across many
files (add a field → touch the model, the form, the serializer, three templates,
two validators).
**Diagnostic:** "Does one change scatter into many places?"
**Refactoring:** Move/Inline to gather the scattered behavior into one place so the
change has one home. Often introduces a class or module that owns the concept.

## Primitive obsession
**Spot it:** money as a bare `float`, a phone number as a `str` validated in twelve
places, a status as a magic string `"active"`, coordinates as a loose `(x, y)`
tuple passed everywhere.
**Diagnostic:** "Is this primitive carrying meaning and rules that live nowhere?"
**Refactoring:** Replace Primitive with Object / Value Type. Use a `dataclass` (often
`frozen=True`) or `enum.Enum` for fixed sets. Validation and behavior move onto the
type; the rest of the code stops re-checking it. (The deterministic counterpart is
`find_parameter_objects.py`, which finds primitives that travel together.)

## Temporal / sequential coupling
**Spot it:** methods that must be called in a specific order — `obj.init();
obj.configure(); obj.run()` — where calling them wrong fails silently or corrupts
state.
**Diagnostic:** "Does correctness depend on call order the type doesn't enforce?"
**Refactoring:** Encapsulate the sequence behind one method, or use a builder /
context manager so the order is structurally guaranteed and the bad states can't be
expressed.

## Large class / God object
**Spot it:** a class with many fields and methods that span several concerns; the
name is vague (`Manager`, `Engine`, `System`); you scroll to understand it.
**Diagnostic:** "Could I split this into two or three things with clearer names?"
**Refactoring:** Extract Class along the seams (groups of fields that are used
together usually mark a sub-object). (`analyze_complexity.py` flags the size;
deciding the seams is judgment.)

## Long method
**Spot it:** a function you can't take in at a glance; sections separated by blank
lines and "now do X" comments; multiple levels of abstraction interleaved.
**Diagnostic:** "Does this do one thing at one level of abstraction?"
**Refactoring:** Extract Method for each section (the comment becomes the function
name); Replace Conditional with Polymorphism or a dispatch dict when the length
comes from a big type-switch; Decompose Conditional for gnarly boolean logic.

## Message chains / train wrecks
**Spot it:** `a.b().c().d().e` — the caller is navigating someone else's structure
and is now coupled to every link.
**Diagnostic:** "Am I reaching through objects to get to one I want?"
**Refactoring:** Hide Delegate — add a method on the first object that returns what
the caller actually needs (Law of Demeter). (`find_coupling_issues.py` flags long
chains; how far to hide is judgment.)

## Data class with no behavior
**Spot it:** a class that is only fields plus getters/setters, while the logic that
operates on those fields lives in other classes that constantly reach in.
**Diagnostic:** "Should the behavior that envies this data live *on* it?"
**Refactoring:** Move Method onto the data. **Caveat:** pure DTOs / boundary objects
(API payloads, dataclasses passed across a wire) are legitimately behavior-free —
don't force behavior onto a deliberate data carrier. Judge by whether other code
keeps manipulating its internals.

## Refused bequest
**Spot it:** a subclass that inherits methods/fields it doesn't want and overrides
them to no-ops or `raise NotImplementedError`.
**Diagnostic:** "Is this really an is-a, or just code reuse via inheritance?"
**Refactoring:** Replace Inheritance with Composition / Delegation; pull the truly
shared part into a separate collaborator.

## Speculative generality & dead flags
**Spot it:** abstract hooks, unused parameters, `if False`-style switches, options
no caller sets. (See `overengineering-and-abstraction.md`.)
**Diagnostic:** "Is anything actually using this generality?"
**Refactoring:** Remove it. The deterministic detectors `find_dead_code.py` and
`find_boolean_params.py` find many of these; deleting the abstraction they imply is
the judgment part.
```
