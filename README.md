# Zeka: The Zero-Knowledge Argument Engine

Zeka is a cross-platform scoring engine for "find-and-fix" cybersecurity exercises, featuring a novel cryptographic scheme and event processing model that ensure competition integrity, and ease of use for both the competitor and the organizer.

## Motivations
A sufficiently advanced cybersecurity competitor has full visibility of their system: they understand how the engine works (since it's open source) and can perfectly observe everything that the engine accesses. If the engine checks *specifically* for a configuration, the competitor will always be able to see this and will be directed to the correct answer. This, among many other issues, is why [aeacus](https://github.com/elysium-suite/aeacus) is not secure.

It's akin to finding your way through a standard maze that only has one exit. Even if there are dead ends, you know that mazes inherently allow you to find the exit simply by running your hand along the right wall for long enough. Metaphorically speaking, how do we remove these walls while still being able to check whether the competitor walked along the right path? 

[Seth](https://github.com/Eth007/seth) achieves this by checking *every* file in a set of base directories. It does not -- and *cannot* -- distinguish between relevant and irrelevant files. For each file, it uses the hashes of its content (after lowercasing and reducing whitespace) and attributes as potential AES keys to try to decrypt messages that will appear on the score report. In this scheme, the competitor has no way of knowing whether their actions are related to any correct answer, and monitoring the engine reveals nothing that the competitor didn't already know, other than the system's correctness! 

However, it's clear why seth doesn't support more complex check logic or regex: these features require that multiple, potentially nonexistent, states map to the same AES key, which is impossible with hashing. This raises the motivating question for Zeka:

What cryptographic primitives exist that support these complex capabilities while retaining the same hiding properties of hashing?

The answer to this question is quite technical. If you're motivated to learn more, check out the [technical](/technical) folder!

---

[alex@ajiang.xyz](mailto:alex@ajiang.xyz). Discord: @syossu
