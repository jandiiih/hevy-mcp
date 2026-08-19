---
"hevy-mcp": patch
---

Make an attached container volume usable without running the server as root.

Hosted platforms mount volumes root-owned, so an image that starts as a
non-root user cannot write to one at all. Railway's guidance is to run the
whole container as root, which would also run the MCP server — holding OAuth
grants and users' Hevy keys — with root privileges.

The entrypoint now starts as root only long enough to hand the OAuth store
directory to the unprivileged `node` user, then execs the server as that user
via `su-exec`. A container that starts unprivileged still runs the server
directly, and an unusable mount degrades to memory-only rather than blocking
startup.
