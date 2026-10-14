# Local changes from keepass 0.15.2

This is the upstream `keepass` 0.15.2 source with two compatibility changes:

- `quick-xml` is built with `overlapped-lists`, so repeated KeePass elements such as `<String>` can be separated by other elements.
- Protected strings and binaries are decrypted in XML document order before serde parsing. KeePass uses one inner cipher stream in that order; history can sit between string fields.

The upstream crate is MIT licensed. See `LICENSE`.
