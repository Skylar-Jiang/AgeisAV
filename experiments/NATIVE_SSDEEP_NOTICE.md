# Research SSDeep translation

`native_ssdeep.c` translates the algorithm in the installed ppdeep 20260221
`_spamsum` implementation by Marcin Ulikowski, based on SpamSum by Andrew Tridgell.
The original package identifies Apache License 2.0 and
https://github.com/elceef/ppdeep as its source. The C translation retains that
license. See https://www.apache.org/licenses/LICENSE-2.0 for the license terms;
retain this attribution and the license when redistributing a build.
The standard license text is included in `NATIVE_SSDEEP_LICENSE.txt`.

This is an experimental implementation, not upstream ssdeep/libfuzzy and not a
validated replacement for all ssdeep implementations. Its parity target is the
project's pinned ppdeep 20260221 byte-to-digest behavior, including empty and
low-entropy inputs. No production code automatically loads the compiled library.
