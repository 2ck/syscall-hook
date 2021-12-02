# syscall-hook - Replace an existing syscall

This linux kernel module provides an example of hooking and replacing an existing
syscall in a kernel with security updates that block older methods (e.g. >=5.0 or >=5.7).

The following workarounds are needed:
- The `sys_call_table` isn't exported by default (since 2.6), and a previous workaround
using `kallsyms_lookup_name` no longer works because that function isn't exported either (since 5.7).
Therefore, this module uses kprobes to get the address of `kallsyms_lookup_name`.
- In order to write to read-only pages, bit `16` (write protect) of the `CR0` register has to be unset.
The function `write_cr0` normally used for this has been amended to pin that bit (since 5.0). A custom
function that directly writes to the `CR0` register is created to bypass this restriction.

## 

Latest kernel version tested: `5.15.5-zen1-1-zen`
