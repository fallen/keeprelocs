# Keeprelocs

If you are trying to boot Xen.efi and you get this error message:

```
Xen 4.17.5-13 (c/s 430ce6cd9365, pq 3941a9ecb541) EFI loader
Unsupported relocation type
```

It means your Xen.efi `.reloc` section has the `MEM_DISCARDABLE` flag in its section header and somehow your loader (be it
your UEFI fw or shim or your patched grub2) honored this flag and did not load Xen.efi's `.reloc` section.

However Xen.efi boot path parses the .reloc section twice:
* there https://elixir.bootlin.com/xen/v4.20.1/source/xen/common/efi/boot.c#L1362
* and there https://elixir.bootlin.com/xen/v4.20.1/source/xen/arch/x86/efi/efi-boot.h#L237

You can run this tool to strip the `MEM_DISCARDABLE` bit from your EFI PE file.
