---
title: devvm network lock
weight: 38
explainer: "Lock this folder's VM to the hosts it learned, on the allowlist tier"
---

Lock this folder's VM to the hosts it learned, on the allowlist tier

## Synopsis

For this folder's VM, which learns the hosts it reaches, choose in a list which of the hosts it reached beyond its allowlist to add to its own rules, then give it the allowlist tier at once. Every host starts ticked but addresses, paste sites and file storage, so read the list before you confirm it. Without a terminal, --all adds every host and --none adds none, and --json lists the hosts and changes nothing.

```text
devvm network lock [flags]
```

## Examples

```text
  devvm network lock         # choose the hosts the VM keeps, then lock it to them
  devvm network lock --json  # list the hosts it learned, changing nothing
  devvm network lock --all   # keep every host it learned, without asking
```

## Options

```text
      --all      add every host the VM learned, without asking
  -h, --help     help for lock
      --here     use this folder's own VM, never that of a folder it's inside
      --json     print it as one JSON object, for scripts
      --none     add none of the hosts the VM learned, without asking
      --parent   use the VM of the nearest folder this one is inside, even across a git repo of its own
```

## Options inherited from parent commands

```text
      --no-input   never ask, and fail where devvm would ask, naming the flag that answers it
  -v, --verbose    show the output of the commands devvm runs instead of a status line
```

## Docs

[The docs page for devvm network lock](../safety/network.md#locking-it) explains it in full.

## See also

- [devvm network](devvm_network.md): Show or change the network tier of this folder's VM
