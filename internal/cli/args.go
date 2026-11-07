package cli

import (
	"errors"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/netpolicy"
	"github.com/devvmhq/devvm/internal/settings"
	"github.com/devvmhq/devvm/internal/sshagent"
	"github.com/devvmhq/devvm/internal/state"
	"github.com/devvmhq/devvm/internal/upgrade"
	"github.com/devvmhq/devvm/internal/vm"
)

// usageCode is the exit code of a usage error: a bad argument or flag, or
// an unknown command or word.
const usageCode = 2

// exclusiveKey is the annotation that lists a command's flags that can't
// be given together, as exclusive records them.
const exclusiveKey = "devvm-exclusive"

// usageError is an error in how devvm was run, found before the command
// does anything: Execute prints it, names the command's --help and exits
// with usageCode.
type usageError struct{ m msg.M }

func (e usageError) Error() string { return e.m.Error() }
func (e usageError) Unwrap() error { return e.m }

// usage makes err a usage error: a message as it is, anything else (the
// command-line parser's own) in usage_error.
func usage(err error) usageError {
	if e, ok := errors.AsType[usageError](err); ok {
		return e
	}
	m, ok := errors.AsType[msg.M](err)
	if !ok {
		m = msg.UsageError(err.Error()).Because(err)
	}
	return usageError{m}
}

// ranError is an error a command's RunE returned, once it ran, or the
// root's layout check (checkLayout): a failure, which showFailure prints,
// not a usage error.
type ranError struct{ err error }

func (e ranError) Error() string { return e.err.Error() }
func (e ranError) Unwrap() error { return e.err }

// checkCommands makes every command under root check its flags and
// arguments before anything else runs (root's PersistentPreRunE, any VM
// lookup), each error a usage error, and marks what RunE returns as a
// failure. The parser's flag errors become usage errors too (flagError).
func checkCommands(root *cobra.Command) {
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return usage(flagError(c, err)) })
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		checkCommand(c)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// checkCommand is what checkCommands does to each command: c checks its
// flags and arguments first, and RunE's errors are failures.
func checkCommand(c *cobra.Command) {
	args := c.Args
	c.Args = func(cmd *cobra.Command, a []string) error {
		if err := noBlanks(cmd, a); err != nil {
			return usage(err)
		}
		if err := checkFlags(cmd); err != nil {
			return usage(err)
		}
		if args != nil {
			if err := args(cmd, a); err != nil {
				return usage(err)
			}
		}
		return nil
	}
	if run := c.RunE; run != nil {
		c.RunE = func(cmd *cobra.Command, a []string) error {
			if err := run(cmd, a); err != nil {
				return ranError{err}
			}
			return nil
		}
	}
}

// argsOf is the arguments in c's Use, without its flags: KEY_FILE,
// [all|none|LIST], RULE...; "" for none.
func argsOf(c *cobra.Command) string {
	var out []string
	depth, start := 0, -1
	use := c.Use
	if i := strings.IndexByte(use, ' '); i >= 0 {
		use = use[i+1:]
	} else {
		use = ""
	}
	for i, r := range use + " " {
		switch {
		case r == '[':
			if depth == 0 && start < 0 {
				start = i
			}
			depth++
		case r == ']':
			depth--
		case r == ' ' && depth == 0 && start >= 0:
			if w := use[start:i]; !strings.HasPrefix(strings.TrimLeft(w, "["), "-") {
				out = append(out, w)
			}
			start = -1
		case r != ' ' && start < 0:
			start = i
		}
	}
	return strings.Join(out, " ")
}

// shownArgs is args as a message shows them: as typed, apart.
func shownArgs(args []string) string { return strings.Join(args, " ") }

// noArgs takes no arguments. A command with commands of its own says the
// word isn't one of them; devvm itself suggests the closest (checkWord).
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if !cmd.HasParent() {
		return checkWord(cmd, args[0])
	}
	if cmd.HasAvailableSubCommands() {
		var names []string
		for _, c := range cmd.Commands() {
			if c.IsAvailableCommand() {
				names = append(names, c.Name())
			}
		}
		return msg.NoSubcommand(cmd.CommandPath(), strings.Join(names, ", "), args[0])
	}
	return msg.ArgsNone(cmd.CommandPath(), shownArgs(args))
}

// argsN takes from least to most arguments (most < 0: any number), each
// one of the command's ValidArgs when it has them.
func argsN(least, most int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		switch {
		case len(args) < least:
			return msg.ArgMissing(argsOf(cmd), cmd.CommandPath())
		case most == 0:
			return noArgs(cmd, args)
		case most > 0 && len(args) > most:
			return msg.ArgsTooMany(argsOf(cmd), cmd.CommandPath(), shownArgs(args))
		}
		if len(cmd.ValidArgs) == 0 {
			return nil
		}
		for _, a := range args {
			if !slices.Contains(cmd.ValidArgs, a) {
				return msg.ArgNotChoice(strings.Join(cmd.ValidArgs, ", "), cmd.CommandPath(), a)
			}
		}
		return nil
	}
}

// exactArgs takes n arguments; maxArgs at most n; minArgs at least n.
func exactArgs(n int) cobra.PositionalArgs { return argsN(n, n) }
func maxArgs(n int) cobra.PositionalArgs   { return argsN(0, n) }
func minArgs(n int) cobra.PositionalArgs   { return argsN(n, -1) }

// exclusive marks cmd's flags names as not given together: Cobra's own
// mark, for completion, and exclusiveKey, which checkFlags checks before
// anything runs.
func exclusive(cmd *cobra.Command, names ...string) {
	cmd.MarkFlagsMutuallyExclusive(names...)
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	groups := cmd.Annotations[exclusiveKey]
	if groups != "" {
		groups += ";"
	}
	cmd.Annotations[exclusiveKey] = groups + strings.Join(names, " ")
}

// checkFlags checks the flags given to cmd: none of a group exclusive
// marked on it or a command above it together, and each value
// checkFlagValue knows.
func checkFlags(cmd *cobra.Command) error {
	f := cmd.Flags()
	for c := cmd; c != nil; c = c.Parent() {
		for group := range strings.SplitSeq(c.Annotations[exclusiveKey], ";") {
			var set []string
			for _, name := range strings.Fields(group) {
				if fl := f.Lookup(name); fl != nil && fl.Changed {
					set = append(set, "--"+name)
				}
			}
			if len(set) > 1 {
				return msg.FlagsExclusive(set[0], set[1])
			}
		}
	}
	var err error
	f.Visit(func(fl *pflag.Flag) {
		if err == nil {
			err = checkFlagValue(fl.Name, fl.Value.String())
		}
	})
	if err != nil {
		return err
	}
	// Cobra checks these only after the root's PersistentPreRunE: a group
	// marked without exclusive, or a required flag, is refused first too,
	// in usage_error.
	if err := cmd.ValidateRequiredFlags(); err != nil {
		return err
	}
	return cmd.ValidateFlagGroups()
}

// checkFlagValue checks the value of a flag, by its name, as each flag
// name has one meaning: what devvm would refuse later, refused first.
func checkFlagValue(name, value string) error {
	var err error
	switch name {
	case "cpus":
		_, err = settings.ParseCPUs("--cpus", value)
	case "memory", "disk":
		_, err = settings.ParseGiB("--"+name, value)
	case "ports":
		_, err = settings.ParsePorts(value)
	case "network":
		if _, _, ok := netpolicy.Choice(value); !ok {
			err = msg.ArgNotChoice(strings.Join(netpolicy.Choices(), ", "), "--network", value)
		}
	case "lifetime":
		if value != "" {
			err = sshagent.CheckLifetime(value)
		}
	case "as":
		err = vm.CheckLinkName(value)
	case "older-than":
		_, err = state.ParseDuration(value)
	case "tools", "agents", "layers":
		err = checkPartFlag("--"+name, value)
	case "to":
		if !upgrade.Valid(strings.TrimPrefix(value, "v")) {
			err = msg.UpgradeNotVersion(value)
		}
	}
	return err
}

// flagError is the message for a flag the parser refused: unknown, without
// its value, or with one it can't take.
func flagError(c *cobra.Command, err error) error {
	if e, ok := errors.AsType[*pflag.NotExistError](err); ok {
		return msg.FlagUnknown(c.CommandPath(), flagName(e.GetSpecifiedName(), e.GetSpecifiedShortnames()))
	}
	if e, ok := errors.AsType[*pflag.ValueRequiredError](err); ok {
		name := flagName(e.GetSpecifiedName(), e.GetSpecifiedShortnames())
		return msg.FlagNeedsValue(name, name+" "+flagForm(e.GetFlag()))
	}
	if e, ok := errors.AsType[*pflag.InvalidValueError](err); ok {
		if m, ok := errors.AsType[msg.M](e.Unwrap()); ok {
			return m
		}
		name, value := "--"+e.GetFlag().Name, e.GetValue()
		if e.GetFlag().Value.Type() == "bool" {
			return msg.FlagBadSwitch(name, value)
		}
		return msg.FlagBadValue(name, flagForm(e.GetFlag()), value)
	}
	if e, ok := errors.AsType[*pflag.InvalidSyntaxError](err); ok {
		return msg.FlagUnknown(c.CommandPath(), e.GetSpecifiedFlag())
	}
	return err
}

// flagName is a flag as it was given: --name, or -n within a group of
// shorthands.
func flagName(name, shorthands string) string {
	if shorthands != "" {
		return "-" + name
	}
	return "--" + name
}

// flagForm is what a flag's value is, as its help names it: N, GiB, AGE.
func flagForm(f *pflag.Flag) string {
	name, _ := pflag.UnquoteUsage(f)
	return name
}
