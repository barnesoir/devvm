package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/settings"
	"github.com/devvmhq/devvm/internal/ui"
)

// jsonVersion is the version of every --json shape. A shape only gains
// fields; any other change to one is a new version.
const jsonVersion = 1

// jsonFlag adds --json to a command that shows or lists something.
func jsonFlag(c *cobra.Command, on *bool) {
	c.Flags().BoolVar(on, "json", false, "print it as one JSON object, for scripts")
}

// wantsJSON reports whether the command was given --json.
func wantsJSON(cmd *cobra.Command) bool {
	f := cmd.Flags().Lookup("json")
	return f != nil && f.Changed && f.Value.String() == "true"
}

// showsOnly checks a command that shows a setting bare and changes it
// with a value: with --json it only shows, so a value (an argument, or
// one of the flags in sets) is refused before next checks the arguments.
func showsOnly(next cobra.PositionalArgs, sets ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if wantsJSON(cmd) {
			given := len(args) > 0
			for _, f := range sets {
				given = given || cmd.Flags().Changed(f)
			}
			if given {
				return msg.JSONShowsOnly(cmd.CommandPath())
			}
		}
		if next == nil {
			return nil
		}
		return next(cmd, args)
	}
}

// printValue writes a setting's value on a line of its own, or with
// asJSON as an object with its key.
func printValue(u *ui.UI, asJSON bool, key, value string) error {
	if asJSON {
		return printJSON(u, map[string]string{key: value})
	}
	_, err := io.WriteString(u.Stdout(), value+"\n")
	return err
}

// defaultOutput is a default's --json: its value by key, such as ports,
// and source, where it came from (a settings.Source).
type defaultOutput map[string]string

// printDefault writes a default in effect, v, as its value then a # and
// label, where it came from (settings.Source.Label), or with asJSON as a
// defaultOutput.
func printDefault(u *ui.UI, asJSON bool, key string, v settings.Value, label string) error {
	if asJSON {
		return printJSON(u, defaultOutput{key: v.Value, "source": string(v.Source)})
	}
	_, err := io.WriteString(u.Stdout(), v.Value+" # "+label+"\n")
	return err
}

// jsonTime is a time as --json has it: RFC 3339, in UTC, to the second;
// "" for the zero time.
func jsonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// printJSON writes v, a struct, to stdout as one indented JSON object
// with "version" first. HTML characters are written as they are.
func printJSON(u *ui.UI, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	body := bytes.TrimSpace(buf.Bytes())
	if len(body) < 2 || body[0] != '{' {
		return errors.New("--json output isn't an object")
	}
	obj := []byte(`{"version":` + strconv.Itoa(jsonVersion))
	if rest := bytes.TrimSpace(body[1:]); string(rest) != "}" {
		obj = append(obj, ',')
	}
	obj = append(obj, body[1:]...)
	var out bytes.Buffer
	if err := json.Indent(&out, obj, "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	_, err := u.Stdout().Write(out.Bytes())
	return err
}
