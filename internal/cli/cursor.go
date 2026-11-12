package cli

import (
	"github.com/spf13/cobra"

	"github.com/devvmhq/devvm/internal/agents"
	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/vm"
)

// newCursorCmd is devvm cursor (Remote-SSH editor; agents.Cursor names the coding agent too).
func newCursorCmd(a *app) *cobra.Command {
	var include bool
	cmd := &cobra.Command{
		Use: agents.Cursor,
		Annotations: about{
			docs: "using/ssh#cursor", group: groupVM,
			noJSON: "it opens Cursor",
		}.annotations(),
		Short: "Open this folder's VM in Cursor over Remote-SSH",
		Long: "Get this folder's VM ready as devvm host does, then open its folder in Cursor over Remote-SSH, " +
			"with Cursor's cursor command.",
		Example: examples(
			"devvm cursor", "open this folder's VM in Cursor",
			"devvm cursor --ssh-config", "the same, adding devvm's Include line to ~/.ssh/config without asking",
		),
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.env(func(env *vm.Env) error {
				env.AddInclude = include
				return vm.Launch{Env: env}.Cursor(cmd.Context())
			}, msg.CursorFailed)
		},
	}
	addSSHConfigFlag(cmd.Flags(), &include)
	addFolderFlags(cmd, a)
	return cmd
}
