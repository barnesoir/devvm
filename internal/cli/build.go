package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/devvmhq/devvm/internal/backend"
	"github.com/devvmhq/devvm/internal/build"
	"github.com/devvmhq/devvm/internal/from"
	"github.com/devvmhq/devvm/internal/image"
	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/ui"
)

// newBuildCmd is devvm build IMAGE.
func newBuildCmd(a *app) *cobra.Command {
	var f imageFlags
	cmd := &cobra.Command{
		Use:   "build IMAGE",
		Short: "Build an image and the images under it, unless they're built",
		Long: "Build an image and the images under it, unless they're built. " +
			"IMAGE is base, or layers joined with + bottom first, so foo+bar is bar on foo on base. " +
			"An image holds no shared tools: a VM gets those when devvm makes it, or with devvm tools.",
		Example: examples(
			"devvm build docker", "build base and the docker layer on it",
			"devvm build foo+bar", "build base, foo and foo+bar"),
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return imageCmd(cmd.Context(), a, f, args[0], build.Builds.Build)
		},
	}
	f.add(cmd)
	return cmd
}

// newRebuildCmd is devvm rebuild IMAGE.
func newRebuildCmd(a *app) *cobra.Command {
	var f imageFlags
	cmd := &cobra.Command{
		Use:   "rebuild IMAGE",
		Short: "Build an image again, and delete the old one",
		Long: "Build an image again from its parent as it is, then delete the stale images " +
			"no VM uses, the old one and those built on it among them. " +
			"When images are built on it, devvm asks first in a terminal without --no-input.",
		Example: examples(
			"devvm rebuild foo", "build foo again with the newest packages",
			"devvm rebuild base --force", "rebuild base without asking, as a script must",
		),
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return imageCmd(cmd.Context(), a, f, args[0], build.Builds.Rebuild)
		},
	}
	f.add(cmd)
	addForceFlag(cmd.Flags(), &f.force)
	return cmd
}

// imageFlags are the flags of the commands that build or delete an image
// by its name: the container image its base starts from; rebuild's
// --force too.
type imageFlags struct {
	from  string
	force bool
}

func (f *imageFlags) add(cmd *cobra.Command) {
	addFromFlag(cmd.Flags(), &f.from)
}

// imageCmd runs do on the builds of the backend new VMs get, once the
// name is one (read once, here) and the backend can run.
func imageCmd(ctx context.Context, a *app, f imageFlags, name string, do func(build.Builds, context.Context, image.Name) error) error {
	b, err := a.builder()
	if err == nil {
		b.From, b.Force = fromRef(f.from), f.force
		err = from.Check(b.From)
	}
	var img image.Name
	if err == nil {
		img, err = build.Names{Env: b}.Parse(name)
	}
	if err == nil {
		err = backend.Check(ctx, b.Backend)
	}
	if err == nil {
		err = do(build.Builds{Env: b}, ctx, img)
	}
	return failed(err, func(reason string) msg.M { return msg.BuildFailed(name, reason) })
}

// pickFeatures returns what asks which features base gets, in u's
// terminal; without one, they stay as they are.
func pickFeatures(u *ui.UI) func([]build.Feature) []build.Feature {
	return func(fs []build.Feature) []build.Feature {
		choices := make([]ui.Choice, len(fs))
		for i, f := range fs {
			choices[i] = ui.Choice{Name: f.Name, Desc: f.Desc, On: f.On}
		}
		// A list that couldn't show keeps the features as they were.
		sections, _ := u.Pick(msg.FeaturesHelp(), []ui.Section{{Choices: choices}})
		picked := sections[0].Choices
		out := make([]build.Feature, len(picked))
		for i, c := range picked {
			out[i] = build.Feature{Name: c.Name, Desc: c.Desc, On: c.On}
		}
		return out
	}
}
