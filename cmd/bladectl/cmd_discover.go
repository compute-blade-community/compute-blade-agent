package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/compute-blade-community/compute-blade-agent/pkg/discovery"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	discoverWait time.Duration
	discoverSave bool
)

func init() {
	cmdDiscover.Flags().DurationVarP(&discoverWait, "wait", "w", 3*time.Second, "how long to listen for blades")
	cmdDiscover.Flags().BoolVar(&discoverSave, "save", false,
		"add discovered blades to the bladectl config and update the address of configured ones")
	rootCmd.AddCommand(cmdDiscover)
}

var cmdDiscover = &cobra.Command{
	Use:   "discover",
	Short: "Find compute-blade-agents on the local network",
	Long: "Finds compute-blade-agents announcing their API via mDNS (_compute-blade._tcp). Only agents listening on TCP\n" +
		"announce themselves.\n\n" +
		"With --save, blades without authentication are added to the bladectl config and the address of blades that are\n" +
		"already configured is updated. Blades requiring mTLS can't be added automatically: copy their client\n" +
		"certificate from ~/.config/bladectl/config.yaml on the blade first.",
	Example: "bladectl discover\n" +
		"bladectl discover --save\n" +
		"bladectl discover --save && bladectl get status --all",
	Args: cobra.ExactArgs(0),
	// discover works without (or with an incomplete) bladectl config, so skip the root's client setup
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, cfgPath, err := loadBladectlConfig()
		if err != nil {
			return err
		}

		blades, err := discovery.Browse(cmd.Context(), discoverWait)
		if err != nil {
			return err
		}
		if len(blades) == 0 {
			fmt.Println("No compute-blade-agents found. Agents only announce themselves when their API listens on TCP.")
			return nil
		}

		results := make([]config.DiscoveryResult, len(blades))
		for idx, blade := range blades {
			results[idx] = cfg.MergeDiscovered(blade.Name, blade.Server(), blade.Authenticated)
		}

		printDiscoveredBlades(blades, results)

		if !discoverSave {
			return nil
		}
		if err := writeBladectlConfig(cfgPath, cfg); err != nil {
			return err
		}
		fmt.Printf("\nSaved %s\n", cfgPath)
		return nil
	},
}

// loadBladectlConfig reads the bladectl config, or returns an empty one if none exists yet.
func loadBladectlConfig() (*config.BladectlConfig, string, error) {
	cfg := &config.BladectlConfig{}

	err := viper.ReadInConfig()
	var notFound viper.ConfigFileNotFoundError
	switch {
	case errors.As(err, &notFound):
		dir, herr := config.EnsureBladectlConfigHome()
		if herr != nil {
			return nil, "", errors.New(herr.Display())
		}
		return cfg, filepath.Join(dir, "config.yaml"), nil
	case err != nil:
		return nil, "", err
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, "", err
	}
	return cfg, viper.ConfigFileUsed(), nil
}

func writeBladectlConfig(path string, cfg *config.BladectlConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// the config may contain client keys
	return os.WriteFile(path, data, fs.FileMode(0o600))
}

func discoveryResultLabel(result config.DiscoveryResult) string {
	switch result {
	case config.DiscoveryUnchanged:
		return okStyle().Render("configured")
	case config.DiscoveryUpdated:
		return warnStyle().Render("address changed")
	case config.DiscoveryAdded:
		return warnStyle().Render("new")
	case config.DiscoveryNeedsCredentials:
		return warnStyle().Render("new, needs mTLS credentials")
	case config.DiscoveryLocal:
		return okStyle().Render("configured (local)")
	default:
		return ""
	}
}

func printDiscoveredBlades(blades []discovery.Blade, results []config.DiscoveryResult) {
	tbl := tablewriter.NewTable(os.Stdout,
		tablewriter.WithHeader([]string{"Blade", "Server", "Addresses", "Version", "Auth", "Config"}),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoFormat(tw.Off),
	)

	for idx, blade := range blades {
		addresses := make([]string, 0, len(blade.Addresses))
		for _, ip := range blade.Addresses {
			if ip.To4() != nil || !ip.IsLinkLocalUnicast() {
				addresses = append(addresses, ip.String())
			}
		}

		auth := "none"
		if blade.Authenticated {
			auth = "mTLS"
		}

		_ = tbl.Append([]string{
			blade.Name,
			net.JoinHostPort(blade.Host, strconv.Itoa(blade.Port)),
			strings.Join(addresses, ", "),
			blade.Version,
			auth,
			discoveryResultLabel(results[idx]),
		})
	}

	_ = tbl.Render()
}
