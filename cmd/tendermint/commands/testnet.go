package commands

import (
	gobytes "bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/bytes"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

var (
	nValidators    int
	nNonValidators int
	configFile     string
	outputDir      string
	nodeDirPrefix  string

	populatePersistentPeers bool
	hostnamePrefix          string
	hostnameSuffix          string
	startingIPAddress       string
	hostnames               []string
	p2pPort                 int
	randomMonikers          bool

	setEntropyFiles bool
)

const (
	nodeDirPerm = 0755
)

func init() {
	TestnetFilesCmd.Flags().IntVar(&nValidators, "v", 4,
		"Number of validators to initialize the testnet with")
	TestnetFilesCmd.Flags().StringVar(&configFile, "config", "",
		"Config file to use (note some options may be overwritten)")
	TestnetFilesCmd.Flags().IntVar(&nNonValidators, "n", 0,
		"Number of non-validators to initialize the testnet with")
	TestnetFilesCmd.Flags().StringVar(&outputDir, "o", "./mytestnet",
		"Directory to store initialization data for the testnet")
	TestnetFilesCmd.Flags().StringVar(&nodeDirPrefix, "node-dir-prefix", "node",
		"Prefix the directory name for each node with (node results in node0, node1, ...)")

	TestnetFilesCmd.Flags().BoolVar(&populatePersistentPeers, "populate-persistent-peers", true,
		"Update config of each node with the list of persistent peers build using either"+
			" hostname-prefix or"+
			" starting-ip-address")
	TestnetFilesCmd.Flags().StringVar(&hostnamePrefix, "hostname-prefix", "node",
		"Hostname prefix (\"node\" results in persistent peers list ID0@node0:26656, ID1@node1:26656, ...)")
	TestnetFilesCmd.Flags().StringVar(&hostnameSuffix, "hostname-suffix", "",
		"Hostname suffix ("+
			"\".xyz.com\""+
			" results in persistent peers list ID0@node0.xyz.com:26656, ID1@node1.xyz.com:26656, ...)")
	TestnetFilesCmd.Flags().StringVar(&startingIPAddress, "starting-ip-address", "",
		"Starting IP address ("+
			"\"192.168.0.1\""+
			" results in persistent peers list ID0@192.168.0.1:26656, ID1@192.168.0.2:26656, ...)")
	TestnetFilesCmd.Flags().StringArrayVar(&hostnames, "hostname", []string{},
		"Manually override all hostnames of validators and non-validators (use --hostname multiple times for multiple hosts)")
	TestnetFilesCmd.Flags().IntVar(&p2pPort, "p2p-port", 26656,
		"P2P Port")
	TestnetFilesCmd.Flags().BoolVar(&randomMonikers, "random-monikers", false,
		"Randomize the moniker for each generated node")
	TestnetFilesCmd.Flags().BoolVar(&setEntropyFiles, "set-entropy-files", false, "Enforce existence of entropy key files")
}

// TestnetFilesCmd allows initialisation of files for a Tendermint testnet.
var TestnetFilesCmd = &cobra.Command{
	Use:   "testnet",
	Short: "Initialize files for a Tendermint testnet",
	Long: `testnet will create "v" + "n" number of directories and populate each with
necessary files (private validator, genesis, config, etc.).

Note, strict routability for addresses is turned off in the config file.

Optionally, it will fill in persistent_peers list in config file using either hostnames or IPs.

Example:

	tendermint testnet --v 4 --o ./output --populate-persistent-peers --starting-ip-address 192.168.10.2
	`,
	RunE: testnetFiles,
}

func testnetFiles(cmd *cobra.Command, args []string) error {
	if len(hostnames) > 0 && len(hostnames) != (nValidators+nNonValidators) {
		return fmt.Errorf(
			"testnet needs precisely %d hostnames (number of validators plus non-validators) if --hostname parameter is used",
			nValidators+nNonValidators,
		)
	}

	config := cfg.DefaultConfig()

	// overwrite default config if set and valid
	if configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
		if err := viper.Unmarshal(config); err != nil {
			return err
		}
		if err := config.ValidateBasic(); err != nil {
			return err
		}
	}

	genVals := make([]types.GenesisValidator, nValidators)
	entropyValidators := make(types.ValidatorsByAddress, nValidators)

	for i := 0; i < nValidators; i++ {
		nodeDirName := fmt.Sprintf("%s%d", nodeDirPrefix, i)
		nodeDir := filepath.Join(outputDir, nodeDirName)
		config.SetRoot(nodeDir)

		err := os.MkdirAll(filepath.Join(nodeDir, "config"), nodeDirPerm)
		if err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}
		err = os.MkdirAll(filepath.Join(nodeDir, "data"), nodeDirPerm)
		if err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}

		initFilesWithConfig(config)

		pvKeyFile := filepath.Join(nodeDir, config.BaseConfig.PrivValidatorKey)
		pvStateFile := filepath.Join(nodeDir, config.BaseConfig.PrivValidatorState)
		pv := privval.LoadFilePV(pvKeyFile, pvStateFile)

		pubKey, err := pv.GetPubKey()
		if err != nil {
			return errors.Wrap(err, "can't get pubkey")
		}
		genVals[i] = types.GenesisValidator{
			Address: pubKey.Address(),
			PubKey:  pubKey,
			Power:   1,
			Name:    nodeDirName,
		}

		entropyValidators[i] = &types.Validator{Address: pubKey.Address()}
	}

	// Sort genesis validators
	if setEntropyFiles {
		sort.Sort(entropyValidators)
		for i := 0; i < nValidators; i++ {
			address := genVals[i].Address
			idx := sort.Search(len(entropyValidators), func(i int) bool {
				return gobytes.Compare(address, entropyValidators[i].Address) <= 0
			})
			if idx < len(entropyValidators) && gobytes.Equal(entropyValidators[idx].Address, address) {
				err := moveEntropyFile(idx, i)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("genValidators and entropyValidators mismatch")
			}
		}
	}

	for i := 0; i < nNonValidators; i++ {
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("%s%d", nodeDirPrefix, i+nValidators))
		config.SetRoot(nodeDir)

		err := os.MkdirAll(filepath.Join(nodeDir, "config"), nodeDirPerm)
		if err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}

		err = os.MkdirAll(filepath.Join(nodeDir, "data"), nodeDirPerm)
		if err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}

		initFilesWithConfig(config)

		if setEntropyFiles {
			err = moveEntropyFile(0, i+nValidators)
			if err != nil {
				return err
			}
		}
	}

	// Generate genesis doc from generated validators
	genDoc := &types.GenesisDoc{
		ChainID:         "chain-" + tmrand.Str(6),
		ConsensusParams: types.DefaultConsensusParams(),
		GenesisTime:     tmtime.Now(),
		Validators:      genVals,
		Entropy:         "Fetch.ai Test Genesis Entropy",
	}

	// Write genesis file.
	for i := 0; i < nValidators+nNonValidators; i++ {
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("%s%d", nodeDirPrefix, i))
		if err := genDoc.SaveAs(filepath.Join(nodeDir, config.BaseConfig.Genesis)); err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}
	}

	// Gather persistent peer addresses.
	var (
		persistentPeers string
		err             error
	)
	if populatePersistentPeers {
		persistentPeers, err = persistentPeersString(config)
		if err != nil {
			_ = os.RemoveAll(outputDir)
			return err
		}
	}

	// Overwrite default config.
	for i := 0; i < nValidators+nNonValidators; i++ {
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("%s%d", nodeDirPrefix, i))
		config.SetRoot(nodeDir)
		config.P2P.AddrBookStrict = false
		config.P2P.AllowDuplicateIP = true
		if populatePersistentPeers {
			config.P2P.PersistentPeers = persistentPeers
		}
		config.Moniker = moniker(i)

		cfg.WriteConfigFile(filepath.Join(nodeDir, "config", "config.toml"), config)
	}

	fmt.Printf("Successfully initialized %v node directories\n", nValidators+nNonValidators)
	return nil
}

func moveEntropyFile(entropyIndex int, nodeIndex int) error {
	relevantIndex := entropyIndex
	// Check if node is validator
	if nodeIndex >= nValidators {
		relevantIndex = nodeIndex
	}
	oldEntropyFile := filepath.Join(outputDir, fmt.Sprintf("%d.json", relevantIndex))
	_, findFileErr := os.Stat(oldEntropyFile)
	if os.IsNotExist(findFileErr) {
		return fmt.Errorf("entropy key file %v does not exist", oldEntropyFile)
	}
	newEntropyFile := filepath.Join(filepath.Join(outputDir, fmt.Sprintf("%s%d", nodeDirPrefix, nodeIndex)), config.EntropyKey)
	// Move key file into correct directory
	return os.Rename(oldEntropyFile, newEntropyFile)
}

func hostnameOrIP(i int) string {
	if len(hostnames) > 0 && i < len(hostnames) {
		return hostnames[i]
	}
	if startingIPAddress == "" {
		return fmt.Sprintf("%s%d%s", hostnamePrefix, i, hostnameSuffix)
	}
	ip := net.ParseIP(startingIPAddress)
	ip = ip.To4()
	if ip == nil {
		fmt.Printf("%v: non ipv4 address\n", startingIPAddress)
		os.Exit(1)
	}

	for j := 0; j < i; j++ {
		ip[3]++
	}
	return ip.String()
}

func persistentPeersString(config *cfg.Config) (string, error) {
	persistentPeers := make([]string, nValidators+nNonValidators)
	for i := 0; i < nValidators+nNonValidators; i++ {
		nodeDir := filepath.Join(outputDir, fmt.Sprintf("%s%d", nodeDirPrefix, i))
		config.SetRoot(nodeDir)
		nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
		if err != nil {
			return "", err
		}
		persistentPeers[i] = p2p.IDAddressString(nodeKey.ID(), fmt.Sprintf("%s:%d", hostnameOrIP(i), p2pPort))
	}
	return strings.Join(persistentPeers, ","), nil
}

func moniker(i int) string {
	if randomMonikers {
		return randomMoniker()
	}
	if len(hostnames) > 0 && i < len(hostnames) {
		return hostnames[i]
	}
	if startingIPAddress == "" {
		return fmt.Sprintf("%s%d%s", hostnamePrefix, i, hostnameSuffix)
	}
	return randomMoniker()
}

func randomMoniker() string {
	return bytes.HexBytes(tmrand.Bytes(8)).String()
}
