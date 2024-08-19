## Betterscale tools

### Usage

```
Usage: betterscale <command> [<args>]

Betterscale tools

Options:
  --help            display usage information

Commands:
  dhtnode           Generates DHT node entry
  zerostate         Generates zerostate boc file
  account           Account state creation tools
  keypair           Generates ed25519 key pair
  config            Network config tools
  mine              Generates required address for the contract
  -v, --version     print version information and exit
```

### Example

```bash
N=3
GIVER_BALANCE="1000000000000000000" # 1B tokens for giver
VALIDATOR_BALANCE="1000000000000000" # 1M tokens per validator

ZEROSTATE_TEMPLATE="./examples/zerostate-config.json"

NETWORK_DIR="./mynetwork"
rm -rf "$NETWORK_DIR"
mkdir -p "$NETWORK_DIR"

GEN_UTIME=$(date +%s) # or set explicitly

# Generate validator keys (other tools can be used)
for i in $(seq $N); do
    betterscale keypair > "$NETWORK_DIR/validator-${i}.keys.json"
done

# Prepare zerostate
zerostate=$(cat "$ZEROSTATE_TEMPLATE" | \
    jq ".gen_utime = $GEN_UTIME" | \
    jq ".config.validators_public_keys = []"
)

# Set config keys
betterscale keypair > "$NETWORK_DIR/config.keys.json"
config_public_key=$(jq .public "$NETWORK_DIR/config.keys.json")
minter_public_key="$config_public_key"
zerostate=$(echo "$zerostate" | \
    jq ".config_public_key = $config_public_key" | \
    jq ".minter_public_key = $minter_public_key"
)

# Add giver account
betterscale keypair > "$NETWORK_DIR/giver.keys.json"
giver_public_key=$(jq -r .public "$NETWORK_DIR/giver.keys.json")
giver_account=$(betterscale account wallet \
    --pubkey "$giver_public_key" \
    --balance "$GIVER_BALANCE"
)
giver_account_address=$(echo "$giver_account" | jq .address)
giver_account_boc=$(echo "$giver_account" | jq .boc)
zerostate=$(echo "$zerostate" | \
    jq ".accounts[$giver_account_address] = $giver_account_boc" | \
    jq ".config.fundamental_addresses += [$giver_account_address]"
)

# Prepare global config
global_config=$(cat <<-END
{
  "@type": "config.global",
  "dht": {
    "@type": "dht.config.global",
    "k": 6,
    "a": 3,
    "static_nodes": {
      "@type": "dht.nodes",
      "nodes": [
      ]
    }
  }
}
END
)

# Fill zerostate and global config with validators
for i in $(seq $N); do
    port=(20000 + i)
    public_key=$(jq -r .public "$NETWORK_DIR/validator-${i}.keys.json")
    secret_key=$(jq -r .secret "$NETWORK_DIR/validator-${i}.keys.json")

    # Generate and add DHT entry
    dht_entry=$(betterscale dhtnode --address "127.0.0.1:${i}" --secret "$secret_key")
    global_config=$(echo $global_config | jq ".dht.static_nodes.nodes += [${dht_entry}]")

    # Generate validator account
    account=$(betterscale account wallet \
        --pubkey "$public_key" \
        --balance "$VALIDATOR_BALANCE"
    )
    account_address=$(echo $account | jq .address)
    account_boc=$(echo $account | jq .boc)

    zerostate=$(echo "$zerostate" | jq ".accounts[$account_address] = $account_boc")
    zerostate=$(echo "$zerostate" | jq ".config.validators_public_keys += [\"$public_key\"]")
done

# Generate zerostate BOC
echo "$zerostate" > "$NETWORK_DIR/zerostate.json"
zerostate_id=$(betterscale zerostate \
    --config "$NETWORK_DIR/zerostate.json" \
    --output "$NETWORK_DIR/"
)

# Set zerostate id in the global config
global_config=$(echo "$global_config" | jq ".validator = $zerostate_id")

# Fix u64 in jq
global_config=$(echo "$global_config" | sed -e 's/-9223372036854776000/-9223372036854775808/g')

# Write global config
echo "$global_config" > "$NETWORK_DIR/global-config.json"
```
