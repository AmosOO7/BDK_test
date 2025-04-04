use bdk_wallet::keys::{
    bip39::{Mnemonic, Language, WordCount},
    DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
};
use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpub},
    Network,
};
use secp256k1::Secp256k1;
use std::{error::Error, str::FromStr};
use std::process::Command;
use serde_json::Value;

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a 12-word mnemonic
    let mnemonic: GeneratedKey<Mnemonic, bdk_wallet::descriptor::Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|e| format!("Failed to generate mnemonic: {:?}", e))?;

    // Convert mnemonic to string
    let mnemonic_str = mnemonic.to_string();
    println!("Generated Mnemonic: {}", mnemonic_str);

    // Convert mnemonic to ExtendedKey
    let xkey: ExtendedKey<bdk_wallet::descriptor::Segwitv0> = mnemonic.into_extended_key()?;

    // Derive the extended private key (Xpriv)
    let secp = Secp256k1::new();
    let xprv = xkey.into_xprv(Network::Testnet).ok_or("Failed to derive xprv")?;

    // Get the master fingerprint
    let fingerprint = xprv.fingerprint(&secp);

    // Parse the derivation path
    let derivation_path = DerivationPath::from_str("m/84h/0h/0h")?;

    // Derive child extended private key
    let derived_xprv = xprv.derive_priv(&secp, &derivation_path)?;

    // Convert to extended public key (xpub)
    let xpub = Xpub::from_priv(&secp, &derived_xprv);

    // Construct the raw descriptor
    let raw_descriptor = format!("wpkh([{}{}]{}/*)", fingerprint, "/84h/0h/0h", xpub);

    // Run `bitcoin-cli -testnet getdescriptorinfo` to get the descriptor information including checksum
    let output = Command::new("bitcoin-cli")
        .arg("-testnet")
        .arg("getdescriptorinfo")
        .arg(&raw_descriptor)
        .output()?;

    if !output.status.success() {
        return Err(format!("Failed to execute bitcoin-cli: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    // Parse the JSON output to extract the checksum
    let output_str = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&output_str)?;
    let checksum = json["checksum"]
        .as_str()
        .ok_or("Checksum not found in the response")?;

    // Append the checksum to the raw descriptor
    let descriptor_with_checksum = format!("{}#{}", raw_descriptor, checksum);

    // Output the descriptor with the checksum
    println!("Generated HD Descriptor with Checksum: {}", descriptor_with_checksum);

    Ok(())
}
