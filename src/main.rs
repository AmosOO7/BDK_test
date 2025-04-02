use bdk_wallet::keys::{
    bip39::{Mnemonic, Language, WordCount},
    DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
};
use bdk_wallet::descriptor::Segwitv0;
use bdk_wallet::bitcoin::Network;
use secp256k1::Secp256k1;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a 12-word mnemonic
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> = Mnemonic::generate((WordCount::Words12, Language::English))
        .map_err(|e| format!("Failed to generate mnemonic: {:?}", e))?;

    // Convert mnemonic to string
    let mnemonic_str = mnemonic.to_string();
    println!("Generated Mnemonic: {}", mnemonic_str);

    // Convert mnemonic to ExtendedKey<Segwitv0>
    let xkey: ExtendedKey<Segwitv0> = mnemonic.into_extended_key()?;

    // Derive the extended private key (Xpriv)
    let xprv = xkey.into_xprv(Network::Bitcoin).ok_or("Failed to derive xprv")?;

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Extract public key correctly
    let public_key = xprv.private_key.public_key(&secp);

    // Construct a SegWit descriptor
    let descriptor = format!("wpkh({})", public_key);

    println!("Generated Descriptor: {}", descriptor);

    Ok(())
}
