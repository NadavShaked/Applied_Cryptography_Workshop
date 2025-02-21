use std::ops::{Add, Mul, MulAssign, Sub};
use bls12_381::{pairing, G1Affine, G2Affine, G1Projective, Scalar, G2Projective};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use hex::{decode, FromHex};
use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use sha2::digest::generic_array::GenericArray;
use warp::Filter;
use sha2::Sha256;

#[derive(Debug)]
struct HexArray<const N: usize>([u8; N]);

impl<const N: usize> Serialize for HexArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexArray<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(DeError::custom)?;
        if bytes.len() != N {
            return Err(DeError::custom(format!(
                "Invalid length: expected {} bytes, got {} bytes",
                N,
                bytes.len()
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(HexArray(array))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct RequestPayload {
    #[serde(with = "hex_array_96")]
    g_compressed: [u8; 96],
    #[serde(with = "hex_array_48")]
    sigma_compressed: [u8; 48],
    #[serde(with = "hex_array_96")]
    v_compressed: [u8; 96],
    #[serde(with = "hex_array_48")]
    multiplication_sum_compressed: [u8; 48],
    #[serde(with = "hex_array_32")]
    mu_sum_compressed: [u8; 32],
    #[serde(with = "hex_array_48")]
    u_compressed: [u8; 48],
}

mod hex_array_96 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<96>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

mod hex_array_48 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<48>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Serialize};
    use super::HexArray;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HexArray(*value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let array = HexArray::<32>::deserialize(deserializer)?;
        Ok(array.0)
    }
}

impl RequestPayload {
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

fn convert_u128_to_32_bytes(i: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];  // Create a 32-byte array, initially all zeros

    // Convert the u128 into bytes (16 bytes) and place it in the last 16 bytes of the array
    bytes[16..32].copy_from_slice(&i.to_be_bytes());  // Using big-endian format

    bytes
}

fn perform_hash_to_curve(i: u128) -> G1Affine {
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    // Convert u128 to 32-byte array
    let msg = convert_u128_to_32_bytes(i);

    // Perform hash-to-curve
    let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&msg, dst);

    // Convert from G1Projective to G1Affine
    G1Affine::from(&g)
}

fn hex_to_u64_4(hex_str: &str) -> [u64; 4] {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str); // Remove "0x" prefix if present
    let bytes = decode(hex_str).expect("Invalid hex string");
    assert!(bytes.len() == 32, "Hex string must represent 32 bytes");

    let mut result = [0u64; 4];
    for i in 0..4 {
        result[i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    result
}

fn hex_to_bytes_le(hex_str: &str) -> [u8; 32] {
    // Remove "0x" prefix if present
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Decode hex string to Vec<u8>
    let mut bytes = hex::decode(hex_str).expect("Invalid hex string");

    // Reverse byte order for little-endian representation
    bytes.reverse();

    // Convert Vec<u8> to [u8; 32]
    bytes.try_into().expect("Hex string should be 32 bytes long")
}

fn hex_str_to_scalar(hex_str: &str) -> Scalar {
    // Remove "0x" prefix if present
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Decode hex string to Vec<u8>
    let mut bytes = hex::decode(hex_str).expect("Invalid hex string");

    // Reverse byte order for little-endian representation
    bytes.reverse();

    // Convert Vec<u8> into [u8; 32]
    let bytes_array: [u8; 32] = bytes.try_into().expect("Hex string should be 32 bytes long");

    // Convert bytes to Scalar
    Scalar::from_bytes(&bytes_array).unwrap()
}

#[tokio::main]
async fn main() {
    let h_i = perform_hash_to_curve(6);
    let h_i_1 = h_i.to_compressed();
    println!("h_i_1: {}", hex::encode(h_i_1));

    let h_k = perform_hash_to_curve(32);
    let h_k_1 = h_k.to_compressed();
    let h_k_2 = G1Projective::from(h_k);
    println!("h_k_1: {}", hex::encode(h_k_1));

    let add = h_i.add(h_k_2);
    let add_1 = G1Affine::from(add);
    let add_2 = add_1.to_compressed();
    println!("add_2: {}", hex::encode(add_2));

    // get hex representation of number in Z_p, and convert to scalar and finally multiply the add value
    let hex = "0ad40f9a780d3423a56e6c5f85381f27323d68c0837d7308b3463301552acd2e";
    let uu = hex_to_bytes_le(&hex);
    let g = Scalar::from_bytes(&uu).unwrap();
    println!("g hex representation: {}", g.to_string());

    let f = add.mul(g);
    let f_1 = G1Affine::from(f);
    let f_2 = f_1.to_compressed();
    println!("f: {}", hex::encode(f_2));

    let verify = warp::path("verify")
        .and(warp::post())
        .and(warp::body::json())
        .map(|body: RequestPayload| {
            if let Err(e) = body.validate() {
                return warp::reply::json(&format!("Validation error: {}", e));
            }

            let g_norm: [u8; 96] = body.g_compressed;
            let σ_norm: [u8; 48] = body.sigma_compressed;
            let v_norm: [u8; 96] = body.v_compressed;
            let mu_sum_norm_in_little_endian: [u8; 32] = body.mu_sum_compressed;

            let g_norm = G2Affine::from_compressed(&g_norm);
            let σ_norm = G1Affine::from_compressed(&σ_norm);
            let v_norm = G2Affine::from_compressed(&v_norm);
            let mu_scalar = Scalar::from_bytes(&mu_sum_norm_in_little_endian).unwrap();

            let queries = vec![
                (202, "389496987a173d1e0708a3ecae0f892a7c61dbda2fc8071270ee68243c815e1d"),
                (61, "27ed61afb84efef5102363762f8cc682af57473927f7ca78ed12c5a02e308673"),
                (94, "4639ff21007f9d7b939f61bbbd30e8509674d588b8b3de1c269fe616279ddf1d"),
            ];

            let mut all_mul = G1Projective::identity();
            for (i, v_i_hex) in queries {
                let h_i = perform_hash_to_curve(i);
                let v_i = hex_str_to_scalar(v_i_hex);
                let v_i_mul_v_i = h_i.mul(v_i);

                all_mul = all_mul.add(v_i_mul_v_i);
            }

            let u_norm: [u8; 48] = body.u_compressed;
            let u_norm = G1Affine::from_compressed(&u_norm);
            let u_norm_affine = u_norm.unwrap();
            let u_mul_mu = u_norm_affine.mul(mu_scalar);

            let add = all_mul.add(u_mul_mu);
            let add_affine = G1Affine::from(add);
            let v_norm_affine = v_norm.unwrap();

            let right_pairing = pairing(&add_affine, &v_norm_affine);

            let g_norm_affine = g_norm.unwrap();
            let σ_norm_affine = σ_norm.unwrap();
            let left_pairing = pairing(&σ_norm_affine, &g_norm_affine);

            let is_verified = left_pairing.eq(&right_pairing);
            println!("{}", is_verified);

            let g_norm: [u8; 96] = body.g_compressed;
            let σ_norm: [u8; 48] = body.sigma_compressed;
            let v_norm: [u8; 96] = body.v_compressed;
            let multiplication_sum_norm: [u8; 48] = body.multiplication_sum_compressed;

            let g_norm = G2Affine::from_compressed(&g_norm);
            let σ_norm = G1Affine::from_compressed(&σ_norm);
            let v_norm = G2Affine::from_compressed(&v_norm);
            let multiplication_sum_norm = G1Affine::from_compressed(&multiplication_sum_norm);

            let g_norm_affine = g_norm.unwrap();
            let σ_norm_affine = σ_norm.unwrap();
            let v_norm_affine = v_norm.unwrap();
            let multiplication_sum_norm_affine = multiplication_sum_norm.unwrap();
            let left_pairing = pairing(&σ_norm_affine, &g_norm_affine);
            let right_pairing = pairing(&multiplication_sum_norm_affine, &v_norm_affine);

            let is_verified = left_pairing.eq(&right_pairing);
            println!("{}", is_verified);

            if is_verified {
                warp::reply::json(&"Verified")
            }
            else {
                warp::reply::json(&"Not Verified")
            }
        });

    println!("Server running at http://127.0.0.1:3030/verify");

    warp::serve(verify)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
