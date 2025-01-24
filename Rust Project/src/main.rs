use bls12_381::{pairing, G1Affine, G2Affine};
use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use warp::Filter;

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

impl RequestPayload {
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
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
