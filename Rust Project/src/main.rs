use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use warp::Filter;
// use bls12_381::{pairing, G1Projective, G2Projective, G1Affine, G2Affine};
use ark_bls12_381::G1Projective;
use ark_bls12_381::Fq;
use ark_ff::BigInt;
use ark_ff::fields::{Fp384, MontBackend, MontConfig};

#[derive(Debug)]
struct VerifyRequest {
    g_point: ((BigUint, BigUint), (BigUint, BigUint), (BigUint, BigUint)),
    sigma_point: (BigUint, BigUint, BigUint),
    v_point: ((BigUint, BigUint), (BigUint, BigUint), (BigUint, BigUint)),
    all_point: (BigUint, BigUint, BigUint),
}

impl Serialize for VerifyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("VerifyRequest", 4)?;
        state.serialize_field("g_point", &serialize_nested_tuple(&self.g_point))?;
        state.serialize_field("sigma_point", &serialize_tuple(&self.sigma_point))?;
        state.serialize_field("v_point", &serialize_nested_tuple(&self.v_point))?;
        state.serialize_field("all_point", &serialize_tuple(&self.all_point))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for VerifyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        #[derive(Deserialize)]
        struct Helper {
            g_point: Vec<Vec<String>>,
            sigma_point: Vec<String>,
            v_point: Vec<Vec<String>>,
            all_point: Vec<String>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let g_point = deserialize_nested_tuple(&helper.g_point)
            .map_err(D::Error::custom)?;
        let sigma_point = deserialize_tuple(&helper.sigma_point)
            .map_err(D::Error::custom)?;
        let v_point = deserialize_nested_tuple(&helper.v_point)
            .map_err(D::Error::custom)?;
        let all_point = deserialize_tuple(&helper.all_point)
            .map_err(D::Error::custom)?;

        Ok(VerifyRequest {
            g_point,
            sigma_point,
            v_point,
            all_point,
        })
    }
}

fn serialize_nested_tuple(data: &((BigUint, BigUint), (BigUint, BigUint), (BigUint, BigUint))) -> Vec<Vec<String>> {
    vec![
        vec![data.0 .0.to_string(), data.0 .1.to_string()],
        vec![data.1 .0.to_string(), data.1 .1.to_string()],
        vec![data.2 .0.to_string(), data.2 .1.to_string()],
    ]
}

fn serialize_tuple(data: &(BigUint, BigUint, BigUint)) -> Vec<String> {
    vec![
        data.0.to_string(),
        data.1.to_string(),
        data.2.to_string(),
    ]
}

fn deserialize_nested_tuple(
    data: &[Vec<String>],
) -> Result<((BigUint, BigUint), (BigUint, BigUint), (BigUint, BigUint)), String> {
    if data.len() != 3 {
        return Err("Invalid nested tuple length".to_string());
    }

    let result: Result<Vec<_>, _> = data
        .iter()
        .map(|pair| {
            if pair.len() != 2 {
                return Err("Invalid pair length".to_string());
            }
            let left = pair[0].parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;
            let right = pair[1].parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;
            Ok((left, right))
        })
        .collect();

    let pairs = result?;
    Ok((pairs[0].clone(), pairs[1].clone(), pairs[2].clone()))
}


fn deserialize_tuple(data: &[String]) -> Result<(BigUint, BigUint, BigUint), String> {
    if data.len() != 3 {
        return Err("Invalid tuple length".to_string());
    }

    let a = data[0].parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;
    let b = data[1].parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;
    let c = data[2].parse().map_err(|e: num_bigint::ParseBigIntError| e.to_string())?;

    Ok((a, b, c))
}

fn biguint_to_bigint(biguint: BigUint) -> BigInt<6> {
    let mut limbs = [0u64; 6]; // Initialize the array with zeroes
    let bytes = biguint.to_bytes_le(); // Get the bytes in little-endian order

    // Fill the limbs array by reading the bytes in chunks of 8
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i >= 6 {
            break; // Ensure we don't overflow the array
        }
        let mut limb = 0u64;
        for (j, &byte) in chunk.iter().enumerate() {
            limb |= (byte as u64) << (j * 8);
        }
        limbs[i] = limb;
    }

    BigInt::<6>(limbs)
}

#[tokio::main]
async fn main() {
    let verify = warp::path("verify")
        .and(warp::post())
        .and(warp::body::json())
        .map(|body: VerifyRequest| {
            // let x = Fq::from(1u64); // Example x-coordinate
            // let y = Fq::from(2u64); // Example y-coordinate
            // let z = Fq::from(3u64); // Example z-coordinate
            // let ww = G1Projective::new_unchecked(x, y, z);
            //
            // let big_int = BigInt::<6>([
            //     0x123456789abcdef0,
            //     0x0fedcba987654321,
            //     0x1111111111111111,
            //     0x2222222222222222,
            //     0x3333333333333333,
            //     0x4444444444444444,
            // ]);
            // let pp = Fp384::new(big_int);
            // let aaa = G1Projective::new_unchecked(pp, pp, pp);


            // let g1 = G1Projective::generator();
            // let g2 = G2Projective::generator();

            let sigma_point_x = body.sigma_point.0;
            let sigma_point_y = body.sigma_point.1;
            let sigma_point_z = body.sigma_point.2;

            let xxx = biguint_to_bigint(sigma_point_x);
            let yyy = biguint_to_bigint(sigma_point_y);
            let zzz = biguint_to_bigint(sigma_point_z);

            let xxxx = Fp384::new(xxx);
            let yyyy = Fp384::new(yyy);
            let zzzz = Fp384::new(zzz);
            let aaaa = G1Projective::new(xxxx, yyyy, zzzz);

            // let a = g1.clone();

            // let bbb = G1Projective {
            //     x: G1Projective::,
            //     y: biguint_to_fp(y),
            //     z: biguint_to_fp(z),
            // };

            // let g1_affine = G1Affine::from(aaa);
            //
            // // Convert to affine coordinates
            // let g1_affine = G1Affine::from(g1);
            // let g2_affine = G2Affine::from(g2);
            //
            // // Pairing computation
            // let pairing_result = pairing(&g1_affine, &g2_affine);
            // let pairing_result2 = pairing(&g1_affine, &g2_affine);

            G1Projective::default();
            // let sigma_g1 = sigma_point_to_g1(body.sigma_point);

            // println!("Pairing result: {:?}", pairing_result);
            // println!("Is Equals: {:?}", pairing_result.eq(&pairing_result2));

            println!("g_point: {:?}", body.g_point);
            // println!("sigma_point: {:?}", body.sigma_point);
            println!("v_point: {:?}", body.v_point);
            println!("all_point: {:?}", body.all_point);

            warp::reply::json(&"Verification Complete")
        });

    warp::serve(verify)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
