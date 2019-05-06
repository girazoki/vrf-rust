use failure::Fail;
use hex::FromHex;
use hmac_sha256::HMAC;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint, PointConversionForm},
    error::ErrorStack,
    hash::{hash, MessageDigest},
    nid::Nid,
};
use std::os::raw::c_ulong;

use crate::VRF;
use openssl::ocsp::OcspRevokedStatus;
use core::borrow::Borrow;

/// The size (in bytes) of a secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The type of the secret key
pub type SecretKey<'a> = &'a [u8; SECRET_KEY_SIZE];

/// The type of the public key
pub type PublicKey<'a> = &'a [u8; PUBLIC_KEY_SIZE];

enum Curve {
    SECP256K1,
    SECT163K1,
}

/// Error that can be raised when proving/verifying VRFs
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Error with code {}", code)]
    CodedError { code: c_ulong },
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
    #[fail(display = "Unknown error")]
    Unknown,
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        match error.errors().get(0).map(|e| e.code()) {
            Some(code) => Error::CodedError { code },
            _ => Error::Unknown {},
        }
    }
}

/// Elliptic Curve context
struct ECContext {
    curve: Curve,
    group: EcGroup,
    bn_ctx: BigNumContext,
    order: BigNum,
    hasher: MessageDigest,
    n: usize,
    qlen: usize,

}

/// A Elliptic Curve VRF using the curve p256v1
struct P256v1;

impl<'a> VRF<PublicKey<'a>, SecretKey<'a>> for P256v1 {
    type Error = Error;

    // Generate proof from key pair and message
    fn prove(_x: SecretKey, _alpha: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }
    // Verify proof given public key, proof and message
    fn verify(_y: PublicKey, _pi: &[u8], _alpha: &[u8]) -> Result<bool, Error> {
        Ok(false)
    }
}

/// Function to create a Elliptic Curve context using the curve prime256v1
fn create_ec_context(curve: Curve) -> Result<ECContext, Error> {
    let group = match curve {
        Curve::SECP256K1 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
        Curve::SECT163K1 => EcGroup::from_curve_name(Nid::SECT163K1)?,
    };
    let mut bn_ctx = BigNumContext::new()?;
    let hasher = MessageDigest::sha256();
    let order = BigNum::new().map(|mut ord| {
        group.order(&mut ord, &mut bn_ctx);
        ord
    })?;

    let n = BigNum::new().and_then(|mut a| {
        BigNum::new().and_then(|mut b| {
            BigNum::new().and_then(|mut p| {
                group.components_gfp(&mut a, &mut b, &mut p, &mut bn_ctx);
                Ok(((p.num_bits() + (p.num_bits()% 2)) / 2) as usize)
            })
        })
    })?;

    let qlen =  order.num_bits() as usize;

    Ok(ECContext {
        curve,
        group,
        bn_ctx,
        order,
        hasher,
        n,
        qlen,
    })
}

/// Function for deriving public key given a secret key point
fn derive_public_key(secret_key: &BigNum, ctx: &ECContext) -> Result<EcPoint, Error> {
    let mut point = EcPoint::new(&ctx.group.as_ref())?;
    point.mul_generator(&ctx.group, &secret_key, &ctx.bn_ctx)?;
    Ok(point)
}

/// Function to convert a Hash(PK|DATA) to a point in the curve
fn hash_to_try_and_increment(
    suite_string: &u8,
    public_key: &EcPoint,
    alpha: &[u8],
    mut ctx: &mut ECContext,
) -> Result<EcPoint, Error> {
    let c = 0..255;
    let pk_bytes =
        public_key.to_bytes(&ctx.group, PointConversionForm::COMPRESSED, &mut ctx.bn_ctx)?;
    let mut v = vec![];
    let cipher = [0x01, 0x01];
    v.extend(&cipher);
    v.extend(pk_bytes.clone());
    v.extend(alpha.clone());
    v.push(0);
    let position = v.len() - 1;
    let point = c.into_iter().find_map(|ctr| {
        v[position] = ctr;
        let attempted_hash = hash(ctx.hasher, &v);
        match attempted_hash {
            Ok(attempted_hash) => arbitrary_string_to_point(&attempted_hash, &mut ctx).ok(),
            _ => None,
        }
    });
    point.ok_or(Error::HashToPointError)
}

/// Function for converting a string to a point in the curve
fn arbitrary_string_to_point(data: &[u8], ctx: &mut ECContext) -> Result<EcPoint, Error> {
    let mut v = vec![0x02];
    v.extend(data);
    let point = EcPoint::from_bytes(&ctx.group, &v, &mut ctx.bn_ctx)?;
    Ok(point)
}

fn nonce_generation_RFC6979(
    secret_key: &BigNum,
    data: &[u8],
    ctx: &mut ECContext,
) -> Result<Vec<u8>, Error> {

    // Bits to octets from data - bits2octets(h1)
    // Length of this value should be dependent on qlen (i.e. SECP256k1 is 32)
    let data_trunc = bits2octets(data, ctx)?;
    let left_padding2 = match ctx.curve {
        Curve::SECP256K1 => 32 - data_trunc.len(),
        Curve::SECT163K1 => 21 - data_trunc.len(),
    };
    let mut padded_data_trunc: Vec<u8> = vec![0; left_padding2];
    padded_data_trunc.extend(&data_trunc);

    // Bytes to octets from secret key - int2octects(x)
    // Left padding is required for inserting leading zeros
    let mut secret_key_bytes: Vec<u8> = secret_key.to_vec();
    let left_padding = match ctx.curve {
        Curve::SECP256K1 => 32 - secret_key_bytes.len(),
        Curve::SECT163K1 => 21 - secret_key_bytes.len(),
    };
    let mut padded_secret_key_bytes: Vec<u8> = vec![0; left_padding];
    padded_secret_key_bytes.extend(&secret_key_bytes);

    // Init V & K
    // K = HMAC_K(V || 0x00 || int2octects(secret_key) || bits2octects(data))
    let mut V = [0x01; 32];
    let mut K = [0x00; 32];

    K = HMAC::mac([&V[..], &[0x00], &padded_secret_key_bytes[..], &padded_data_trunc[..]].concat().as_slice(), &K);
    V = HMAC::mac(&V, &K);

    K = HMAC::mac([&V[..], &[0x01], &padded_secret_key_bytes[..], &padded_data_trunc[..]].concat().as_slice(), &K);
    V = HMAC::mac(&V, &K);

//    let order = BigNum::new().map(|mut ord| {
//        ctx.group.order(&mut ord, &mut ctx.bn_ctx);
//        ord
//    })?;

//    Ok(HMAC::mac(&V, &K))
    loop {
        V = HMAC::mac(&V, &K);
//        return Ok(V);
        let ret_bn = bits2int(&V, ctx.qlen)?;

        if &ret_bn > &BigNum::from_u32(0)? && &ret_bn < &ctx.order {
            return Ok(ret_bn.to_vec());
        }
        K = HMAC::mac([&V[..], &[0x00]].concat().as_slice(), &K);
        V = HMAC::mac(&V, &K);
    }

    //Err(Error::Unknown)

    // END

//    let mut message = vec![];
//    let data_trunc = bits2octets(data, ctx)?;
//    let mut exp_secret_key = secret_key.to_vec();
//
//    //FIXME!: this should create a vec of zeros of length (qlen - sizeof(secret_key.to_vec()))
//    let zero_vec = vec![0; 1];
//
//    message.extend(&V);
//    message.push(0);
//    //FIXME: ref
//    message.extend(&zero_vec);
//    message.extend(secret_key.to_vec());
//    message.extend(&data_trunc);
////    println!("message{:x?}", message);
//
//    let k1 = HMAC::mac(&message, &K);
////    println!("k1{:x?}", k1);
//
//    let v1 = HMAC::mac(&V, &k1);
////    println!("v1{:x?}", v1);
//    let mut message1 = vec![];
//    message1.extend(&v1);
//    message1.push(1);
//    //FIXME: ref
//    message1.extend(&zero_vec);
//    message1.extend(secret_key.to_vec());
//    message1.extend(&data_trunc);
//    let k2 = HMAC::mac(&message1, &k1);
////    println!("k2{:x?}", k2);
//    let v2 = HMAC::mac(&v1, &k2);
////    println!("v2{:x?}", v2);
//    // if result is bigger than q, repeat
//    Ok(HMAC::mac(&v2, &k2))
}

fn bits2octets(data: &[u8], ctx: &mut ECContext) -> Result<Vec<u8>, Error> {
    //FIXME: TO DECIDE WHETHER FOLLOW DIFFERENT TEST VECTORS (qlen for both cases)
    let mut z1 = match  ctx.curve {
        Curve::SECP256K1 => bits2int(data, data.len()*8)?,
        Curve::SECT163K1 => bits2int(data, ctx.qlen)?,
    };
    //let mut z1 =  bits2int(data, data.len()*8)?;
//    let mut z1 =  bits2int(data, data.len()*8)?;

//    let z2 = &z1 - &order;
//
//    let bn_zero = BigNum::from_u32(0)?;
//    let result = if &z2 < &bn_zero {
//        z2.to_vec()
//    } else {
//        z1.to_vec()
//    };

//    //    let mut data_bn = bits2int(data, 256)?;
//
    let result = BigNum::new().map(|mut res| {
        res.nnmod(&z1, &ctx.order, &mut ctx.bn_ctx);
        res.to_vec()
    })?;

    Ok(result)
}

/// Transforms slice into Bignum and right-shifts it by len(data)-qlen bits.
fn bits2int(data: &[u8], qlen: usize) -> Result<BigNum, Error> {
    let data_len_bits = data.len() * 8;
    let result = BigNum::from_slice(data).and_then(|data_bn| {
        if data_len_bits > qlen {
            let mut truncated = BigNum::new()?;
            truncated.rshift(&data_bn, (data_len_bits - qlen) as i32)?;

            Ok(truncated)
        } else {
            Ok(data_bn)
        }
    })?;
    let _data2 = data.to_vec();
    let _data_vec = result.to_vec();

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prove() {
        let x = [0; 32];
        let alpha = [0, 0, 0];

        let proof = P256v1::prove(&x, &alpha);
        assert_eq!(proof.unwrap(), vec![]);
    }

    #[test]
    fn test_verify() {
        let y = [0; 33];
        let pi = [0];
        let alpha = [0, 0, 0];

        assert_eq!(P256v1::verify(&y, &pi, &alpha).unwrap(), false);
    }

    #[test]
    fn test_derive_public_key() {
        // Example of using a different hashing function

        let k = [0x01];
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();

        let secret_key = BigNum::from_slice(&k).unwrap();
        let expected = [
            0x03, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96,
        ];
        let derived_public_key = derive_public_key(&secret_key, &ctx).unwrap();
        let expected_point = EcPoint::from_bytes(&ctx.group, &expected, &mut ctx.bn_ctx).unwrap();
        assert!(derived_public_key
            .eq(&ctx.group, &expected_point, &mut ctx.bn_ctx)
            .unwrap());
    }

    /// Hash to try and increment (TAI) test
    /// Test vector extracted from VRF RFC draft (section A.1)
    #[test]
    fn test_hash_to_try_and_increment() {
        // Example of using a different hashing function
        let suite: u8 = 1;
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let public_key_hex =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let public_key = EcPoint::from_bytes(&ctx.group, &public_key_hex, &mut ctx.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&ctx.group, &expected_hash_hex, &mut ctx.bn_ctx).unwrap();
        // Data to be hashed: ASCII "sample
        let data = hex::decode("73616d706c65").unwrap();
        let derived_hash = hash_to_try_and_increment(&suite, &public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }

    #[test]
    fn test_hash_to_try_and_increment_2() {
        // Example of using a different hashing function
        let suite: u8 = 1;
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let public_key_hex =
            hex::decode("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d")
                .unwrap();
        let public_key = EcPoint::from_bytes(&ctx.group, &public_key_hex, &mut ctx.bn_ctx).unwrap();
        let expected_hash_hex =
            hex::decode("02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d")
                .unwrap();
        let expected_hash =
            EcPoint::from_bytes(&ctx.group, &expected_hash_hex, &mut ctx.bn_ctx).unwrap();
        let data = hex::decode("4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536").unwrap();
        let derived_hash = hash_to_try_and_increment(&suite, &public_key, &data, &mut ctx).unwrap();
        assert!(derived_hash
            .eq(&ctx.group, &expected_hash, &mut ctx.bn_ctx)
            .unwrap());
    }

    /// Nonce generation test using the curve K-163
    /// Test vector extracted from RFC6979 (section A.1)
    #[test]
    fn test_nonce_generation_RFC6979_SECT163K1() {
        let mut ctx = create_ec_context(Curve::SECT163K1).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();

        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("009A4D6792295A7F730FC3F2B49CBC0F62E862272F").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_RFC6979(&sk_bn, &data, &mut ctx).unwrap();

        assert_eq!(derived_nonce, expected_nonce);

        // let t = BigNum::from_slice(&[0x01]).unwrap();
        //        let mut c_k = BigNum::new().unwrap();
        //
        //        // In the RFC is called K (or T)
        //        let expected_nonce =
        //            hex::decode("9305a46de7ff8eb107194debd3fd48aa20d5e7656cbe0ea69d2a8d4e7c67314a")
        //                .unwrap();
        //        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
        //            .unwrap();
        //        let data_bn = BigNum::from_slice(&data).unwrap();
        //        c_k.mod_mul(&data_bn, &t, &ord, &mut ctx.bn_ctx).unwrap();
        //        println!("{:?}", data);
        //        println!("{:?}", c_k.to_vec());
        //
        //        let derived_nonce = nonce_generation_RFC6979(&sk_point, &data, &mut ctx).unwrap();
        //        println!("{:x?}", derived_nonce);
        //        assert!(derived_nonce == expected_nonce.as_slice());
    }

    #[test]
    fn test_nonce_generation_RFC6979_SECP256K1() {
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let mut ord = BigNum::new().unwrap();
        let mut a = BigNum::new().unwrap();
        let mut b = BigNum::new().unwrap();
        let mut p = BigNum::new().unwrap();
        ctx.group.components_gfp(&mut a, &mut b, &mut p, &mut ctx.bn_ctx).unwrap();


        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_RFC6979(&sk_bn, &data, &mut ctx).unwrap();
        assert_eq!(derived_nonce, expected_nonce);
    }

    #[test]
    fn test_nonce_generation_RFC6979_SECP256K1_2() {
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();
        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data = hex::decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_RFC6979(&sk_bn, &data, &mut ctx).unwrap();
        assert_eq!(derived_nonce, expected_nonce);
    }
    #[test]
    fn test_nonce_generation_RFC6979_SECP256K1_3() {
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let mut ord = BigNum::new().unwrap();
        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();
        // Expected result/nonce (labelled as K or T)
        // This is the va;ue of T
        let expected_nonce =
            hex::decode("c1aba586552242e6b324ab4b7b26f86239226f3cfa85b1c3b675cc061cf147dc")
                .unwrap();

        // Secret Key (labelled as x)
        let sk = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
        let sk_bn = BigNum::from_slice(&sk).unwrap();

        // Hashed input message (labelled as h1)
        //FIXME: TO CHECK if 0x02 is correct
        let data = hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
            .unwrap();
        let data_bn = BigNum::from_slice(&data).unwrap();

        // Nonce generation
        let derived_nonce = nonce_generation_RFC6979(&sk_bn, &data, &mut ctx).unwrap();

        assert_eq!(derived_nonce, expected_nonce);
    }

    //    #[test]
//    fn test_nonce_generation_RFC6979_SECP256K1() {
//        let mut ctx = create_ec_context().unwrap();
//        // Private Key
//        let k = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
//            .unwrap();
//        let mut ord = BigNum::new().unwrap();
//        ctx.group.order(&mut ord, &mut ctx.bn_ctx).unwrap();
//        let t = BigNum::from_slice(&[0x01]).unwrap();
//        let secret_key = BigNum::from_slice(&k).unwrap();
//
//        let expected_k =
//            hex::decode("c1aba586552242e6b324ab4b7b26f86239226f3cfa85b1c3b675cc061cf147dc")
//                .unwrap();
//        let data = hex::decode("02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e")
//            .unwrap();
//        let data_bn = BigNum::from_slice(&data).unwrap();
//        let derived_k = nonce_generation_RFC6979(&secret_key, &data, &mut ctx).unwrap();
//        println!("{:x?}", derived_k);
//        assert_eq!(derived_k, expected_k.as_slice());
//    }

    #[test]
    fn test_bits2int() {
        let mut ctx = create_ec_context(Curve::SECP256K1).unwrap();
        let data1 = vec![0x01; 32];
        let data1_bn = BigNum::from_slice(&data1).unwrap();
        let result1 = bits2int(&data1, 256).unwrap();
        assert_eq!(data1_bn, result1);

        let data2 = vec![0x01; 33];
        let data2_bn = BigNum::from_slice(&data2).unwrap();
        let result2 = bits2int(&data2, 256).unwrap();
        let mut truncated = BigNum::new().unwrap();
        truncated.rshift(&data2_bn, 8);
        assert_eq!(truncated.to_vec(), result2.to_vec());
    }
}
