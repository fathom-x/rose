//! Canonical CBOR, as the bundle hash is defined.
//!
//! Upstream hashes a bundle as `SHA-256(serde_cbor::to_vec(serde_cbor::value::to_value(b)))`:
//! the value's maps are `BTreeMap`s under serde_cbor's `Value` ordering, so the encoding is
//! independent of the JSON's field and label order. This module reproduces that ordering over
//! `ciborium`'s value so the hash agrees byte for byte (pinned by upstream's contract fixture
//! and, in the tests, by a differential check against serde_cbor itself). serde_cbor's rule,
//! from its `Ord for Value`: smaller major type first; then, for two integers, the smaller
//! magnitude; for two byte strings, text strings, arrays or maps, the shorter first; then
//! bytes and text lexically, and anything else by its serialization.

use ciborium::value::{Integer, Value};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// `value` as canonical CBOR bytes: every map sorted by [`canonical_cmp`], recursively.
pub fn to_canonical_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ciborium::value::Error> {
    let mut value = Value::serialized(value)?;
    sort(&mut value);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out)
        .map_err(|e| ciborium::value::Error::Custom(e.to_string()))?;
    Ok(out)
}

/// The SHA-256 of [`to_canonical_vec`], as the bundle hash is defined.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<[u8; 32], ciborium::value::Error> {
    Ok(Sha256::digest(to_canonical_vec(value)?).into())
}

fn sort(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(sort),
        Value::Map(entries) => {
            for (k, v) in entries.iter_mut() {
                sort(k);
                sort(v);
            }
            entries.sort_by(|(a, _), (b, _)| canonical_cmp(a, b));
        }
        Value::Tag(_, inner) => sort(inner),
        _ => {}
    }
}

fn major_type(value: &Value) -> u8 {
    match value {
        Value::Integer(i) => {
            if i128::from(*i) >= 0 {
                0
            } else {
                1
            }
        }
        Value::Bytes(_) => 2,
        Value::Text(_) => 3,
        Value::Array(_) => 4,
        Value::Map(_) => 5,
        Value::Tag(..) => 6,
        Value::Null | Value::Bool(_) | Value::Float(_) => 7,
        _ => 7,
    }
}

fn magnitude(i: Integer) -> i128 {
    i128::from(i).abs()
}

fn encoded(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // A value that came out of `Value::serialized` always re-encodes.
    let _ = ciborium::into_writer(value, &mut out);
    out
}

/// serde_cbor's `Ord for Value`, over ciborium's value.
pub fn canonical_cmp(a: &Value, b: &Value) -> Ordering {
    let (ta, tb) = (major_type(a), major_type(b));
    if ta != tb {
        return ta.cmp(&tb);
    }
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => magnitude(*x).cmp(&magnitude(*y)),
        (Value::Bytes(x), Value::Bytes(y)) if x.len() != y.len() => x.len().cmp(&y.len()),
        (Value::Text(x), Value::Text(y)) if x.len() != y.len() => x.len().cmp(&y.len()),
        (Value::Array(x), Value::Array(y)) if x.len() != y.len() => x.len().cmp(&y.len()),
        (Value::Map(x), Value::Map(y)) if x.len() != y.len() => x.len().cmp(&y.len()),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::Text(x), Value::Text(y)) => x.cmp(y),
        _ => encoded(a).cmp(&encoded(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Serialize)]
    struct Nested {
        zebra: Vec<u8>,
        a: HashMap<String, String>,
        bb: [u8; 4],
        version: &'static str,
        negative: i64,
        flag: bool,
    }

    fn sample() -> Nested {
        Nested {
            zebra: vec![1, 2, 3],
            a: HashMap::from([
                ("name".to_string(), "x".to_string()),
                ("environment".into(), "test".into()),
                ("owner".into(), "o".into()),
            ]),
            bb: [9, 8, 7, 6],
            version: "V1",
            negative: -5,
            flag: true,
        }
    }

    #[test]
    fn agrees_with_serde_cbor_canonical_value() {
        let ours = to_canonical_vec(&sample()).unwrap();
        let theirs = serde_cbor::to_vec(&serde_cbor::value::to_value(sample()).unwrap()).unwrap();
        assert_eq!(hex::encode(ours), hex::encode(theirs));
    }

    #[test]
    fn text_keys_sort_by_length_then_bytes() {
        let mut v = Value::Map(vec![
            (Value::Text("bb".into()), Value::Null),
            (Value::Text("c".into()), Value::Null),
            (Value::Text("aaa".into()), Value::Null),
            (Value::Text("a".into()), Value::Null),
        ]);
        sort(&mut v);
        let Value::Map(entries) = v else {
            unreachable!()
        };
        let keys: Vec<_> = entries
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(keys, ["a", "c", "bb", "aaa"]);
    }

    #[test]
    fn integers_sort_by_magnitude_within_a_major_type() {
        assert_eq!(
            canonical_cmp(&Value::Integer(10.into()), &Value::Integer(9.into())),
            Ordering::Greater
        );
        assert_eq!(
            canonical_cmp(&Value::Integer((-1).into()), &Value::Integer(100.into())),
            Ordering::Greater
        );
        assert_eq!(
            canonical_cmp(&Value::Text("z".into()), &Value::Array(vec![])),
            Ordering::Less
        );
    }
}
