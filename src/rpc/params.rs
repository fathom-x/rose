//! Positional-parameter parsing shared by both engines' handlers.
//!
//! Bitcoin Core's typed-argument strictness is dialect, not wallet logic: the same `minconf`,
//! the same `count`/`from` page, the same `getbalance` dummy argument, the same
//! `walletpassphrase` arguments, whichever engine serves the call. These helpers started in
//! `wallet_methods` because that was the only handler module; they live here now so the
//! Bitcoin sub-table can keep using them in a build that compiles no Zcash engine at all.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::wallet::store::Passphrase;

/// Validate `getbalance`'s legacy first argument, which Bitcoin Core requires to be
/// excluded or `"*"` (anything else is `-32 RPC_METHOD_DEPRECATED`).
pub(crate) fn check_balance_dummy(v: Option<&Value>) -> Result<(), RpcError> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s == "*" => Ok(()),
        Some(Value::String(_)) => Err(RpcError::new(
            crate::error::codes::RPC_METHOD_DEPRECATED,
            "dummy first argument must be excluded or set to \"*\".",
        )),
        Some(_) => Err(RpcError::type_error("dummy must be a string")),
    }
}
/// Parse `listtransactions`/`z_listtransactions`'s `count` and `from` positional args with
/// Bitcoin Core's strictness: a negative value is `-8`, a non-integer is `-3`.
pub(crate) fn count_from_params(
    req: &RpcRequest,
    count_i: usize,
    from_i: usize,
) -> Result<(usize, usize), RpcError> {
    let count = match req.param(count_i).filter(|v| !v.is_null()) {
        None => 10,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative count")),
            None => return Err(RpcError::type_error("count must be a number")),
        },
    };
    let from = match req.param(from_i).filter(|v| !v.is_null()) {
        None => 0,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative from")),
            None => return Err(RpcError::type_error("from must be a number")),
        },
    };
    Ok((count, from))
}
/// Parse one of `listunspent`'s integer depth params with Bitcoin Core's typed-argument
/// strictness (wrong type is a -3, not silently the default).
pub(crate) fn depth_param(v: Option<&Value>, name: &str, default: i64) -> Result<i64, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_i64()
            .ok_or_else(|| RpcError::type_error(format!("{name} must be a number"))),
    }
}

/// Bitcoin Core clamps the unlock timeout to this many seconds (~3.17 years); larger values
/// are silently reduced rather than rejected.
pub(crate) const MAX_UNLOCK_TIMEOUT_SECS: i64 = 100_000_000;

/// Parse `walletpassphrase <passphrase> <timeout>`'s arguments as both engines take them: a
/// missing passphrase is the help error, a missing or non-integer timeout and a negative one
/// are `-8`, as is an empty passphrase; a huge timeout is clamped to
/// [`MAX_UNLOCK_TIMEOUT_SECS`]. Checked before the wallet is touched, so a malformed call
/// answers the same whatever state the wallet is in.
pub(crate) fn walletpassphrase_args(req: &RpcRequest) -> Result<(Passphrase, i64), RpcError> {
    let passphrase = req.require_str(0, "walletpassphrase requires a passphrase")?;
    // Timeout (seconds) is required and must be a non-negative integer; huge values are clamped.
    let timeout = req.param(1).and_then(|v| v.as_i64()).ok_or_else(|| {
        RpcError::invalid_parameter("walletpassphrase requires an integer timeout (seconds)")
    })?;
    if timeout < 0 {
        return Err(RpcError::invalid_parameter("Timeout cannot be negative."));
    }
    if passphrase.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    Ok((
        Passphrase::from(passphrase.to_owned()),
        timeout.min(MAX_UNLOCK_TIMEOUT_SECS),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn getbalance_dummy_must_be_star() {
        assert!(check_balance_dummy(None).is_ok());
        assert!(check_balance_dummy(Some(&Value::Null)).is_ok());
        assert!(check_balance_dummy(Some(&json!("*"))).is_ok());
        let e = check_balance_dummy(Some(&json!("account1"))).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_METHOD_DEPRECATED);
        let e = check_balance_dummy(Some(&json!(7))).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }

    #[test]
    fn depth_params_are_strictly_typed() {
        assert_eq!(depth_param(None, "minconf", 1).unwrap(), 1);
        assert_eq!(depth_param(Some(&json!(6)), "minconf", 1).unwrap(), 6);
        let e = depth_param(Some(&json!("6")), "minconf", 1).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }

    /// `walletpassphrase`'s arguments, as both engines parse them: a huge timeout is clamped
    /// to Core's cap rather than refused, and each malformed shape is its Core code.
    #[test]
    fn walletpassphrase_args_clamp_and_refuse() {
        let req = |params| RpcRequest::positional("walletpassphrase".to_string(), params);
        let (_, timeout) =
            walletpassphrase_args(&req(vec![json!("pass"), json!(i64::MAX)])).unwrap();
        assert_eq!(timeout, MAX_UNLOCK_TIMEOUT_SECS);
        let (_, timeout) = walletpassphrase_args(&req(vec![json!("pass"), json!(0)])).unwrap();
        assert_eq!(timeout, 0);
        let code = |params| walletpassphrase_args(&req(params)).unwrap_err().code;
        assert_eq!(code(vec![]), crate::error::codes::RPC_MISC_ERROR);
        assert_eq!(
            code(vec![json!("pass")]),
            crate::error::codes::RPC_INVALID_PARAMETER
        );
        assert_eq!(
            code(vec![json!("pass"), json!(-1)]),
            crate::error::codes::RPC_INVALID_PARAMETER
        );
        assert_eq!(
            code(vec![json!(""), json!(60)]),
            crate::error::codes::RPC_INVALID_PARAMETER
        );
    }
}
