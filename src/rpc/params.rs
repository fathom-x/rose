//! Positional-parameter parsing shared by both engines' handlers.
//!
//! Bitcoin Core's typed-argument strictness is dialect, not wallet logic: the same `minconf`,
//! the same `count`/`from` page, the same `getbalance` dummy argument, whichever engine serves
//! the call. These three helpers started in `wallet_methods` because that was the only handler
//! module; they live here now so the Bitcoin sub-table can keep using them in a build that
//! compiles no Zcash engine at all.

use serde_json::Value;

use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;

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
}
