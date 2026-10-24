//! Minimal blocking JSON-RPC client for a Substrate node.

use anyhow::{anyhow, bail, Context, Result};
use codec::Decode;
use serde_json::{json, Value};
use sp_core::H256;
use sp_runtime::AccountId32;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Rpc {
	url: String,
	next_id: AtomicU64,
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>> {
	hex::decode(value.trim_start_matches("0x")).context("invalid hex from node")
}

fn as_str(value: &Value) -> Result<&str> {
	value.as_str().ok_or_else(|| anyhow!("expected a string, got {value}"))
}

impl Rpc {
	pub fn new(url: &str) -> Self {
		Self { url: url.to_string(), next_id: AtomicU64::new(1) }
	}

	pub fn call(&self, method: &str, params: Value) -> Result<Value> {
		let id = self.next_id.fetch_add(1, Ordering::Relaxed);
		let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
		let response: Value = ureq::post(&self.url)
			.send_json(request)
			.with_context(|| format!("cannot reach node at {} (is it running?)", self.url))?
			.into_json()?;
		if let Some(error) = response.get("error") {
			let message = error["message"].as_str().unwrap_or("unknown error");
			match error.get("data") {
				Some(data) => bail!("{method}: {message}: {data}"),
				None => bail!("{method}: {message}"),
			}
		}
		Ok(response["result"].clone())
	}

	pub fn block_hash(&self, number: u32) -> Result<H256> {
		let hash = self.call("chain_getBlockHash", json!([number]))?;
		Ok(H256::from_slice(&decode_hex(as_str(&hash)?)?))
	}

	pub fn best_number(&self) -> Result<u32> {
		let header = self.call("chain_getHeader", json!([]))?;
		let number = as_str(&header["number"])?;
		Ok(u32::from_str_radix(number.trim_start_matches("0x"), 16)?)
	}

	/// Number of the latest finalized block.
	pub fn finalized_number(&self) -> Result<u32> {
		let hash = self.call("chain_getFinalizedHead", json!([]))?;
		let header = self.call("chain_getHeader", json!([as_str(&hash)?]))?;
		let number = as_str(&header["number"])?;
		Ok(u32::from_str_radix(number.trim_start_matches("0x"), 16)?)
	}

	/// `(spec_version, transaction_version)` of the current runtime.
	pub fn runtime_version(&self) -> Result<(u32, u32)> {
		let v = self.call("state_getRuntimeVersion", json!([]))?;
		let field = |name: &str| {
			v[name].as_u64().map(|x| x as u32).ok_or_else(|| anyhow!("missing {name}"))
		};
		Ok((field("specVersion")?, field("transactionVersion")?))
	}

	/// Next nonce for `who`, including transactions already waiting in the pool.
	pub fn next_nonce(&self, who: &AccountId32) -> Result<u32> {
		let nonce = self.call("system_accountNextIndex", json!([who.to_string()]))?;
		nonce.as_u64().map(|n| n as u32).ok_or_else(|| anyhow!("bad nonce {nonce}"))
	}

	pub fn block_extrinsics(&self, hash: H256) -> Result<Vec<String>> {
		let block = self.call("chain_getBlock", json!([format!("{hash:?}")]))?;
		block["block"]["extrinsics"]
			.as_array()
			.ok_or_else(|| anyhow!("malformed block"))?
			.iter()
			.map(|x| as_str(x).map(str::to_owned))
			.collect()
	}

	pub fn storage<T: Decode>(&self, key: &[u8], at: Option<H256>) -> Result<Option<T>> {
		let key = format!("0x{}", hex::encode(key));
		let params = match at {
			Some(hash) => json!([key, format!("{hash:?}")]),
			None => json!([key]),
		};
		match self.call("state_getStorage", params)? {
			Value::Null => Ok(None),
			value => Ok(Some(T::decode(&mut &decode_hex(as_str(&value)?)?[..])?)),
		}
	}

	/// Submit a SCALE-encoded extrinsic, returning its hash.
	pub fn submit(&self, encoded: &[u8]) -> Result<H256> {
		let hash =
			self.call("author_submitExtrinsic", json!([format!("0x{}", hex::encode(encoded))]))?;
		Ok(H256::from_slice(&decode_hex(as_str(&hash)?)?))
	}
}
