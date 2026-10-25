// Load the probe module, verify the committed fixtures (valid and tampered) and time it.
import { readFileSync } from "node:fs";
const here = new URL(".", import.meta.url).pathname;
const target = process.env.CARGO_TARGET_DIR ?? `${here}target`;
const wasm = readFileSync(`${target}/wasm32-unknown-unknown/release/wasm_verify_probe.wasm`);
const mod = await WebAssembly.compile(wasm);
console.log("imports:", WebAssembly.Module.imports(mod).map((i) => `${i.module}.${i.name}`));
const { exports: x } = await WebAssembly.instantiate(mod, {});
const put = (bytes) => {
	const p = x.probe_alloc(bytes.length);
	new Uint8Array(x.memory.buffer, p, bytes.length).set(bytes);
	return [p, bytes.length];
};
for (const stem of ["mldsa-batch-n4", "payroll-n16"]) {
	const f = (e) => readFileSync(`${here}../../fixtures/${stem}.${e}`);
	const proof = f("proof"), pv = f("pv"), vk = f("vkey");
	const args = [...put(proof), ...put(pv), ...put(vk)];
	const times = [];
	for (let i = 0; i < 5; i++) {
		const t = performance.now();
		const ok = x.probe_verify(...args);
		times.push(performance.now() - t);
		if (ok !== 1) throw new Error(`${stem}: valid proof rejected`);
	}
	const bad = Uint8Array.from(pv);
	bad[0] ^= 1;
	const badArgs = [...put(proof), ...put(bad), ...put(vk)];
	if (x.probe_verify(...badArgs) !== 0) throw new Error(`${stem}: wrong public values accepted`);
	const ms = times.map((t) => t.toFixed(1)).join(" ");
	console.log(`${stem}: ok, wasm verify ms (first..): ${ms}`);
}
