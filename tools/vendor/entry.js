// Browser bundle: exposes window.MLKEM = { ml_kem768, version }.
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export { ml_kem768 };
export const version = NOBLE_VERSION; // injected by build.mjs
