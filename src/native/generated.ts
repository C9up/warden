// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export declare function jwtSign(payload: string, secret: string): string;

export declare function jwtVerify(token: string, secret: string): string;
