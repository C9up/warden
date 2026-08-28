// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export declare function jwtSign(payload: string, secret: string): string;

export declare function jwtVerify(token: string, secret: string): string;

export declare function constantTimeEq(a: string, b: string): boolean;

export declare function hmacSign(data: string, secret: string): string;

export declare function hmacVerify(
	data: string,
	signature: string,
	secret: string,
): boolean;

export declare function randomBytes(len: number): string;

export declare function randomHex(len: number): string;
