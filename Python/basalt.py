def md5(message):
	def rotl(a, times=1):
		return ((a << times) | (a >> (32 - times))) % (2 ** 32)

	def func(a, b, c, rnd=0):
		if rnd == 0:
			return (a & b) | (~a & c)
		if rnd == 1:
			return (a & c) | (b & ~c)
		if rnd == 2:
			return a ^ b ^ c
		if rnd == 3:
			return b ^ (a | ~c)

	def parse(block, iv):
		schedule = []

		for i in range(0, 64, 4):
			schedule.append(int.from_bytes(block[i:i+4], "little"))

		schedule = [
			schedule[0], schedule[1], schedule[2], schedule[3], schedule[4], schedule[5], schedule[6], schedule[7],
			schedule[8], schedule[9], schedule[10], schedule[11], schedule[12], schedule[13], schedule[14], schedule[15],

			schedule[1], schedule[6], schedule[11], schedule[0], schedule[5], schedule[10], schedule[15], schedule[4],
			schedule[9], schedule[14], schedule[3], schedule[8], schedule[13], schedule[2], schedule[7], schedule[12],

			schedule[5], schedule[8], schedule[11], schedule[14], schedule[1], schedule[4], schedule[7], schedule[10],
			schedule[13], schedule[0], schedule[3], schedule[6], schedule[9], schedule[12], schedule[15], schedule[2],

			schedule[0], schedule[7], schedule[14], schedule[5], schedule[12], schedule[3], schedule[10], schedule[1],
			schedule[8], schedule[15], schedule[6], schedule[13], schedule[4], schedule[11], schedule[2], schedule[9]
		]

		state = iv.copy()

		for i in range(64):
			state = [
				state[3],
				(rotl((func(state[1], state[2], state[3], rnd=i // 16) + state[0] + schedule[i] + kconsts[i]) % (2 ** 32), times=rconsts[i]) + state[1]) % (2 ** 32),
				state[1],
				state[2]
			]

		buffer = []

		for i in range(4):
			buffer.append((iv[i] + state[i]) % (2 ** 32))

		return buffer

	iv = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

	kconsts = [
		0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
		0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
		0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
		0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
		0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
		0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
		0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
		0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
		0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
		0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
		0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
		0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
		0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
		0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
		0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
		0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
	]
	rconsts = [
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	]

	if isinstance(message, str):
		text = bytearray(message, "utf-8")
	elif isinstance(message, (bytearray, bytes)):
		text = bytearray(message) 
	else:
		raise TypeError()

	final = False

	while True:
		block = text[:64]

		if len(block) < 64:
			block.extend(b"\x80")

			while len(block) % 64 != 56:
				block.extend(b"\x00")

			block.extend((len(message) * 8).to_bytes(8, "little"))

			final = True

		if len(block) == 64:
			iv = parse(block, iv)

		if len(block) == 128:
			buffer = block

			iv = parse(buffer[:64], iv)
			iv = parse(buffer[64:], iv)

		if final:
			break

		text = text[64:]

	return b"".join(b.to_bytes(4, "little") for b in iv)

def sha1(message):
	def rotl(a, times=1):
		return ((a << times) | (a >> (32 - times))) % (2 ** 32)

	def func(a, b, c, rnd=0):
		if rnd == 0:
			return (a & b) | (~a & c)
		if rnd == 1:
			return a ^ b ^ c
		if rnd == 2:
			return (a & b) | (a & c) | (b & c)
		if rnd == 3:
			return a ^ b ^ c

	def parse(block, iv):
		schedule = []

		for i in range(0, 64, 4):
			schedule.append(int.from_bytes(block[i:i+4], "big"))

		for i in range(64):
			schedule.append(rotl(schedule[-16] ^ schedule[-14] ^ schedule[-8] ^ schedule[-3]))

		state = iv.copy()

		for i in range(80):
			t1 = (rotl(state[0], times=5) + func(state[1], state[2], state[3], rnd=i // 20) + state[4] + schedule[i] + consts[i // 20]) % (2 ** 32)

			state = [
				t1,
				state[0],
				rotl(state[1], times=30),
				state[2],
				state[3]
			]

		buffer = []

		for i in range(5):
			buffer.append((iv[i] + state[i]) % (2 ** 32))

		return buffer

	iv = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
	consts = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

	if isinstance(message, str):
		text = bytearray(message, "utf-8")
	elif isinstance(message, (bytearray, bytes)):
		text = bytearray(message) 
	else:
		raise TypeError()

	final = False

	while True:
		block = text[:64]

		if len(block) < 64:
			block.extend(b"\x80")

			while len(block) % 64 != 56:
				block.extend(b"\x00")

			block.extend((len(message) * 8).to_bytes(8, "big"))

			final = True

		if len(block) == 64:
			iv = parse(block, iv)

		if len(block) == 128:
			buffer = block

			iv = parse(buffer[:64], iv)
			iv = parse(buffer[64:], iv)

		if final:
			break

		text = text[64:]

	return b"".join(b.to_bytes(4, "big") for b in iv)

def sha2(message, digest=256):
	if isinstance(digest, int):
		digest = digest
		bits = 64 if digest > 256 else 32
	elif isinstance(digest, tuple):
		bits = digest[0] // 8
		digest = digest[1]
	else:
		raise TypeError()

	if bits == 32:
		if digest == 224:
			iv = [
				0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
				0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
			]

		if digest == 256:
			iv = [
				0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
				0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
			]

		consts = [
			0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
			0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
			0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
			0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
			0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
			0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
			0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
			0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
			0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
			0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
			0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
			0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
			0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
			0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
			0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
			0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
		]

		def lowsigma0(a):
			return rotr(a, times=7) ^ rotr(a, times=18) ^ shr(a, times=3)

		def lowsigma1(a):
			return rotr(a, times=17) ^ rotr(a, times=19) ^ shr(a, times=10)

		def upsigma0(a):
			return rotr(a, times=2) ^ rotr(a, times=13) ^ rotr(a, times=22)

		def upsigma1(a):
			return rotr(a, times=6) ^ rotr(a, times=11) ^ rotr(a, times=25)

	if bits == 64:
		if digest == 224:
			iv = [
				0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
				0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
			]

		if digest == 256:
			iv = [
				0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
				0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2
			]

		if digest == 384:
			iv = [
				0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
				0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
			]

		if digest == 512:
			iv = [
				0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
				0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
			]

		consts = [
			0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
			0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
			0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
			0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
			0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
			0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
			0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
			0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
			0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
			0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
			0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
			0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
			0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
			0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
			0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
			0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
			0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
			0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
			0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
			0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
		]

		def lowsigma0(a):
			return rotr(a, times=1) ^ rotr(a, times=8) ^ shr(a, times=7)

		def lowsigma1(a):
			return rotr(a, times=19) ^ rotr(a, times=61) ^ shr(a, times=6)

		def upsigma0(a):
			return rotr(a, times=28) ^ rotr(a, times=34) ^ rotr(a, times=39)

		def upsigma1(a):
			return rotr(a, times=14) ^ rotr(a, times=18) ^ rotr(a, times=41)

	def shr(a, times=1):
		return a >> times

	def rotr(a, times=1):
		return ((a >> times) | (a << (bits - times))) % (2 ** bits)

	def ch(a, b, c):
		return (a & b) ^ (~a & c)

	def maj(a, b, c):
		return (a & b) ^ (a & c) ^ (b & c)

	def parse(block, iv):
		schedule = []

		for i in range(0, bits * 2, bits // 8):
			schedule.append(int.from_bytes(block[i:i+(bits // 8)], "big"))

		for i in range(((bits // 32) * 16) + 32):
			schedule.append((schedule[-16] + lowsigma0(schedule[-15]) + schedule[-7] + lowsigma1(schedule[-2])) % (2 ** bits))

		state = iv.copy()

		for i in range(((bits // 32) * 16) + 48):
			t1 = (ch(state[4], state[5], state[6]) + upsigma1(state[4]) + state[7] + schedule[i] + consts[i]) % (2 ** bits)
			t2 = (maj(state[0], state[1], state[2]) + upsigma0(state[0])) % (2 ** bits)

			state = [
				(t1 + t2) % (2 ** bits),
				state[0],
				state[1],
				state[2],
				(state[3] + t1) % (2 ** bits),
				state[4],
				state[5],
				state[6],
				state[7]
			]

		buffer = []

		for i in range(8):
			buffer.append((iv[i] + state[i]) % (2 ** bits))

		return buffer

	if isinstance(message, str):
		text = bytearray(message, "utf-8")
	elif isinstance(message, (bytearray, bytes)):
		text = bytearray(message) 
	else:
		raise TypeError()

	final = False

	while True:
		block = text[:(bits * 2)]

		if len(block) < (bits * 2):
			block.extend(b"\x80")

			while len(block) % (bits * 2) != (bits * 2) - (bits // 4):
				block.extend(b"\x00")

			block.extend((len(message) * 8).to_bytes(bits // 4, "big"))

			final = True

		if len(block) == bits * 2:
			iv = parse(block, iv)

		if len(block) == bits * 4:
			buffer = block

			iv = parse(buffer[:(bits * 2)], iv)
			iv = parse(buffer[(bits * 2):], iv)

		if final:
			break

		text = text[(bits * 2):]

	return (b"".join(b.to_bytes(bits // 8, "big") for b in iv))[0:(digest // 8)]
