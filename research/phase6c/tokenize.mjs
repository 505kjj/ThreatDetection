export function tokenize(text, length) {
  if (typeof text !== 'string' || ![80, 160].includes(length)) throw new TypeError('Invalid sequence input');
  const tokens = new BigInt64Array(length);
  const characters = Array.from(text).slice(0, length);
  for (let index = 0; index < characters.length; index++) {
    const code = characters[index].codePointAt(0);
    tokens[index] = BigInt(code >= 32 && code <= 126 ? code - 30 : 1);
  }
  return tokens;
}
