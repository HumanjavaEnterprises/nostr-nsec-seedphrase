/**
 * Count the number of leading zero bits in a hex string
 * @param {string} hex - The hex string to count leading zeroes in
 * @returns {number} The number of leading zero bits
 */
export function countLeadingZeroes(hex: string): number {
  let count = 0;
  for (let i = 0; i < hex.length; i++) {
    const char = hex[i];
    if (char === '0') {
      count += 4;  // Each hex digit represents 4 bits
    } else {
      // Count leading zeroes in this hex digit
      const digit = parseInt(char, 16);
      if (digit === 0) continue;
      
      // Count leading zeroes in the non-zero digit
      count += Math.clz32(digit) - 28;  // -28 because we want the last 4 bits
      break;
    }
  }
  return count;
}

/**
 * Count the number of trailing zero bits in a hex string
 * @param {string} hex - The hex string to count trailing zeroes in
 * @returns {number} The number of trailing zero bits
 */
export function countTrailingZeroes(hex: string): number {
  let count = 0;
  for (let i = hex.length - 1; i >= 0; i--) {
    const char = hex[i];
    if (char === '0') {
      count += 4;  // Each hex digit represents 4 bits
    } else {
      // Count trailing zeroes in this hex digit
      const digit = parseInt(char, 16);
      if (digit === 0) continue;
      
      // Count trailing zeroes in the non-zero digit
      count += Math.clz32(digit & -digit) - 28;  // -28 because we want the last 4 bits
      break;
    }
  }
  return count;
}

/**
 * Count the number of set bits (1s) in a hex string
 * @param {string} hex - The hex string to count bits in
 * @returns {number} The number of set bits
 */
export function countSetBits(hex: string): number {
  let count = 0;
  for (let i = 0; i < hex.length; i++) {
    const digit = parseInt(hex[i], 16);
    count += digit.toString(2).split('1').length - 1;
  }
  return count;
}
