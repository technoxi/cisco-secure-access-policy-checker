(function (root) {
  "use strict";

  function ipv4Bytes(text) {
    const parts = text.split(".");
    if (parts.length !== 4 || !parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return null;
    return parts.map(Number);
  }

  function parse(text) {
    if (typeof text !== "string") return null;
    const v4 = ipv4Bytes(text);
    if (v4) return { version: 4, bytes: v4 };
    if (!text.includes(":") || /[^0-9a-f:.]/i.test(text)) return null;
    let address = text;
    if (address.includes(".")) {
      const lastColon = address.lastIndexOf(":");
      const tail = ipv4Bytes(address.slice(lastColon + 1));
      if (!tail) return null;
      address = `${address.slice(0, lastColon + 1)}${((tail[0] << 8) | tail[1]).toString(16)}:${((tail[2] << 8) | tail[3]).toString(16)}`;
    }
    const compressed = address.includes("::");
    if (compressed && address.indexOf("::") !== address.lastIndexOf("::")) return null;
    const halves = compressed ? address.split("::") : [address];
    const left = halves[0] ? halves[0].split(":") : [];
    const right = compressed && halves[1] ? halves[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    if (compressed ? missing < 1 : missing !== 0) return null;
    const groups = [...left, ...Array(compressed ? missing : 0).fill("0"), ...right];
    if (!groups.every(part => /^[0-9a-f]{1,4}$/i.test(part))) return null;
    return { version: 6, bytes: groups.flatMap(part => [parseInt(part, 16) >> 8, parseInt(part, 16) & 255]) };
  }

  function parseCidr(text) {
    if (typeof text !== "string") return null;
    const parts = text.split("/");
    if (parts.length > 2) return null;
    const address = parse(parts[0]);
    if (!address) return null;
    const limit = address.version === 4 ? 32 : 128;
    if (parts.length === 2 && !/^(0|[1-9]\d{0,2})$/.test(parts[1])) return null;
    const prefix = parts.length === 2 ? Number(parts[1]) : limit;
    return prefix <= limit ? { ...address, prefix } : null;
  }

  function contains(ip, cidr) {
    const address = parse(ip);
    const network = parseCidr(cidr);
    if (!address || !network || address.version !== network.version) return false;
    const whole = Math.floor(network.prefix / 8);
    for (let i = 0; i < whole; i++) if (address.bytes[i] !== network.bytes[i]) return false;
    const bits = network.prefix % 8;
    return !bits || (address.bytes[whole] >> (8 - bits)) === (network.bytes[whole] >> (8 - bits));
  }

  root.IPAddress = { parse, parseCidr, contains };
  if (typeof module !== "undefined" && module.exports) module.exports = root.IPAddress;
})(typeof window !== "undefined" ? window : globalThis);
