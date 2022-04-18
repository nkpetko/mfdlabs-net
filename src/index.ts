/*
   Copyright 2022 Nikita Petko <petko@vmminfra.net>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
    File Name: NetworingUtility.ts
    Description: A lot of useful functions for working with networks, such as getting the external IP address, gateway, IP conversions, etc.
                 You can import it by typing: import net from '@mfdlabs/net';
    Written by: Nikita Petko

    TODO: Empty, null and undefined checks for input parameters as there's no type checking in JavaScript.
    TODO: Find a way to make the @notest methods testable with mock data.
*/

import * as os from 'os';
import * as dns from 'dns';
import * as http from 'http';
import * as child_process from 'child_process';

/**
 * A lot of useful functions for working with networks, such as getting the external IP address, gateway, IP conversions, etc.
 *
 * You can import it by typing:
 * @example **TypeScript**
 * ```ts
 * import net from '@mfdlabs/net';
 * ```
 * @example **JavaScript**
 * ```js
 * const net = require('@mfdlabs/net');
 * ```
 *
 * =============================================================================
 *
 *  Copyright 2022 Nikita Petko <petko@vmminfra.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * =============================================================================
 *
 */
class NetModule {
  ////////////////////////////////////////////////////////////////////////////////
  // Private Static Methods
  ////////////////////////////////////////////////////////////////////////////////

  /**
   * Parses a big integer string into an array of digit values.
   * @param {string} bigint The big integer string.
   * @param {number} base The base of the big integer.
   * @returns {number[]} The array of digit values.
   * @internal This is an internal method and should not be used by external code.
   */
  private static _parseBigInt(bigint: string, base: number): number[] {
    // convert bigint string to array of digit values
    const values = [];
    for (let i = 0; i < bigint.length; i++) {
      values[i] = parseInt(bigint.charAt(i), base);
    }
    return values;
  }

  /**
   * Format a big integer into a string.
   * @param {number[]} values The array of digit values.
   * @param {number} base The base of the big integer.
   * @returns {string} The big integer string.
   * @internal This is an internal method and should not be used by external code.
   */
  private static _formatBigInt(values: number[], base: number): string {
    // convert array of digit values to bigint string
    let str = '';
    for (const value of values) {
      str += value.toString(base);
    }
    return str;
  }

  /**
   * Converts the base of a big integer.
   * @param {string} bigint The big integer string.
   * @param {number} inputBase The base of the big integer.
   * @param {number} outputBase The base to convert to.
   * @returns {bigint} The converted big integer.
   * @internal This is an internal method and should not be used by external code.
   */
  private static _convertBase(bigint: string, inputBase: number, outputBase: number): bigint {
    const inputValues = this._parseBigInt(bigint, inputBase);
    const outputValues = [];
    let remainder: number;
    const len = inputValues.length;
    let pos = 0;

    while (pos < len) {
      remainder = 0; // set remainder to 0
      for (let i = pos; i < len; i++) {
        // long integer division of input values divided by output base
        // remainder is added to output array
        remainder = inputValues[i] + remainder * inputBase;
        inputValues[i] = Math.floor(remainder / outputBase);
        remainder -= inputValues[i] * outputBase;
        if (inputValues[i] === 0 && i === pos) {
          pos++;
        }
      }
      outputValues.push(remainder);
    }
    outputValues.reverse(); // transform to big-endian/msd order
    return BigInt(this._formatBigInt(outputValues, outputBase));
  }

  ////////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////
  /// Public Static Constants
  ////////////////////////////////////////////////////////////////////////////////

  /**
   * A regex that compresses IPv6 addresses.
   */
  public static readonly CompressIPv6Regex = /\b:?(?:0+:?){2,}/;

  /**
   * A regex that extracts an IPv4 address from an IPv6 address.
   */
  public static readonly ExtractIPv4FromIPv6Regex = /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/;

  /**
   * A regex that verifies an embedded IPv4 address within an IPv6 address.
   */
  public static readonly ValidateIPv4Regex =
    /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})/;

  /**
   * A regex to match IPv6 addresses. It is advised to use the IsIPv6 function instead of this.
   */
  public static readonly IPv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

  /**
   * A regex to match IPv4 addresses. It is advised to use the IsIPv4 function instead of this.
   */
  public static readonly IPv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  /**
   * A regex to match ethernet network interfaces from netwokInterfaces().
   */
  public static readonly EthernetInterfaceRegex = /^eth[0-9]+$/;

  /**
   * A regex to match WiFi network interfaces from netwokInterfaces().
   */
  public static readonly WifiInterfaceRegex = /^(wlan[0-9]+|WiFi)$/gi;

  /**
   * A constant that represents the maximum number of segments in an IPv6 address.
   */
  public static readonly ValidIPv6GroupsCount = 8 as const;

  /**
   * A constant that represents the maximum number of numbers allowed in an IPv6 address hexidecimal segment.
   */
  public static readonly ValidIPv6GroupSize = 4 as const;

  /**
   * A constant that represents the largest possible RFC1918 IPv4 address.
   */
  public static readonly MaxRFC1918IPv4Cidr = '10.0.0.0/8' as const;

  /**
   * A constant that represents the second largest possible RFC1918 IPv4 address.
   */
  public static readonly SecondMaxRFC1918IPv4Cidr = '172.16.0.0/12' as const;

  /**
   * A constant that represents the smallest possible RFC1918 IPv4 address.
   */
  public static readonly MinRFC1918IPv4Cidr = '192.168.0.0/16' as const;

  /**
   * A constant that represents the IPv4 loopback CIDR.
   */
  public static readonly IPv4LoopbackCidr = '127.0.0.0/8' as const;

  /**
   * A constant that represents the IPv6 RFC4193 private network CIDR.
   * @see https://tools.ietf.org/html/rfc4193
   */
  public static readonly IPv6RFC4193Cidr = 'fc00::/7' as const;

  /**
   * A constant that represents the left side of the IPv6 RFC4193 private network CIDR.
   * @see https://tools.ietf.org/html/rfc4193
   */
  public static readonly IPv6RFC4193LeftCidr = 'fc00::/8' as const;

  /**
   * A constant that represents the right side of the IPv6 RFC4193 private network CIDR.
   * @see https://tools.ietf.org/html/rfc4193
   */
  public static readonly IPv6RFC4193RightCidr = 'fd00::/8' as const;

  /**
   * A constant that represents the IPv6 RFC3879 private network CIDR.
   * @see https://tools.ietf.org/html/rfc3879
   * @deprecated This is no longer used.
   */
  public static readonly IPv6RFC3879Cidr = 'fec0::/10' as const;

  /**
   * A constant that represents the IPv6 loopback CIDR.
   */
  public static readonly IPv6LoopbackCidr = '::1/128' as const;

  /**
   * A constant that represents the IPv4 Link-Local address.
   */
  public static readonly IPv4LinkLocal = '169.254.0.0/16' as const;

  /**
   * A constant that represents the IPv6 Link-Local address.
   */
  public static readonly IPv6LinkLocal = 'fe80::/10' as const;

  ////////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////////////////////
  /// Public Static Functions
  ////////////////////////////////////////////////////////////////////////////////

  /**
   * Attempts to expand a compressed IPv6 address like ::1 to a full IPv6 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fe80::215:5dff:fe02:1c37';
   *
   * net.decompressIPv6(ip); // 'fe80:0000:0000:0000:0215:5dff:fe02:1c37'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fe80::215:5dff:fe02:1c37';
   *
   * net.decompressIPv6(ip); // 'fe80:0000:0000:0000:0215:5dff:fe02:1c37'
   * ```
   * @param {string} ip The input IPv6 address.
   * @returns {string} The expanded IPv6 address.
   */
  public static decompressIPv6(ip: string): string {
    // decompresses an IPv6 address
    // by expanding the :: notation
    // and filling in the missing leading zeroes
    const oldIP = ip;
    let fullAddress = '';
    let expandedAddress = '';

    let groups = [];

    if (this.isIPv4(ip)) {
      // if IPv4 only, expand it to an IPv4 mapped IPv6 address
      // ::ffff:x.x.x.x
      ip = '::ffff:' + ip;
    }

    // Look for embedded IPv4 addresses
    if (this.ValidateIPv4Regex.test(ip)) {
      let IPv4 = '';

      groups = ip.match(this.ExtractIPv4FromIPv6Regex);

      for (let i = 1; i < groups.length; i++) {
        IPv4 += ('00' + parseInt(groups[i], 10).toString(16)).slice(-2) + (i === 2 ? ':' : '');
      }

      ip = ip.replace(this.ExtractIPv4FromIPv6Regex, IPv4);
    }

    if (!this.isIPv6(ip)) {
      return oldIP;
    }

    if (ip.indexOf('::') === -1)
      // All eight groups are present
      fullAddress = ip;
    else {
      // Consecutive groups of zeroes have been collapsed with ::
      const sides = ip.split('::');
      let groupsPresent = 0;

      for (const side of sides) groupsPresent += side.split(':').length;

      fullAddress += sides[0] + ':';
      for (let i = 0; i < this.ValidIPv6GroupsCount - groupsPresent; i++) fullAddress += '0000:';

      fullAddress += sides[1];
    }

    groups = fullAddress.split(':');
    for (let i = 0; i < this.ValidIPv6GroupsCount; i++) {
      while (groups[i].length < this.ValidIPv6GroupSize) groups[i] = '0' + groups[i];

      expandedAddress += i !== this.ValidIPv6GroupsCount - 1 ? groups[i] + ':' : groups[i];
    }

    return expandedAddress;
  }

  /**
   * Compresses an IPv6 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fe80:0000:0000:0000:0215:5dff:fe02:1c37';
   *
   * net.compressIPv6(ip); // 'fe80::215:5dff:fe02:1c37'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fe80:0000:0000:0000:0215:5dff:fe02:1c37';
   *
   * net.compressIPv6(ip); // 'fe80::215:5dff:fe02:1c37'
   * ```
   * @param {string} ip The IPv6 address to compress.
   * @returns {string} The compressed IPv6 address.
   */
  public static compressIPv6(ip: string): string {
    // compresses an IPv6 address
    // by replacing the zero segments with ::, only one :: is allowed, so try elect the longest one
    // and find leading zeroes within the segments and remove them
    if (!this.isIPv6(ip)) {
      return ip;
    }

    // We want to expand the address to the full form
    // So we can remove leading zeroes
    ip = this.decompressIPv6(ip);

    let segments = ip.split(':').filter((segment) => segment.length > 0);

    for (let i = 0; i < segments.length; i++) {
      // if the segment is not all zeroes then remove leading zeroes
      if (segments[i].match(/0/g)?.length !== this.ValidIPv6GroupSize) segments[i] = segments[i].replace(/^0+/, '');
    }

    ip = segments.filter((segment) => segment.length > 0).join(':');

    let replaced = ip.replace(this.CompressIPv6Regex, '::');

    segments = replaced.split(':');

    // If the segment length is 8 and the far left segment has :: then we need to remove it
    if (segments.length === this.ValidIPv6GroupsCount) {
      replaced = replaced.replace(/^::/, '');
    }

    return replaced;
  }

  /**
   * Determine if the given IP is a valid IPv4 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const ipv6 = '::1';
   *
   * net.isIPv4(ip); // true
   * net.isIPv4(ipv6); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const ipv6 = '::1';
   *
   * net.isIPv4(ip); // true
   * net.isIPv4(ipv6); // false
   * ```
   * @param {string} ip The IP address to check.
   * @returns {boolean} `true` if the IP is a valid IPv4 address, otherwise `false`.
   */
  public static isIPv4(ip: string): boolean {
    return this.IPv4Regex.test(ip);
  }

  /**
   * Determines if the given IP is a valid IPv6 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const ipv4 = '127.0.0.1';
   *
   * net.IsIPv6(ip); // true
   * net.IsIPv6(ipv4); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const ipv4 = '127.0.0.1';
   *
   * net.IsIPv6(ip); // true
   * net.IsIPv6(ipv4); // false
   * ```
   * @param {string} ip The IP address to check.
   * @returns {boolean} `true` if the IP is a valid IPv6 address, otherwise `false`.
   */
  public static isIPv6(ip: string): boolean {
    return this.IPv6Regex.test(ip);
  }

  /**
   * Converts the input IPv4 address to a number.
   *
   * If the input is not a valid IPv4 address, the function will return 0.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * cosnt ipv6 = '::1';
   *
   * net.ipv4ToNumber(ip); // 2130706433
   * net.ipv4ToNumber(ipv6); // 0
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const ipv6 = '::1';
   *
   * net.ipv4ToNumber(ip); // 2130706433
   * net.ipv4ToNumber(ipv6); // 0
   * ```
   * @param {string} ip The IP address to convert.
   * @returns {number} The number representation of the IP address. If the input is not a valid IPv4 address, the function will return 0.
   */
  public static ipv4ToNumber(ip: string): number {
    if (!this.isIPv4(ip)) return 0;

    const parts = ip.split('.');

    return (
      parseInt(parts[0], 10) * Math.pow(256, 3) +
      parseInt(parts[1], 10) * Math.pow(256, 2) +
      parseInt(parts[2], 10) * Math.pow(256, 1) +
      parseInt(parts[3], 10)
    );
  }

  /**
   * Convert the input IPv6 address to an integer.
   *
   * If the input is not a valid IPv6 address, the function will return 0n.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fe80::215:5dff:fe02:1c37';
   * const ipv4 = '127.0.0.1';
   *
   * net.ipv6ToNumber(ip); // 338288524927261089654169026357994069047n
   * net.ipv6ToNumber(ipv4); // 0n
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fe80::215:5dff:fe02:1c37';
   * const ipv4 = '127.0.0.1';
   *
   * net.ipv6ToNumber(ip); // 338288524927261089654169026357994069047n
   * net.ipv6ToNumber(ipv4); // 0n
   * ```
   * @param {string} ip The IP address to convert.
   * @returns {bigint} The number representation of the IP address. If the input is not a valid IPv6 address, the function will return 0n.
   */
  public static ipv6ToNumber(ip: string): bigint {
    if (!this.isIPv6(ip)) return 0n;

    // Converts the likes of ::1 to 0000:0000:0000:0000:0000:0000:0000:0001
    const fullAddress = this.decompressIPv6(ip);

    // Split the address into its segments
    const parts = fullAddress.split(':');

    const newParts = [];

    parts.forEach((it) => {
      let bin = parseInt(it, 16).toString(2);

      while (bin.length < 16) {
        bin = '0' + bin;
      }

      newParts.push(bin);
    });

    return this._convertBase(newParts.join(''), 2, 10);
  }

  /**
   * Convert the input number or bigint to an IPv4 address.
   *
   * If the input is greater than 0xffffffff, the function will return 255.255.255.255.
   * If the input is less than 0, the function will return 0.0.0.0.
   *
   * If the input is a bigint, the function will convert it to a number.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 0x7f000001;
   * const otherIp = 0xa64000b;
   * const ipv6 = 0xfe8000000000000002155dfffe021c37n;
   *
   * net.numberToIPv4(ip); // '127.0.0.1'
   * net.numberToIPv4(otherIp); // '10.100.0.11'
   * net.numberToIPv4(ipv6); // '255.255.255.255' -- Only because the input is greater than 0xffffffff
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 0x7f000001;
   * const otherIp = 0xa64000b;
   * const ipv6 = 0xfe8000000000000002155dfffe021c37n;
   *
   * net.numberToIPv4(ip); // '127.0.0.1'
   * net.numberToIPv4(otherIp); // '10.100.0.11'
   * net.numberToIPv4(ipv6); // '255.255.255.255' -- Only because the input is greater than 0xffffffff
   * ```
   * @param {number|bigint} ip The IP address to convert.
   * @returns {string} The IPv4 address. If the input is greater than 0xffffffff, the function will return 255.255.255.255, if the input is less than 0, the function will return 0.0.0.0. If the input is a bigint, the function will convert it to a number.
   */
  public static numberToIPv4(ip: number | bigint): string {
    if (ip < 0) return '0.0.0.0';
    if (ip > 0xffffffff) return '255.255.255.255';

    // Check if the ip is a bigint, if so convert it to a number
    if (typeof ip === 'bigint') ip = Number(ip);

    return (ip >>> 24) + '.' + ((ip >>> 16) & 0xff) + '.' + ((ip >>> 8) & 0xff) + '.' + (ip & 0xff);
  }

  /**
   * Attempts to convert the input number or bigint to an IPv6 address.
   *
   * If the input is greater than 0xffffffffffffffffffffffffffffffffn, the function will return ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
   * If the input is less than 0n, the function will return :: (if compress is true) or 0000:0000:0000:0000:0000:0000:0000:0000 (if compress is false).
   *
   * If the input is a number, the function will convert it to a bigint.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 0x7f000001n;
   * const otherIp = 0xa640000bn;
   * const ipv6 = 0xfe8000000000000002155dfffe021c37n;
   *
   * net.numberToIPv6(ip); // '::7f00:0001'
   * net.numberToIPv6(otherIp); // '::a640:00b'
   * net.numberToIPv6(ipv6); // 'fe80::2155:dfff:fe02:1c37'
   * net.numberToIPv6(ipv6, false); // '0000:0000:0000:0000:0000:0000:7f00:0001'
   * net.numberToIPv6(ipv6, false); // '0000:0000:0000:0000:0000:0000:a640:000b'
   * net.numberToIPv6(ipv6, false); // 'fe80:0000:0000:0000:2155:dfff:fe02:1c37'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 0x7f000001n;
   * const otherIp = 0xa640000bn;
   * const ipv6 = 0xfe8000000000000002155dfffe021c37n;
   *
   * net.numberToIPv6(ip); // '::7f00:0001'
   * net.numberToIPv6(otherIp); // '::a640:00b'
   * net.numberToIPv6(ipv6); // 'fe80::2155:dfff:fe02:1c37'
   * net.numberToIPv6(ipv6, false); // '0000:0000:0000:0000:0000:0000:7f00:0001'
   * net.numberToIPv6(ipv6, false); // '0000:0000:0000:0000:0000:0000:a640:000b'
   * net.numberToIPv6(ipv6, false); // 'fe80:0000:0000:0000:2155:dfff:fe02:1c37'
   * ```
   * @param {bigint|number} ip The IP address to convert.
   * @param {boolean?} compress Whether or not to compress the IPv6 address. As in 0000:0000:0000:0000:0000:0000:0000:0001 -> ::1
   * @returns {string} The IPv6 address. If the input is greater than 0xffffffffffffffffffffffffffffffffn, the function will return ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff, if the input is less than 0n, the function will return :: (if compress is true) or 0000:0000:0000:0000:0000:0000:0000:0000 (if compress is false). If the input is a number, the function will convert it to a bigint.
   */
  public static numberToIPv6(ip: bigint | number, compress: boolean = true): string {
    if (ip < 0n) return compress ? '::' : '0000:0000:0000:0000:0000:0000:0000:0000';
    if (ip > 0xffffffffffffffffffffffffffffffffn) return 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff';

    // Check if the ip is a number, if so, convert it to a bigint
    if (typeof ip === 'number') ip = BigInt(ip);

    // It decompresses here because I am too lazy to fill in the single 0 segments
    const addr = this.decompressIPv6(
      (ip >> 112n).toString(16) +
        ':' +
        ((ip >> 96n) & 0xffffn).toString(16) +
        ':' +
        ((ip >> 80n) & 0xffffn).toString(16) +
        ':' +
        ((ip >> 64n) & 0xffffn).toString(16) +
        ':' +
        ((ip >> 48n) & 0xffffn).toString(16) +
        ':' +
        ((ip >> 32n) & 0xffffn).toString(16) +
        ':' +
        ((ip >> 16n) & 0xffffn).toString(16) +
        ':' +
        (ip & 0xffffn).toString(16),
    );

    return compress ? this.compressIPv6(addr) : addr;
  }

  /**
   * Converts the input IPv4 address CIDR to it's respective start and end addresses.
   *
   * If the input CIDR subnet is not an IPv4 address, the function will return null.
   * If the mask is not specified, the function will return the subnet address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '10.0.0.0/8';
   * const ipv6 = 'fe80::/10';
   *
   * net.ipv4CIDRToStartEnd(ip); // ['10.0.0.0', '10.255.255.255']
   * net.ipv4CIDRToStartEnd(ipv6); // [null, null]
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '10.0.0.0/8';
   * const ipv6 = 'fe80::/10';
   *
   * net.ipv4CIDRToStartEnd(ip); // ['10.0.0.0', '10.255.255.255']
   * net.ipv4CIDRToStartEnd(ipv6); // [null, null]
   * ```
   * @param {string} cidr The IPv4 address CIDR to convert.
   * @returns {[string, string]} The start and end addresses of the CIDR subnet.
   */
  public static ipv4CIDRToStartEnd(cidr: string): [string, string] {
    const parts = cidr.split('/');

    const cidrSubnet = parts[0];

    if (!this.isIPv4(cidrSubnet)) return [null, null];
    if (parts.length === 1) return [cidr, cidr];

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // FIXME: Once this gets to class B it will stop allowing any prefixes and will just be 0.0.0.0             //
    // 14/04/2022: Fixed by making the numbers bigints, the reasoning for this is because the numbers are       //
    //             signed and when the leftmost bit is set, the number is negative which breaks the inverse     //
    //             operation. For some reason node.js can do uint right shift, but it can't do uint left shift. //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // HACK: This is a hack to get around the fact that the numbers are broken in node.js
    const ip = BigInt(this.ipv4ToNumber(cidrSubnet));

    const maskBits = parseInt(parts[1], 10);

    if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) return [null, null];

    const mask = 0xffffffffn << (32n - BigInt(maskBits));

    return [this.numberToIPv4(ip & mask), this.numberToIPv4(ip | (~mask & 0xffffffffn))];
  }

  /**
   * Converts the input IPv6 address CIDR to it's respective start and end addresses.
   *
   * If the input CIDR subnet is not an IPv6 address, the function will return null.
   * If the mask is not specified, the function will return the subnet address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::/0';
   * const ipv6 = 'fe80::/10';
   *
   * net.ipv6CIDRToStartEnd(ip); // ['::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ipv6); // ['fe80::', 'fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ip, false); // ['0000:0000:0000:0000:0000:0000:0000:0000', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ipv6, false); // ['fe80:0000:0000:0000:0000:0000:0000:0000', 'fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::/0';
   * const ipv6 = 'fe80::/10';
   *
   * net.ipv6CIDRToStartEnd(ip); // ['::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ipv6); // ['fe80::', 'fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ip, false); // ['0000:0000:0000:0000:0000:0000:0000:0000', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * net.ipv6CIDRToStartEnd(ipv6, false); // ['fe80:0000:0000:0000:0000:0000:0000:0000', 'fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
   * ```
   * @param {string} cidr The IPv6 address CIDR to convert.
   * @param {boolean?} compress Whether or not to compress the IPv6 address. As in 0000:0000:0000:0000:0000:0000:0000:0001 -> ::1
   * @returns {[string, string]} The start and end addresses of the CIDR subnet.
   */
  public static ipv6CIDRToStartEnd(cidr: string, compress: boolean = true): [string, string] {
    const parts = cidr.split('/');

    if (!this.isIPv6(parts[0])) return [null, null];
    if (parts.length === 1)
      return [
        !compress ? this.decompressIPv6(cidr) : this.compressIPv6(cidr),
        !compress ? this.decompressIPv6(cidr) : this.compressIPv6(cidr),
      ];

    const ip = this.ipv6ToNumber(parts[0]);

    //////////////////////////////////////////////////////////////////////////
    // FIXME: For some reason this will cap at the maskBits of 64,          //
    //        so we need to do some extra work to get the correct           //
    // 13/04/2021: Fixed this issue by converting the maskBits to a bigint. //
    //////////////////////////////////////////////////////////////////////////

    const maskBits = parseInt(parts[1], 10);

    if (isNaN(maskBits) || maskBits < 0 || maskBits > 128) return [null, null];

    const mask = 0xffffffffffffffffffffffffffffffffn << (128n - BigInt(maskBits));

    return [
      this.numberToIPv6(ip & mask, compress),
      this.numberToIPv6(ip | (~mask & 0xffffffffffffffffffffffffffffffffn), compress),
    ];
  }

  /**
   * Converts the input IPv4 start and end addresses to it's respective CIDR.
   * It will return the smallest possible CIDR.
   *
   * If the input start and end addresses are not IPv4 addresses, the function will return null.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const start = '10.0.0.0';
   * const end = '10.255.255.255';
   *
   * net.ipv4StartEndToCIDR(start, end); // '10.0.0.0/8'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const start = '10.0.0.0';
   * const end = '10.255.255.255';
   *
   * net.ipv4StartEndToCIDR(start, end); // '10.0.0.0/8'
   * ```
   * @param {string} start The IPv4 start address.
   * @param {string} end The IPv4 end address.
   * @returns {string} The CIDR subnet. Returns null if the input addresses are not IPv4 addresses.
   */
  public static ipv4StartEndToCIDR(start: string, end: string): string {
    if (!this.isIPv4(start) || !this.isIPv4(end)) return null;

    if (start === end) return start + '/32';

    const startInt = this.ipv4ToNumber(start);
    const endInt = this.ipv4ToNumber(end);

    const mask = 32 - Math.floor(Math.log2(endInt - startInt + 1));

    return this.numberToIPv4(startInt) + '/' + mask;
  }

  /**
   * Converts the input IPv6 start and end addresses to it's respective CIDR.
   * It will return the smallest possible CIDR.
   *
   * If the input start and end addresses are not IPv6 addresses, the function will return null.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const start = '::';
   * const end = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff';
   *
   * net.ipv6StartEndToCIDR(start, end); // '::/0'
   * net.ipv6StartEndToCIDR(start, end, false); // '0000:0000:0000:0000:0000:0000:0000:0000/0'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const start = '::';
   * const end = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff';
   *
   * net.ipv6StartEndToCIDR(start, end); // '::/0'
   * net.ipv6StartEndToCIDR(start, end, false); // '0000:0000:0000:0000:0000:0000:0000:0000/0'
   * ```
   * @param {string} start The IPv6 start address.
   * @param {string} end The IPv6 end address.
   * @param {boolean?} compress Whether or not to compress the IPv6 address. As in 0000:0000:0000:0000:0000:0000:0000:0001 -> ::1
   * @returns {string} The CIDR subnet. Returns null if the input addresses are not IPv6 addresses.
   */
  public static ipv6StartEndToCIDR(start: string, end: string, compress: boolean = true): string {
    if (!this.isIPv6(start) || !this.isIPv6(end)) return null;

    const startInt = this.ipv6ToNumber(start);
    const endInt = this.ipv6ToNumber(end);

    // Instead of math.log2, we use the bitwise operators to get the number of leading zeroes
    const mask = 128 - (128n - (128n - (endInt - startInt))).toString(2).replace(/0/g, '').length;

    return this.numberToIPv6(startInt, compress) + '/' + mask;
  }

  /**
   * Determines if the given IP address is within the IP range notation.
   *
   * If the input ip or range is empty, the function will return false.
   * If the input ip matches the range, the function will return true. As in ip = 127.0.0.1 and range = 127.0.0.1 (this will actually translate to 127.0.0.1/32)
   *
   * If the input ip is not an IPv4, the function will return false.
   * If the input range lower or upper bounds are not IPv4 addresses, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ipRange = '127.0.0.0-127.255.255.255';
   *
   * net.isIPv4InRange(ip, ipRange); // true
   * net.isIPv4InRange(otherIp, ipRange); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ipRange = '127.0.0.0-127.255.255.255';
   *
   * net.isIPv4InRange(ip, ipRange); // true
   * net.isIPv4InRange(otherIp, ipRange); // false
   * ```
   * @param {string} ip The IP address to check.
   * @param {string} range The IP range notation to check against.
   * @returns {boolean} Whether or not the IP address is within the IP range notation.
   */
  public static isIPv4InRange(ip: string, range: string): boolean {
    if (ip === '' || range === '') return false;
    if (ip === range) return true;
    if (!this.isIPv4(ip)) return false;

    // range might be 255.255.*.* or 1.2.3.0-1.2.3.255
    if (range.indexOf('*') !== -1) {
      // a.b.*.* format
      // Just convert it to A-B format by setting * to 0 for A and 255 for B
      const lower = range.replace(/\*/, '0');
      const upper = range.replace(/\*/, '255');
      range = `${lower}-${upper}`;
    }

    if (range.indexOf('-') !== -1) {
      // A-B format
      const [lower, upper] = range.split('-');

      if (!this.isIPv4(lower) || !this.isIPv4(upper)) return false;

      // Get the lower ip bytes
      const lowerBytes = this.ipv4ToNumber(lower);

      // Get the upper ip bytes
      const upperBytes = this.ipv4ToNumber(upper);

      // Get the ip bytes
      const ipBytes = this.ipv4ToNumber(ip);

      return ipBytes >= lowerBytes && ipBytes <= upperBytes;
    }

    return false;
  }

  /**
   * Determines if the given IP address is within any of the IP range notations.
   *
   * If the range list is empty, the function will return false.
   * If the input IP is not an IPv4 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIPv4 = '10.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1-127.255.255.255', '10.0.0.0-10.255.255.255'];
   *
   * net.isIPv4InRangeList(ip, ranges); // true (ip matches 127.0.0.1-127.255.255.255)
   * net.isIPv4InRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * net.isIPv4InRangeList(otherIPv4, ranges); // true (ip matches 10.0.0.0-10.255.255.255)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIPv4 = '10.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1-127.255.255.255', '10.0.0.0-10.255.255.255'];
   *
   * net.isIPv4InRangeList(ip, ranges); // true (ip matches 127.0.0.1-127.255.255.255)
   * net.isIPv4InRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * net.isIPv4InRangeList(otherIPv4, ranges); // true (ip matches 10.0.0.0-10.255.255.255)
   * ```
   * @param {string} ip The IP address to check.
   * @param {string[]} rangeList The IP range notations to check against.
   * @returns {boolean} Whether or not the IP address is within any of the IP range notations. If the range list is empty, the function will return false. If the input IP is not an IPv4 address, the function will return false.
   */
  public static isIPv4InRangeList(ip: string, rangeList: string[]): boolean {
    if (rangeList.length === 0) return false;
    if (!this.isIPv4(ip)) return false;

    for (const range of rangeList) {
      if (this.isIPv4InRange(ip, range)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IPv6 address is within the IP range notation.
   *
   * If the input ip or range is empty, the function will return false.
   * if the input ip matches the range, the function will return true. As in ip = ::1 and range = ::1 (this will actually translate to ::1/128)
   *
   * If the input ip is not an IPv6, the function will return false.
   * If the input range lower or upper bounds are not IPv6 addresses, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ipRange = '::1-::ffff';
   *
   * net.isIPv6InRange(ip, ipRange); // true
   * net.isIPv6InRange(otherIp, ipRange); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ipRange = '::1-::ffff';
   *
   * net.isIPv6InRange(ip, ipRange); // true
   * net.isIPv6InRange(otherIp, ipRange); // false
   * ```
   * @param {string} ip The IP address to check.
   * @param {string} range The IP range notation to check against.
   * @returns {boolean} Whether or not the IP address is within the IP range notation.
   */
  public static isIPv6InRange(ip: string, range: string): boolean {
    if (ip === '' || range === '') return false;
    if (ip === range) return true;
    if (!this.isIPv6(ip)) return false;

    // range can only be in the format of aaaa:bbbb:cccc:dddd:eeee:ffff:gggg:hhhh-hhhh:iiii:jjjj:kkkk:llll:mmmm:nnnn:oooo:pppp
    if (range.indexOf('-') !== -1) {
      // A-B format
      let [lower, upper] = range.split('-');

      if (!this.isIPv6(lower) || !this.isIPv6(upper)) return false;

      lower = this.decompressIPv6(lower);
      upper = this.decompressIPv6(upper);

      // Get the lower ip bytes
      const lowerBytes = this.ipv6ToNumber(lower);

      // Get the upper ip bytes
      const upperBytes = this.ipv6ToNumber(upper);

      // Get the ip bytes
      const ipBytes = this.ipv6ToNumber(ip);

      return ipBytes >= lowerBytes && ipBytes <= upperBytes;
    }

    return false;
  }

  /**
   * Determines if the given IPv6 address is within any of the IP range notations.
   *
   * If the range list is empty, the function will return false.
   * If the input IP is not an IPv6 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1-::ffff', '::1-::ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
   *
   * net.isIPv6InRangeList(ip, ranges); // true (ip matches ::1-::ffff)
   * net.isIPv6InRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1-::ffff', '::1-::ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
   *
   * net.isIPv6InRangeList(ip, ranges); // true (ip matches ::1-::ffff)
   * net.isIPv6InRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IP address to check.
   * @param {string[]} rangeList The IP range notations to check against.
   * @returns {boolean} Whether or not the IP address is within any of the IP range notations. If the range list is empty, the function will return false. If the input IP is not an IPv6 address, the function will return false.
   */
  public static isIPv6InRangeList(ip: string, rangeList: string[]): boolean {
    if (rangeList.length === 0) return false;
    if (!this.isIPv6(ip)) return false;

    for (const range of rangeList) {
      if (this.isIPv6InRange(ip, range)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IP address is within the IP netmask notation.
   *
   * If the input ip or netmask is empty, the function will return false.
   * if the input ip matches the netmask, the function will return true. As in ip = ::1 and netmask = ::1 (this will actually translate to ::1/128)
   * If the input netmask is 0.0.0.0/0.0.0.0, the function will return true always.
   * If the input netmask is not an IPv4, the function will return false.
   *
   * If the input netmask subnet is not a valid IPv4, the function will return false.
   * If the input netmask subnet mask is not a valid IPv4, it will default to 255.255.255.255.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const netmask = '127.0.0.0/255.0.0.0';
   *
   * net.isIPv4InNetmask(ip, netmask); // true
   * net.isIPv4InNetmask(otherIp, netmask); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const netmask = '127.0.0.0/255.0.0.0';
   *
   * net.isIPv4InNetmask(ip, netmask); // true
   * net.isIPv4InNetmask(otherIp, netmask); // false
   * ```
   * @note This method is only valid for IPv4 addresses as fully qualified IPv6 Subnet masks are not a thing.
   * @param {string} ip The IP address to check.
   * @param {string} netmask The IP netmask notation to check against.
   * @returns {boolean} Whether or not the IP address is within the IP netmask notation.
   */
  public static isIPv4InNetmask(ip: string, netmask: string): boolean {
    if (ip === '' || netmask === '') return false;
    if (ip === netmask) return true;
    if (netmask === '0.0.0.0/0.0.0.0') return true;
    if (!this.isIPv4(ip)) return false;

    if (netmask.indexOf('/') !== -1) {
      const split = netmask.split('/');
      const range = split[0];
      if (!this.isIPv4(range)) return false;

      let mask = split[1];

      if (mask.indexOf('.') !== -1) {
        // netmask is a
        // a.b.c.d/mask
        // replace all * with 0
        mask = mask.replace(/\*/g, '0');

        if (!this.isIPv4(mask)) mask = '255.255.255.255';

        // Get the mask bytes
        const maskBytes = this.ipv4ToNumber(mask);

        // Get the ip bytes
        const ipBytes = this.ipv4ToNumber(ip);

        // get range bytes
        const rangeBytes = this.ipv4ToNumber(range);

        return (ipBytes & maskBytes) === (rangeBytes & maskBytes);
      }
    }

    return false;
  }

  /**
   * Determines if the given IP address is within any of the IP netmask notations.
   *
   * If the range list is empty, the function will return false.
   * If the input IP is not an IPv4 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.0/255.0.0.0'];
   *
   * net.isIPv4InNetmaskList(ip, ranges); // true (ip matches 127.0.0.0/255.0.0.0)
   * net.isIPv4InNetmaskList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.0/255.0.0.0'];
   *
   * net.isIPv4InNetmaskList(ip, ranges); // true (ip matches 127.0.0.0/255.0.0.0)
   * net.isIPv4InNetmaskList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IP address to check.
   * @param {string[]} netmaskList The IP netmask notations to check against.
   * @returns {boolean} Whether or not the IP address is within any of the IP netmask notations. If the range list is empty, the function will return false. If the input IP is not an IPv4 address, the function will return false.
   */
  public static isIPv4InNetmaskList(ip: string, netmaskList: string[]): boolean {
    if (netmaskList.length === 0) return false;
    if (!this.isIPv4(ip)) return false;

    for (const netmask of netmaskList) {
      if (this.isIPv4InNetmask(ip, netmask)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IP address is within the IP CIDR notation.
   *
   * If the input ip or cidr is empty, the function will return false.
   * if the input ip matches the cidr, the function will return true. As in ip = 127.0.0.1 and cidr = 127.0.0.1 (this will actually translate to 127.0.0.1/32), the function will return true.
   * If the input cidr is 0.0.0.0/0 it will always return true.
   * If the input ip is not an IPv4, the function will return false.
   * If the input cidr subnet is not a valid IPv4, the function will return false.
   * If the mask is not specified, it will default to 32.
   * If the specified mask is not a valid number, it will default to 32.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const cidr = '127.0.0.0/8';
   *
   * net.isIPv4InCidrRange(ip, cidr); // true
   * net.isIPv4InCidrRange(otherIp, cidr); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const cidr = '127.0.0.0/8';
   *
   * net.isIPv4InCidrRange(ip, cidr); // true
   * net.isIPv4InCidrRange(otherIp, cidr); // false
   * ```
   * @param {string} ip The IP address to check.
   * @param {string} cidr The IP CIDR notation to check against.
   * @returns {boolean} Whether or not the IP address is within the IP CIDR notation.
   */
  public static isIPv4InCidrRange(ip: string, cidr: string): boolean {
    if (ip === '' || cidr === '') return false;
    if (ip === cidr) return true;
    if (cidr === '0.0.0.0/0') return true;
    if (!this.isIPv4(ip)) return false;

    const split = cidr.split('/');
    const subnet = split[0];

    if (!this.isIPv4(subnet)) return false;

    let mask = split[1];

    // Mask is technically optional. If it's not specified, assume it's a /32
    if (mask === undefined) mask = '32';

    let maskAsInt = parseInt(mask, 10);

    if (isNaN(maskAsInt) || maskAsInt < 0 || maskAsInt > 32) maskAsInt = 32;

    // Get ip bytes
    const ipBytes = this.ipv4ToNumber(ip);

    // Get mask bytes
    const maskBytes = -1 << (32 - maskAsInt);

    // Get subnet bytes
    let subnetBytes = this.ipv4ToNumber(subnet);

    // nb: in case the supplied subnet wasn't correctly aligned.
    subnetBytes &= maskBytes;

    return (ipBytes & maskBytes) === subnetBytes;
  }

  /**
   * Determines if the given IP address is within any of the IP CIDR notations.
   *
   * If the range list is empty, the function will return false.
   * If the input IP is not an IPv4 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1/8'];
   *
   * net.isIPv4InCidrRangeList(ip, ranges); // true (ip matches 127.0.0.1/8)
   * net.isIPv4InCidrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1/8'];
   *
   * net.isIPv4InCidrRangeList(ip, ranges); // true (ip matches 127.0.0.1/8)
   * net.isIPv4InCidrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IP address to check.
   * @param {string[]} cidrList The IP CIDR notations to check against.
   * @returns {boolean} Whether or not the IP address is within any of the IP CIDR notations.
   */
  public static isIPv4InCidrRangeList(ip: string, cidrList: string[]): boolean {
    if (cidrList.length === 0) return false;
    if (!this.isIPv4(ip)) return false;

    for (const cidr of cidrList) {
      if (this.isIPv4InCidrRange(ip, cidr)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IPv6 address is within the IP CIDR notation.
   *
   * If the input ip or cidr is empty, the function will return false.
   * if the input ip matches the cidr, the function will return true. As in ip = ::1 and cidr = ::1 (this will actually translate to ::1/128), the function will return true.
   * If the input cidr is ::/0 it will always return true.
   * If the input ip is not an IPv6, the function will return false.
   * If the input cidr subnet is not a valid IPv6, the function will return false.
   * If the mask is not specified, it will default to 128.
   * If the specified mask is not a valid number, it will default to 128.
   *
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const cidr = '::1/112';
   *
   * net.isIPv6InCidrRange(ip, cidr); // true
   * net.isIPv6InCidrRange(otherIp, cidr); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const cidr = '::1/112';
   *
   * net.isIPv6InCidrRange(ip, cidr); // true
   * net.isIPv6InCidrRange(otherIp, cidr); // false
   * ```
   * @param {string} ip The IPv6 address to check.
   * @param {string} cidr The IPv6 CIDR notation to check against.
   * @returns {boolean} Whether or not the IPv6 address is within the IPv6 CIDR notation.
   */
  public static isIPv6InCidrRange(ip: string, cidr: string): boolean {
    if (ip === '' || cidr === '') return false;
    if (ip === cidr) return true;
    if (cidr === '::/0') return true;
    if (!this.isIPv6(ip)) return false;

    const split = cidr.split('/');
    const subnet = split[0];

    if (!this.isIPv6(subnet)) return false;

    let mask = split[1];

    // Mask is technically optional. If it's not specified, assume it's a /128
    if (mask === undefined) mask = '128';

    let maskAsInt = parseInt(mask, 10);

    if (isNaN(maskAsInt) || maskAsInt < 0 || maskAsInt > 128) maskAsInt = 128;

    // Get ip bytes
    const ipBytes = this.ipv6ToNumber(ip);

    // Get mask bytes
    const maskBytes = -1n << (128n - BigInt(maskAsInt));

    // Get subnet bytes
    let subnetBytes = this.ipv6ToNumber(subnet);

    // nb: in case the supplied subnet wasn't correctly aligned.
    subnetBytes &= maskBytes;

    return (ipBytes & maskBytes) === subnetBytes;
  }

  /**
   * Determines if the given IPv6 address is within any of the IP CIDR notations.
   *
   * If the range list is empty, the function will return false.
   * If the input IP is not an IPv6 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1/112'];
   *
   * net.isIPv6InCidrRangeList(ip, ranges); // true (ip matches ::1/112)
   * net.isIPv6InCidrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1/112'];
   *
   * net.isIPv6InCidrRangeList(ip, ranges); // true (ip matches ::1/112)
   * net.isIPv6InCidrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IPv6 address to check.
   * @param {string[]} cidrList The IPv6 CIDR notations to check against.
   * @returns {boolean} Whether or not the IPv6 address is within any of the IPv6 CIDR notations.
   */
  public static isIPv6InCidrRangeList(ip: string, cidrList: string[]): boolean {
    if (cidrList.length === 0) return false;
    if (!this.isIPv6(ip)) return false;

    for (const cidr of cidrList) {
      if (this.isIPv6InCidrRange(ip, cidr)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IP address is within the IP Range, Netmask, or CIDR notation.
   *
   * If the input ip or range is empty, the function will return false.
   * if the input ip matches the range, the function will return true. As in ip = 127.0.0.1 and range = 127.0.0.1 (this will actually translate to 127.0.0.1/32), the function will return true.
   * If the input range is not a valid IP Range, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const range = '127.0.0.0-127.255.255.255';
   * const netmask = '127.0.0.0/255.0.0.0';
   * const cidr = '127.0.0.0/8';
   *
   * net.isIPv4InCidrNetmaskOrRange(ip, range); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, range); // false
   * net.isIPv4InCidrNetmaskOrRange(ip, netmask); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, netmask); // false
   * net.isIPv4InCidrNetmaskOrRange(ip, cidr); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, cidr); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const range = '127.0.0.0-127.255.255.255';
   * const netmask = '127.0.0.0/255.0.0.0';
   * const cidr = '127.0.0.0/8';
   *
   * net.isIPv4InCidrNetmaskOrRange(ip, range); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, range); // false
   * net.isIPv4InCidrNetmaskOrRange(ip, netmask); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, netmask); // false
   * net.isIPv4InCidrNetmaskOrRange(ip, cidr); // true
   * net.isIPv4InCidrNetmaskOrRange(otherIp, cidr); // false
   * ```
   * @param {string} ip The IP address to check.
   * @param {string} cidrNetmaskOrRange The IP Range, Netmask, or CIDR notation to check against.
   * @returns {boolean} Whether or not the IP address is within the IP Range, Netmask, or CIDR notation.
   */
  public static isIPv4InCidrNetmaskOrRange(ip: string, cidrNetmaskOrRange: string): boolean {
    if (ip === '' || cidrNetmaskOrRange === '') return false;
    if (ip === cidrNetmaskOrRange) return true;
    if (!this.isIPv4(ip)) return false;

    return (
      this.isIPv4InRange(ip, cidrNetmaskOrRange) ||
      this.isIPv4InNetmask(ip, cidrNetmaskOrRange) ||
      this.isIPv4InCidrRange(ip, cidrNetmaskOrRange)
    );
  }

  /**
   * Determines if the given IPv6 address is within the IP Range or CIDR notation.
   *
   * If the input ip or range is empty, the function will return false.
   * if the input ip matches the range, the function will return true. As in ip = ::1 and range = ::1 (this will actually translate to ::1/128), the function will return true.
   * If the input range is not a valid IP Range, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const range = '::1-::ffff';
   * const cidr = '::1/112';
   *
   * net.isIPv6InCidrOrRange(ip, range); // true
   * net.isIPv6InCidrOrRange(otherIp, range); // false
   * net.isIPv6InCidrOrRange(ip, cidr); // true
   * net.isIPv6InCidrOrRange(otherIp, cidr); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const range = '::1-::ffff';
   * const cidr = '::1/112';
   *
   * net.isIPv6InCidrOrRange(ip, range); // true
   * net.isIPv6InCidrOrRange(otherIp, range); // false
   * net.isIPv6InCidrOrRange(ip, cidr); // true
   * net.isIPv6InCidrOrRange(otherIp, cidr); // false
   * ```
   * @param {string} ip The IPv6 address to check.
   * @param {string} cidrOrRange The IPv6 Range or CIDR notation to check against.
   * @returns {boolean} Whether or not the IPv6 address is within the IPv6 Range or CIDR notation.
   */
  public static isIPv6InCidrOrRange(ip: string, cidrOrRange: string): boolean {
    if (ip === '' || cidrOrRange === '') return false;
    if (ip === cidrOrRange) return true;
    if (!this.isIPv6(ip)) return false;

    return this.isIPv6InRange(ip, cidrOrRange) || this.isIPv6InCidrRange(ip, cidrOrRange);
  }

  /**
   * Determines if the given IP address is within the IP Range, Netmask, or CIDR notations
   *
   * If the input list is empty, the function will return false.
   * If the input ip is not a valid IPv4 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1-127.255.255.255', '127.0.0.0/255.0.0.0', '127.0.0.0/8'];
   *
   * net.isIPv4InCidrNetmaskOrRangeList(ip, ranges); // true (ip matches all of the ranges)
   * net.isIPv4InCidrNetmaskOrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const ranges = ['127.0.0.1-127.255.255.255', '127.0.0.0/255.0.0.0', '127.0.0.0/8'];
   *
   * net.isIPv4InCidrNetmaskOrRangeList(ip, ranges); // true (ip matches all of the ranges)
   * net.isIPv4InCidrNetmaskOrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IP address to check.
   * @param {string[]} cidrNetmaskOrRangeList The IP Range, Netmask, or CIDR notations to check against.
   * @returns {boolean} Whether or not the IP address is within the IP Range, Netmask, or CIDR notations.
   */
  public static isIPv4InCidrNetmaskOrRangeList(ip: string, cidrNetmaskOrRangeList: string[]): boolean {
    if (cidrNetmaskOrRangeList.length === 0) return false;
    if (!this.isIPv4(ip)) return false;

    for (const cidrNetmaskOrRange of cidrNetmaskOrRangeList) {
      if (this.isIPv4InCidrNetmaskOrRange(ip, cidrNetmaskOrRange)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IPv6 address is within the IP Range or CIDR notations.
   *
   * If the input list is empty, the function will return false.
   * If the input ip is not a valid IPv6 address, the function will return false.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1-::ffff', '::1/112'];
   *
   * net.isIPv6InCidrOrRangeList(ip, ranges); // true (ip matches all of the ranges)
   * net.isIPv6InCidrOrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1';
   * const otherIp = '127.0.0.1';
   * const ranges = ['::1-::ffff', '::1/112'];
   *
   * net.isIPv6InCidrOrRangeList(ip, ranges); // true (ip matches all of the ranges)
   * net.isIPv6InCidrOrRangeList(otherIp, ranges); // false (ip doesn't match any of the ranges)
   * ```
   * @param {string} ip The IPv6 address to check.
   * @param {string[]} cidrOrRangeList The IPv6 Range or CIDR notations to check against.
   * @returns {boolean} Whether or not the IPv6 address is within the IPv6 Range or CIDR notation.
   */
  public static isIPv6InCidrOrRangeList(ip: string, cidrOrRangeList: string[]): boolean {
    if (cidrOrRangeList.length === 0) return false;
    if (!this.isIPv6(ip)) return false;

    for (const cidrOrRange of cidrOrRangeList) {
      if (this.isIPv6InCidrOrRange(ip, cidrOrRange)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Determines if the given IPv4 address is an RFC1918 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const rfc1918Ip = '10.0.0.1';
   *
   * net.isIPv4RFC1918(ip); // false
   * net.isIPv4RFC1918(otherIp); // false
   * net.isIPv4RFC1918(rfc1918Ip); // true
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   * const rfc1918Ip = '10.0.0.1';
   *
   * net.isIPv4RFC1918(ip); // false
   * net.isIPv4RFC1918(otherIp); // false
   * net.isIPv4RFC1918(rfc1918Ip); // true
   * ```
   * @param {string} ip The IPv4 address to check.
   * @returns {boolean} Whether or not the IPv4 address is an RFC1918 address.
   */
  public static isIPv4RFC1918(ip: string): boolean {
    return this.isIPv4InCidrRangeList(ip, [
      this.MaxRFC1918IPv4Cidr,
      this.SecondMaxRFC1918IPv4Cidr,
      this.MinRFC1918IPv4Cidr,
    ]);
  }

  /**
   * Determines if the given IPv4 address is a loopback address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   *
   * net.isIPv4Loopback(ip); // true
   * net.isIPv4Loopback(otherIp); // false (because it's an IPv6 address)
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.1';
   * const otherIp = '::1';
   *
   * net.isIPv4Loopback(ip); // true
   * net.isIPv4Loopback(otherIp); // false (because it's an IPv6 address)
   * ```
   * @param {string} ip The IPv4 address to check.
   * @returns {boolean} Whether or not the IPv4 address is a loopback address.
   */
  public static isIPv4Loopback(ip: string): boolean {
    return this.isIPv4InCidrRange(ip, this.IPv4LoopbackCidr);
  }

  /**
   * Determines if the given IPv6 address is a RFC4193 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fe80::1';
   * const otherIp = '::1';
   *
   * net.isIPv6RFC4193(ip); // true
   * net.isIPv6RFC4193(otherIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fe80::1';
   * const otherIp = '::1';
   *
   * net.isIPv6RFC4193(ip); // true
   * net.isIPv6RFC4193(otherIp); // false
   * ```
   * @param {string} ip The IPv6 address to check.
   * @returns {boolean} Whether or not the IPv6 address is a RFC4193 address.
   */
  public static isIPv6RFC4193(ip: string): boolean {
    return this.isIPv6InCidrRange(ip, this.IPv6RFC4193Cidr);
  }

  /**
   * Determines if the given IPv6 address is a RFC3879 address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fc00::1';
   * const otherIp = '::1';
   *
   * net.isIPv6RFC3879(ip); // true
   * net.isIPv6RFC3879(otherIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fc00::1';
   * const otherIp = '::1';
   *
   * net.isIPv6RFC3879(ip); // true
   * net.isIPv6RFC3879(otherIp); // false
   * ```
   * @deprecated RFC3879 is deprecated.
   * @param {string} ip The IPv6 address to check.
   * @returns {boolean} Whether or not the IPv6 address is a RFC3879 address.
   */
  public static isIPv6RFC3879(ip: string): boolean {
    return this.isIPv6InCidrRange(ip, this.IPv6RFC3879Cidr);
  }

  /**
   * Determines if the given IPv6 address is a site-local address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fec0::1';
   * const otherIp = '::1';
   *
   * net.isIPv6Loopback(ip); // false
   * net.isIPv6Loopback(otherIp); // true
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fec0::1';
   * const otherIp = '::1';
   *
   * net.isIPv6Loopback(ip); // false
   * net.isIPv6Loopback(otherIp); // true
   * ```
   * @param {string} ip The IPv6 address to check.
   * @returns {boolean} Whether or not the IPv6 address is a site-local address.
   */
  public static isIPv6Loopback(ip: string): boolean {
    return this.isIPv6InCidrRange(ip, this.IPv6LoopbackCidr);
  }

  /**
   * Determines if the given IPv4 address is a link-local address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '169.254.0.1';
   * const otherIp = '::1';
   * const loopbackIp = '127.0.0.1';
   *
   * net.isIPv4LinkLocal(ip); // true
   * net.isIPv4LinkLocal(otherIp); // false
   * net.isIPv4LinkLocal(loopbackIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '169.254.0.1';
   * const otherIp = '::1';
   * const loopbackIp = '127.0.0.1';
   *
   * net.isIPv4LinkLocal(ip); // true
   * net.isIPv4LinkLocal(otherIp); // false
   * net.isIPv4LinkLocal(loopbackIp); // false
   * ```
   * @param {string} ip The IPv4 address to check.
   * @returns {boolean} Whether or not the IPv4 address is a link-local address.
   */
  public static isIPv4LinkLocal(ip: string): boolean {
    return this.isIPv4InCidrRange(ip, this.IPv4LinkLocal);
  }

  /**
   * Determines if the given IPv6 address is a link-local address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = 'fe80::1';
   * const otherIp = '127.0.0.1';
   * const loopbackIp = '::1';
   *
   * net.isIPv6LinkLocal(ip); // true
   * net.isIPv6LinkLocal(otherIp); // false
   * net.isIPv6LinkLocal(loopbackIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = 'fe80::1';
   * const otherIp = '127.0.0.1';
   * const loopbackIp = '::1';
   *
   * net.isIPv6LinkLocal(ip); // true
   * net.isIPv6LinkLocal(otherIp); // false
   * net.isIPv6LinkLocal(loopbackIp); // false
   * ```
   * @param {string} ip The IPv6 address to check.
   * @returns {boolean} Whether or not the IPv6 address is a link-local address.
   */
  public static isIPv6LinkLocal(ip: string): boolean {
    return this.isIPv6InCidrRange(ip, this.IPv6LinkLocal);
  }

  /**
   * Determines if the given CIDR is an IPv4 CIDR.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '127.0.0.0/8';
   * const otherIp = '::1/128';
   *
   * net.isCidrIPv4(ip); // true
   * net.isCidrIPv4(otherIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '127.0.0.0/8';
   * const otherIp = '::1/128';
   *
   * net.isCidrIPv4(ip); // true
   * net.isCidrIPv4(otherIp); // false
   * ```
   * @param {string} cidr The CIDR to check.
   * @returns {boolean} Whether or not the CIDR is an IPv4 CIDR.
   */
  public static isCidrIPv4(cidr: string): boolean {
    return this.isIPv4(cidr?.split('/')[0]);
  }

  /**
   * Determines if the given CIDR is an IPv6 CIDR.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * const ip = '::1/128';
   * const otherIp = '127.0.0.0/8';
   *
   * net.isCidrIPv6(ip); // true
   * net.isCidrIPv6(otherIp); // false
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * const ip = '::1/128';
   * const otherIp = '127.0.0.0/8';
   *
   * net.isCidrIPv6(ip); // true
   * net.isCidrIPv6(otherIp); // false
   * ```
   * @param {string} cidr The CIDR to check.
   * @returns {boolean} Whether or not the CIDR is an IPv6 CIDR.
   */
  public static isCidrIPv6(cidr: string): boolean {
    return this.isIPv6(cidr?.split('/')[0]);
  }

  /**
   * Resolves the IP address of the given hostname.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * await net.resolveHostname('localhost'); // '127.0.0.1' or '::1'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * await net.resolveHostname('localhost'); // '127.0.0.1' or '::1'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @async This method is asynchronous and needs to be awaited.
   * @param {string} hostname The hostname to resolve.
   * @returns {Promise<string>} The IP address of the hostname.
   */
  public static async resolveHostname(hostname: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      dns.lookup(hostname, (err, address, _) => {
        if (err) {
          if (err.code === 'ENOTFOUND') {
            resolve(null);

            return;
          }

          reject(err);
        }
        return resolve(address);
      });
    });
  }

  /**
   * Gets the RFC1918 IP address for the current machine.
   *
   * It will either return the first ethernet interface address or WiFi interface address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getLocalIPv4(); // '192.168.0.2'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getLocalIPv4(); // '192.168.0.2'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {string} The current IPv4 address.
   */
  public static getLocalIPv4(): string {
    const netInterfaces = os.networkInterfaces();
    for (const interfaceName in netInterfaces) {
      if (!this.EthernetInterfaceRegex.test(interfaceName) && !this.WifiInterfaceRegex.test(interfaceName)) continue;

      const netInterface = netInterfaces[interfaceName];

      for (const alias of netInterface) {
        if (
          alias.family === 'IPv4' &&
          alias.address !== 'localhost' &&
          !this.isIPv4Loopback(alias.address) &&
          this.isIPv4RFC1918(alias.address)
        ) {
          return alias.address;
        }
      }
    }
    return '127.0.0.1'; // This means we have no IPv4 address, and we're not on a LAN. TODO: Make this determine if we're link-local or not.
  }

  /**
   * Gets the current RFC 4193 or RFC 3879 IPv6 address for the current machine.
   *
   * It will either return the first ethernet interface address or WiFi interface address.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getLocalIPv6(); // 'fdb6:c1e2:b44e:0:f838:c9e0:1d98:6a57'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getLocalIPv6(); // 'fdb6:c1e2:b44e:0:f838:c9e0:1d98:6a57'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {string} The current IPv6 address.
   */
  public static getLocalIPv6(): string {
    const netInterfaces = os.networkInterfaces();
    for (const interfaceName in netInterfaces) {
      if (!this.EthernetInterfaceRegex.test(interfaceName) && !this.WifiInterfaceRegex.test(interfaceName)) continue;

      const netInterface = netInterfaces[interfaceName];

      for (const alias of netInterface) {
        if (
          alias.family === 'IPv6' &&
          !this.isIPv6Loopback(alias.address) &&
          (this.isIPv6RFC3879(alias.address) || this.isIPv6RFC4193(alias.address))
        ) {
          return alias.address;
        }
      }
    }
    return '::1'; // This means we have no IPv4 address, and we're not on a LAN. TODO: Make this determine if we're link-local or not.
  }

  /**
   * Attempts to fetch the public IP of the current machine from it's network interfaces.
   * It will go through each ethernet and wlan interface and return the first one that isn't loopback or RFC1918.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getPublicIPv4FromInterfaces(); // '13.23.40.33'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getPublicIPv4FromInterfaces(); // '13.23.40.33'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {string} The public IPv4 address.
   */
  public static getPublicIPv4FromInterfaces(): string {
    const netInterfaces = os.networkInterfaces();
    for (const interfaceName in netInterfaces) {
      if (!this.EthernetInterfaceRegex.test(interfaceName) && !this.WifiInterfaceRegex.test(interfaceName)) continue;

      const netInterface = netInterfaces[interfaceName];

      for (const alias of netInterface) {
        if (
          alias.family === 'IPv4' &&
          alias.address !== 'localhost' &&
          !this.isIPv4Loopback(alias.address) &&
          !this.isIPv4RFC1918(alias.address) &&
          !this.isIPv4LinkLocal(alias.address)
        ) {
          return alias.address;
        }
      }
    }
    return null;
  }

  /**
   * Attempts to fetch the public IPv6 of the current machine from it's network interfaces.
   * It will go through each ethernet and wlan interface and return the first one that isn't loopback, RFC3879, or RFC4193.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getPublicIPv6FromInterfaces(); // '2607:f740:e00b::1'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getPublicIPv6FromInterfaces(); // '2607:f740:e00b::1'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {string} The public IPv6 address.
   */
  public static getPublicIPv6FromInterfaces(): string {
    const netInterfaces = os.networkInterfaces();
    for (const interfaceName in netInterfaces) {
      if (!this.EthernetInterfaceRegex.test(interfaceName) && !this.WifiInterfaceRegex.test(interfaceName)) continue;

      const netInterface = netInterfaces[interfaceName];

      for (const alias of netInterface) {
        if (
          alias.family === 'IPv6' &&
          !this.isIPv6Loopback(alias.address) &&
          !this.isIPv6RFC4193(alias.address) &&
          !this.isIPv6RFC3879(alias.address) &&
          !this.isIPv4LinkLocal(alias.address)
        ) {
          return alias.address;
        }
      }
    }
    return null;
  }

  /**
   * Trys to fetch the public IP address of the current machine.
   * Use this over `getPublicIPv4FromInterfaces()` and `getPublicIPv6FromInterfaces()`
   * if you do not have any WAN addresses assigned to any of your network interfaces as this will
   * attempt to fetch the public IP address by requesting an external API such as api.ipify.org.
   *
   * It is not garunteed to return the WAN IPv4 or IPv6 address of the current machine.
   * It is whatever your Gateway is configured to translate to.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getPublicIP(); // '193.12.33.26'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getPublicIP(); // '193.12.33.26'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @async This method is asynchronous and needs to be awaited.
   * @returns {Promise<string>} The public IPv4 or IPv6 address.
   */
  public static async getPublicIP(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      http.get({ host: 'api.ipify.org', port: 80, path: '/' }, (resp) => {
        resp.on('data', (ip) => {
          resolve(ip.toString());

          return;
        });

        resp.on('error', (err) => {
          reject(err);

          return;
        });
      });
    });
  }

  /**
   * Gets the route table for the current machine.
   *
   * This is only supported on Windows until I figure out how to properly implement it on Linux.
   *
   * TODO: Implement this on Linux.
   * TODO: Result types.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getRouteTable(); // [{ type: 'interface', name: 'Software Loopback Interface 1' }, { type: 'iv4', gateway: '192.168.1.1', ... }]
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getRouteTable(); // [{ type: 'interface', name: 'Software Loopback Interface 1' }, { type: 'iv4', gateway: '192.168.1.1', ... }]
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {any[]} The route table. You will need to do some manual parsing to get the actual values. The only shared key is `type` which will be either `interface`, `iv4`, or `iv6`.
   */
  public static getRouteTable(): any[] {
    if (process.platform === 'win32') {
      // We will use `route print` to get the route table.
      // It is in the format of:
      // ===========================================================================
      // Interface List
      // 1...........................Software Loopback Interface 1
      // ...
      // ===========================================================================
      //
      // IPv4 Route Table
      // ===========================================================================
      // Active Routes:
      // Network Destination        Netmask          Gateway       Interface  Metric
      //           0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.50     35
      // ...
      // ===========================================================================
      // Persistent Routes:
      //    ...
      // ===========================================================================
      //
      // IPv6 Route Table
      // ===========================================================================
      // Active Routes:
      //  If Metric Network Destination      Gateway
      //   1    331 ::1/128                  On-link
      //   ...
      // ===========================================================================
      // Persistent Routes:
      //    ...
      // ===========================================================================
      //
      // We will only parse the IPv4 route table if IPv4Only is true.

      const routeTable = child_process.execSync('route print').toString();
      const routeTableLines = routeTable.split('\r\n'); // we assume it's gonna be \r\n because windows.

      let interfaces = false;
      let IPv4Routes = false;
      let IPv6Routes = false;
      let didHitFirstHeader = false;

      const routes = [];
      for (const line of routeTableLines) {
        if (line.startsWith('===========================================================================')) {
          // Check if they are all false. If so then we are the first header which means this equals sign comes before the title.
          if (!interfaces && !IPv4Routes && !IPv6Routes) {
            interfaces = true;
            IPv4Routes = false;
            IPv6Routes = false;
            didHitFirstHeader = true;

            continue;
          }

          if (didHitFirstHeader) {
            // We hit the second header, so we are done. Unset the flags.
            interfaces = false;
            IPv4Routes = false;
            IPv6Routes = false;
            didHitFirstHeader = false;
          } else {
            didHitFirstHeader = true;
          }

          continue;
        }

        if (line.startsWith('Active Routes:')) {
          continue;
        }

        if (line.startsWith('Interface List')) {
          continue;
        }

        // We need to differentiate between the Interface List, IPv4 Route Table, and IPv6 Route Table.

        if (line.startsWith('IPv4 Route Table')) {
          interfaces = false;
          IPv4Routes = true;
          IPv6Routes = false;

          continue;
        }

        if (line.startsWith('IPv6 Route Table')) {
          interfaces = false;
          IPv4Routes = false;
          IPv6Routes = true;

          continue;
        }

        if (interfaces) {
          // We are in the interface list.
          // It is in the format of:
          // .... numbers .....Interface Name
          // We need to parse the interface name. We don't care about the numbers.
          const interfaceName = line.split('.');

          // It should be the last item in the array.
          if (interfaceName.length > 0) {
            routes.push({
              name: interfaceName[interfaceName.length - 1].trim(),
              type: 'interface',
            });
          }

          continue;
        }

        if (IPv4Routes) {
          // We are in the IPv4 route table.
          // It is in the format of:
          // Network Destination        Netmask          Gateway       Interface  Metric
          // We need to parse the network destination, netmask, gateway, and interface.
          const route = line.split(' ').filter((x) => x.length > 0);

          // Check if we are at the header. i.e the first line after the equals signs.
          // Just check if it starts with a "Network Destination".
          if (route[0].startsWith('Network')) {
            continue;
          }

          // It should be the last item in the array.
          if (route.length > 0) {
            routes.push({
              gateway: route[2].trim(),
              interface: route[3].trim(),
              metric: parseInt(route[4].trim(), 10),
              netmask: route[1].trim(),
              network: route[0].trim(),
              type: 'iv4',
            });
          }

          continue;
        }

        if (IPv6Routes) {
          // We are in the IPv6 route table.
          // It is in the format of:
          // If Metric Network Destination      Gateway
          // 1    331 ::1/128                  On-link
          // ...
          // We need to parse the network destination, gateway, and interface.
          const route = line.split(' ').filter((x) => x.length > 0);

          // Check if we are at the header. i.e the first line after the equals signs.
          // Just check if it starts with a "If".
          if (route[0].startsWith('If')) {
            continue;
          }

          // It should be the last item in the array.

          // If the route length is 1, then it is the unspecified On-link route.
          if (route.length === 1) {
            routes.push({
              gateway: route[0]?.trim(),
              if: undefined,
              metric: undefined,
              network: undefined,
              type: 'iv6',
            });
          } else if (route.length > 0) {
            routes.push({
              gateway: route[3]?.trim(), // It is possible for this to be undefined.
              if: parseInt(route[0].trim(), 10),
              metric: parseInt(route[1].trim(), 10),
              network: route[2].trim(),
              type: 'iv6',
            });
          }

          continue;
        }
      }

      return routes;
    } else {
      // The problem here is that I don't know how to get the route table on Linux formatted in the same way as Windows.

      return [];
    }
  }

  /**
   * Attempts to fetch the default gateway of the current machine.
   *
   * @example **TypeScript**
   * ```ts
   * import net from '@mfdlabs/net';
   *
   * net.getDefaultGateway(); // '192.168.1.1'
   * ```
   * @example **JavaScript**
   * ```js
   * const net = require('@mfdlabs/net');
   *
   * net.getDefaultGateway(); // '192.168.1.1'
   * ```
   * @notest This function is not tested as the result is way too unpredictable.
   * @returns {string} The default gateway of the current machine.
   */
  public static getDefaultGateway(): string {
    const routes = this.getRouteTable();

    return routes.filter((r) => r.type === 'iv4' && r.gateway !== 'On-link')[0]?.gateway;
  }

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}

export = NetModule;
